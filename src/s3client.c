/* src/s3client.c — minimal outbound S3 client. See include/s3client.h. */
#include "s3client.h"
#include "sigv4.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/evp.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef FS3_TLS
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif

#define S3C_XML_CAP   (64 * 1024)     /* response bodies we parse */
#define S3C_IO_CHUNK  (64 * 1024)

struct s3c {
    s3c_endpoint_t ep;
    int            fd;
    int            reused;            /* the current connection served a request */
    unsigned       connects;
    const int     *cancel;
#ifdef FS3_TLS
    SSL_CTX       *ctx;
    SSL           *ssl;
#endif
    char           err[256];
    char           rbuf[16384];
    size_t         rlen, rpos;
};

static int64_t g_fixed_now;
void s3c_set_clock(int64_t fixed_now) { g_fixed_now = fixed_now; }

static void set_err(s3c_t *c, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(c->err, sizeof(c->err), fmt, ap);
    va_end(ap);
}
const char *s3c_err(const s3c_t *c) { return c->err; }
unsigned s3c_connects(const s3c_t *c) { return c->connects; }
void s3c_set_cancel(s3c_t *c, const int *flag) { c->cancel = flag; }
static int cancelled(s3c_t *c) {
    if (c->cancel && __atomic_load_n(c->cancel, __ATOMIC_RELAXED)) { set_err(c, "cancelled"); return 1; }
    return 0;
}

int s3c_retryable(int rc, const s3c_resp_t *r) {
    if (rc != 0) return 1;
    if (!r) return 0;
    return r->status >= 500 || r->status == 408 || r->status == 429 || r->status == 0;
}

/* ===================================================================== */
/* Endpoint parsing                                                      */
/* ===================================================================== */

int s3c_parse_endpoint(const char *url, s3c_endpoint_t *ep, char *err, size_t errcap) {
    const char *p;
    if (!strncmp(url, "https://", 8))      { ep->https = 1; p = url + 8; }
    else if (!strncmp(url, "http://", 7))  { ep->https = 0; p = url + 7; }
    else { snprintf(err, errcap, "endpoint must start with https:// or http://"); return -1; }
    size_t n = strlen(p);
    if (n && p[n - 1] == '/') n--;                     /* one trailing slash is fine */
    if (n == 0 || n >= 264) { snprintf(err, errcap, "bad endpoint host"); return -1; }
    char hp[264];
    memcpy(hp, p, n); hp[n] = 0;
    if (strpbrk(hp, "/?#@ \t\r\n\\")) {
        snprintf(err, errcap, "endpoint must be scheme://host[:port] (no path, query or user info)");
        return -1;
    }
    char *port = NULL;
    if (hp[0] == '[') {                                /* [IPv6]:port */
        char *rb = strchr(hp, ']');
        if (!rb) { snprintf(err, errcap, "bad IPv6 literal"); return -1; }
        *rb = 0;
        if (rb[1] == ':') port = rb + 2;
        else if (rb[1]) { snprintf(err, errcap, "bad endpoint"); return -1; }
        if (strlen(hp + 1) >= sizeof(ep->host)) { snprintf(err, errcap, "host too long"); return -1; }
        memcpy(ep->host, hp + 1, strlen(hp + 1) + 1);
    } else {
        char *colon = strchr(hp, ':');
        if (colon) { *colon = 0; port = colon + 1; }
        if (strlen(hp) >= sizeof(ep->host)) { snprintf(err, errcap, "host too long"); return -1; }
        memcpy(ep->host, hp, strlen(hp) + 1);
        for (char *q = ep->host; *q; q++) {
            if (!(isalnum((unsigned char)*q) || *q == '.' || *q == '-')) {
                snprintf(err, errcap, "bad host name"); return -1;
            }
            *q = (char)tolower((unsigned char)*q);
        }
    }
    if (!ep->host[0]) { snprintf(err, errcap, "empty host"); return -1; }
    ep->port = 0;
    if (port) {
        char *end;
        long v = strtol(port, &end, 10);
        if (!*port || *end || v < 1 || v > 65535) { snprintf(err, errcap, "bad port"); return -1; }
        ep->port = (int)v;
    }
    return 0;
}

static int ep_port(const s3c_endpoint_t *ep) { return ep->port ? ep->port : (ep->https ? 443 : 80); }
static int host_is_ip(const char *h) __attribute__((unused));
static int host_is_ip(const char *h) {
    unsigned char b[16];
    return inet_pton(AF_INET, h, b) == 1 || inet_pton(AF_INET6, h, b) == 1;
}

/* ===================================================================== */
/* Connection                                                            */
/* ===================================================================== */

s3c_t *s3c_new(const s3c_endpoint_t *ep) {
    s3c_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->ep = *ep;
    if (c->ep.timeout_s <= 0) c->ep.timeout_s = 30;
    c->fd = -1;
    return c;
}

static void conn_close(s3c_t *c) {
#ifdef FS3_TLS
    if (c->ssl) { SSL_free(c->ssl); c->ssl = NULL; }
#endif
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    c->rlen = c->rpos = 0;
    c->reused = 0;
}

void s3c_free(s3c_t *c) {
    if (!c) return;
    conn_close(c);
#ifdef FS3_TLS
    if (c->ctx) SSL_CTX_free(c->ctx);
#endif
    OPENSSL_cleanse(c->ep.secret_key, sizeof(c->ep.secret_key));
    free(c);
}

#ifdef FS3_TLS
static int tls_setup_ctx(s3c_t *c) {
    if (c->ctx) return 0;
    c->ctx = SSL_CTX_new(TLS_client_method());
    if (!c->ctx) { set_err(c, "TLS context: out of memory"); return -1; }
    SSL_CTX_set_min_proto_version(c->ctx, TLS1_2_VERSION);
    if (c->ep.verify_tls) {
        SSL_CTX_set_verify(c->ctx, SSL_VERIFY_PEER, NULL);
        int loaded = 0;
        if (c->ep.ca_file[0]) {
            if (SSL_CTX_load_verify_locations(c->ctx, c->ep.ca_file, NULL) != 1) {
                set_err(c, "cannot load CA file %s", c->ep.ca_file);
                return -1;
            }
            loaded = 1;
        } else {
            SSL_CTX_set_default_verify_paths(c->ctx);
            /* A statically linked OpenSSL looks in the build host's
             * OPENSSLDIR; also try the usual bundle locations (DSM ships
             * /etc/ssl/certs/ca-certificates.crt). */
            static const char *bundles[] = {
                "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                "/etc/ssl/cert.pem", NULL };
            for (int i = 0; bundles[i]; i++)
                if (access(bundles[i], R_OK) == 0
                    && SSL_CTX_load_verify_locations(c->ctx, bundles[i], NULL) == 1) {
                    loaded = 1;
                    break;
                }
        }
        (void)loaded;
    }
    return 0;
}
#endif

static int conn_open(s3c_t *c) {
    if (c->fd >= 0) return 0;
    c->rlen = c->rpos = 0;
    c->reused = 0;
#ifndef FS3_TLS
    if (c->ep.https) { set_err(c, "this fs3 build has no TLS support (needs an FS3_TLS build)"); return -1; }
#endif
    char port[8];
    snprintf(port, sizeof(port), "%d", ep_port(&c->ep));
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM,
                              .ai_flags = AI_NUMERICSERV };
    struct addrinfo *res = NULL;
    int gr = getaddrinfo(c->ep.host, port, &hints, &res);
    if (gr != 0) { set_err(c, "resolve %s: %s", c->ep.host, gai_strerror(gr)); return -1; }
    int fd = -1, last_errno = 0;
    for (struct addrinfo *ai = res; ai && fd < 0; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK, ai->ai_protocol);
        if (fd < 0) { last_errno = errno; continue; }
        int r = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (r < 0 && errno == EINPROGRESS) {
            struct pollfd pfd = { fd, POLLOUT, 0 };
            r = poll(&pfd, 1, c->ep.timeout_s * 1000);
            if (r == 1) {
                int soerr = 0; socklen_t sl = sizeof(soerr);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
                if (soerr) { errno = soerr; r = -1; } else r = 0;
            } else { errno = r == 0 ? ETIMEDOUT : errno; r = -1; }
        }
        if (r < 0) { last_errno = errno; close(fd); fd = -1; }
    }
    freeaddrinfo(res);
    if (fd < 0) { set_err(c, "connect %s:%s: %s", c->ep.host, port, strerror(last_errno)); return -1; }

    /* Blocking from here on, with timeouts. */
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    struct timeval tv = { c->ep.timeout_s, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    c->fd = fd;
    c->connects++;

#ifdef FS3_TLS
    if (c->ep.https) {
        if (tls_setup_ctx(c) < 0) { conn_close(c); return -1; }
        c->ssl = SSL_new(c->ctx);
        if (!c->ssl) { set_err(c, "TLS: out of memory"); conn_close(c); return -1; }
        SSL_set_fd(c->ssl, fd);
        int ip = host_is_ip(c->ep.host);
        if (!ip) SSL_set_tlsext_host_name(c->ssl, c->ep.host);
        if (c->ep.verify_tls) {
            X509_VERIFY_PARAM *vp = SSL_get0_param(c->ssl);
            if (ip) X509_VERIFY_PARAM_set1_ip_asc(vp, c->ep.host);
            else    SSL_set1_host(c->ssl, c->ep.host);
        }
        if (SSL_connect(c->ssl) != 1) {
            long vr = SSL_get_verify_result(c->ssl);
            unsigned long e = ERR_get_error();
            if (vr != X509_V_OK)
                set_err(c, "TLS handshake with %s: certificate: %s", c->ep.host,
                        X509_verify_cert_error_string(vr));
            else
                set_err(c, "TLS handshake with %s failed: %s", c->ep.host,
                        e ? ERR_reason_error_string(e) : "connection closed");
            ERR_clear_error();
            conn_close(c);
            return -1;
        }
    }
#endif
    return 0;
}

static ssize_t io_write(s3c_t *c, const void *buf, size_t n) {
#ifdef FS3_TLS
    if (c->ssl) {
        int w = SSL_write(c->ssl, buf, (int)(n > INT32_MAX ? INT32_MAX : n));
        return w > 0 ? w : -1;
    }
#endif
    ssize_t w;
    do { w = send(c->fd, buf, n, MSG_NOSIGNAL); } while (w < 0 && errno == EINTR);
    return w;
}

static ssize_t io_read(s3c_t *c, void *buf, size_t n) {
#ifdef FS3_TLS
    if (c->ssl) {
        int r = SSL_read(c->ssl, buf, (int)(n > INT32_MAX ? INT32_MAX : n));
        if (r > 0) return r;
        int e = SSL_get_error(c->ssl, r);
        return e == SSL_ERROR_ZERO_RETURN ? 0 : -1;
    }
#endif
    ssize_t r;
    do { r = recv(c->fd, buf, n, 0); } while (r < 0 && errno == EINTR);
    return r;
}

static int write_all(s3c_t *c, const void *buf, size_t n) {
    const char *p = buf;
    while (n) {
        ssize_t w = io_write(c, p, n);
        if (w <= 0) { set_err(c, "send: %s", w < 0 ? strerror(errno) : "closed"); return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}

/* Buffered reads. */
static int fill(s3c_t *c) {
    if (c->rpos < c->rlen) return 1;
    ssize_t r = io_read(c, c->rbuf, sizeof(c->rbuf));
    if (r <= 0) return (int)r;            /* 0 = EOF, -1 = error/timeout */
    c->rpos = 0; c->rlen = (size_t)r;
    return 1;
}

static int read_line(s3c_t *c, char *out, size_t cap) {
    size_t o = 0;
    for (;;) {
        int f = fill(c);
        if (f <= 0) return f == 0 && o == 0 ? 0 : -1;
        char ch = c->rbuf[c->rpos++];
        if (ch == '\n') { if (o && out[o - 1] == '\r') o--; out[o] = 0; return 1; }
        if (o + 1 >= cap) return -1;      /* line too long */
        out[o++] = ch;
    }
}

/* Read exactly n body bytes into `sink` (fd, or a capped memory buffer). */
typedef struct {
    int      fd;            /* -1: memory */
    char    *mem;           /* capped at S3C_XML_CAP; extra is discarded */
    size_t   mem_len;
    uint64_t total, max;
    int      too_big;
} sink_t;

static int sink_put(s3c_t *c, sink_t *s, const char *p, size_t n) {
    if (cancelled(c)) return -1;
    s->total += n;
    if (s->max && s->total > s->max) { s->too_big = 1; set_err(c, "response body too large"); return -1; }
    if (s->fd >= 0) {
        while (n) {
            ssize_t w = write(s->fd, p, n);
            if (w < 0) { if (errno == EINTR) continue; set_err(c, "write: %s", strerror(errno)); return -1; }
            p += w; n -= (size_t)w;
        }
        return 0;
    }
    if (s->mem && s->mem_len < S3C_XML_CAP - 1) {
        size_t room = S3C_XML_CAP - 1 - s->mem_len, k = n < room ? n : room;
        memcpy(s->mem + s->mem_len, p, k);
        s->mem_len += k;
        s->mem[s->mem_len] = 0;
    }
    return 0;
}

static int read_n(s3c_t *c, sink_t *s, uint64_t n) {
    while (n) {
        int f = fill(c);
        if (f <= 0) { set_err(c, "short response body"); return -1; }
        size_t avail = c->rlen - c->rpos, k = avail < n ? avail : (size_t)n;
        if (sink_put(c, s, c->rbuf + c->rpos, k) < 0) return -1;
        c->rpos += k; n -= k;
    }
    return 0;
}

static int read_chunked(s3c_t *c, sink_t *s) {
    char line[128];
    for (;;) {
        if (read_line(c, line, sizeof(line)) != 1) { set_err(c, "bad chunk header"); return -1; }
        char *end;
        unsigned long long sz = strtoull(line, &end, 16);
        if (end == line) { set_err(c, "bad chunk size"); return -1; }
        if (sz == 0) {
            do { if (read_line(c, line, sizeof(line)) != 1) return -1; } while (line[0]);
            return 0;
        }
        if (read_n(c, s, sz) < 0) return -1;
        if (read_line(c, line, sizeof(line)) != 1 || line[0]) { set_err(c, "bad chunk end"); return -1; }
    }
}

/* ===================================================================== */
/* Requests                                                              */
/* ===================================================================== */

static void amz_now(char out[17]) {
    time_t t = g_fixed_now ? (time_t)g_fixed_now : time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, 17, "%Y%m%dT%H%M%SZ", &tm);
}

/* URI-encode a key for the path: everything but unreserved and '/'. */
static int uri_encode_path(const char *in, char *out, size_t cap) {
    static const char H[] = "0123456789ABCDEF";
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        int keep = isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~' || *p == '/';
        if (o + (keep ? 1 : 3) >= cap) return -1;
        if (keep) out[o++] = (char)*p;
        else { out[o++] = '%'; out[o++] = H[*p >> 4]; out[o++] = H[*p & 15]; }
    }
    out[o] = 0;
    return 0;
}

/* Query value encoding (strict: '/' too). */
static int uri_encode_q(const char *in, char *out, size_t cap) {
    static const char H[] = "0123456789ABCDEF";
    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p; p++) {
        int keep = isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~';
        if (o + (keep ? 1 : 3) >= cap) return -1;
        if (keep) out[o++] = (char)*p;
        else { out[o++] = '%'; out[o++] = H[*p >> 4]; out[o++] = H[*p & 15]; }
    }
    out[o] = 0;
    return 0;
}

typedef struct { char name[64]; char value[1024]; } hdr_t;

static int hdr_cmp(const void *a, const void *b) {
    return strcmp(((const hdr_t *)a)->name, ((const hdr_t *)b)->name);
}

static int valid_hdr(const char *name, const char *value) {
    if (!name || !*name || strlen(name) >= 64 || !value || strlen(value) >= 1024) return 0;
    for (const char *p = name; *p; p++)
        if (!(islower((unsigned char)*p) || isdigit((unsigned char)*p) || *p == '-')) return 0;
    for (const char *p = value; *p; p++)
        if ((unsigned char)*p < 0x20 && *p != '\t') return 0;   /* no CR/LF/NUL */
    return 1;
}

typedef struct {
    const char *method;
    const char *bucket, *key;      /* key may be NULL (bucket-level) */
    const char *query;             /* already encoded, canonical order; NULL = none */
    const s3c_hdr_t *extra; size_t n_extra;
    const char *content_type;
    /* body: from fd range, or memory */
    int fd; off_t off; uint64_t len;
    const char *mem; size_t mem_len;
    /* response */
    int out_fd; uint64_t max_bytes; int head;
} req_t;

static void parse_xml_tag(const char *xml, const char *tag, char *out, size_t cap) {
    char open[64], close[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    const char *a = xml ? strstr(xml, open) : NULL;
    if (!a) return;
    a += strlen(open);
    const char *b = strstr(a, close);
    if (!b) return;
    size_t n = (size_t)(b - a);
    if (n >= cap) n = cap - 1;
    memcpy(out, a, n);
    out[n] = 0;
}

static void strip_etag(const char *in, char *out, size_t cap) {
    while (*in == ' ') in++;
    if (!strncmp(in, "&quot;", 6)) in += 6;
    if (*in == '"') in++;
    size_t n = strlen(in);
    while (n && (in[n - 1] == '"' || in[n - 1] == ' ' || in[n - 1] == '\r')) n--;
    if (n >= 6 && !strncmp(in + n - 6, "&quot;", 6)) n -= 6;
    if (n >= cap) n = cap - 1;
    memcpy(out, in, n);
    out[n] = 0;
}

static int payload_sha256(s3c_t *c, const req_t *r, char out[65]) {
    if (r->mem || r->fd < 0) { sigv4_sha256_hex(r->mem ? r->mem : "", r->mem_len, out); return 0; }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    char *buf = malloc(S3C_IO_CHUNK);
    uint64_t done = 0;
    int rc = buf ? 0 : -1;
    while (rc == 0 && done < r->len) {
        size_t want = r->len - done < S3C_IO_CHUNK ? (size_t)(r->len - done) : S3C_IO_CHUNK;
        ssize_t n = pread(r->fd, buf, want, r->off + (off_t)done);
        if (n <= 0) { set_err(c, "read source: %s", n < 0 ? strerror(errno) : "short file"); rc = -1; break; }
        EVP_DigestUpdate(ctx, buf, (size_t)n);
        done += (uint64_t)n;
    }
    unsigned char h[32]; unsigned int hl = 32;
    EVP_DigestFinal_ex(ctx, h, &hl);
    EVP_MD_CTX_free(ctx);
    free(buf);
    static const char HX[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) { out[2 * i] = HX[h[i] >> 4]; out[2 * i + 1] = HX[h[i] & 15]; }
    out[64] = 0;
    return rc;
}

static int send_body(s3c_t *c, const req_t *r) {
    if (r->mem) return r->mem_len ? write_all(c, r->mem, r->mem_len) : 0;
    if (r->fd < 0 || r->len == 0) return 0;
    char *buf = malloc(S3C_IO_CHUNK);
    if (!buf) { set_err(c, "out of memory"); return -1; }
    uint64_t done = 0;
    int rc = 0;
    while (done < r->len) {
        if (cancelled(c)) { rc = -1; break; }
        size_t want = r->len - done < S3C_IO_CHUNK ? (size_t)(r->len - done) : S3C_IO_CHUNK;
        ssize_t n = pread(r->fd, buf, want, r->off + (off_t)done);
        if (n <= 0) { set_err(c, "read source: %s", n < 0 ? strerror(errno) : "short file"); rc = -1; break; }
        if (write_all(c, buf, (size_t)n) < 0) { rc = -1; break; }
        done += (uint64_t)n;
    }
    free(buf);
    return rc;
}

/* One attempt. *stale is set when a reused keep-alive connection failed
 * before any response byte arrived (safe to retry on a new one). */
static int do_request_once(s3c_t *c, const req_t *r, s3c_resp_t *resp, int *stale) {
    *stale = 0;
    memset(resp, 0, sizeof(*resp));
    if (conn_open(c) < 0) return -1;
    int was_reused = c->reused;

    /* Host and path. */
    char host[300], path[3200], ekey[3000] = "";
    int port = ep_port(&c->ep), defport = c->ep.https ? 443 : 80;
    int v6 = strchr(c->ep.host, ':') != NULL;
    const char *bucket = r->bucket ? r->bucket : "";
    if (r->key && uri_encode_path(r->key, ekey, sizeof(ekey)) < 0) { set_err(c, "key too long"); return -1; }
    if (c->ep.virtual_host && *bucket) {
        snprintf(host, sizeof(host), "%s.%s", bucket, c->ep.host);
        snprintf(path, sizeof(path), "/%s", ekey);
    } else {
        snprintf(host, sizeof(host), v6 ? "[%s]" : "%s", c->ep.host);
        if (*bucket) snprintf(path, sizeof(path), "/%s%s%s", bucket, r->key ? "/" : "", ekey);
        else snprintf(path, sizeof(path), "/");
    }
    if (port != defport) {
        size_t hn = strlen(host);
        snprintf(host + hn, sizeof(host) - hn, ":%d", port);
    }

    /* Headers to sign (all we send). */
    hdr_t *h = calloc(16 + r->n_extra, sizeof(hdr_t));
    if (!h) { set_err(c, "out of memory"); return -1; }
    size_t nh = 0;
    char amz[17], phash[65];
    amz_now(amz);
    uint64_t blen = r->mem ? r->mem_len : (r->fd >= 0 ? r->len : 0);
    int has_body = !strcmp(r->method, "PUT") || !strcmp(r->method, "POST");
    if (c->ep.https || !has_body) {
        snprintf(phash, sizeof(phash), "%s", has_body ? "UNSIGNED-PAYLOAD"
                 : "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    } else if (payload_sha256(c, r, phash) < 0) { free(h); return -1; }
#define ADDH(N, ...) do { snprintf(h[nh].name, sizeof(h[nh].name), "%s", N); \
                          snprintf(h[nh].value, sizeof(h[nh].value), __VA_ARGS__); nh++; } while (0)
    ADDH("host", "%s", host);
    ADDH("x-amz-date", "%s", amz);
    ADDH("x-amz-content-sha256", "%s", phash);
    if (has_body) {
        ADDH("content-length", "%llu", (unsigned long long)blen);
        if (r->content_type) ADDH("content-type", "%s", r->content_type);
    }
    for (size_t i = 0; i < r->n_extra; i++) {
        if (!valid_hdr(r->extra[i].name, r->extra[i].value)) {
            set_err(c, "invalid header %s", r->extra[i].name ? r->extra[i].name : "?");
            free(h);
            return -1;
        }
        ADDH(r->extra[i].name, "%s", r->extra[i].value);
    }
#undef ADDH
    qsort(h, nh, sizeof(hdr_t), hdr_cmp);
    sigv4_hdr_t *sh = calloc(nh, sizeof(*sh));
    if (!sh) { free(h); set_err(c, "out of memory"); return -1; }
    for (size_t i = 0; i < nh; i++) {
        sh[i].k = (s3_str_t){ h[i].name, strlen(h[i].name) };
        sh[i].v = (s3_str_t){ h[i].value, strlen(h[i].value) };
    }
    sigv4_sign_req_t sr = { r->method, path, r->query, sh, nh, phash };
    char auth[1024];
    int srv = sigv4_sign(&sr, c->ep.access_key, c->ep.secret_key, c->ep.region, amz, auth, sizeof(auth));
    free(sh);
    if (srv < 0) { free(h); set_err(c, "signing failed"); return -1; }

    /* Request head. */
    size_t cap = 8192 + nh * 1100;
    char *head = malloc(cap);
    if (!head) { free(h); set_err(c, "out of memory"); return -1; }
    size_t o = (size_t)snprintf(head, cap, "%s %s%s%s HTTP/1.1\r\n", r->method, path,
                                r->query && *r->query ? "?" : "", r->query ? r->query : "");
    for (size_t i = 0; i < nh && o < cap; i++)
        o += (size_t)snprintf(head + o, cap - o, "%s: %s\r\n", h[i].name, h[i].value);
    if (o < cap) o += (size_t)snprintf(head + o, cap - o, "authorization: %s\r\nuser-agent: fs3-replication\r\n\r\n", auth);
    free(h);
    if (o >= cap) { free(head); set_err(c, "request head too large"); return -1; }
    int wrc = write_all(c, head, o);
    free(head);
    int send_failed = 0;
    if (wrc < 0 || send_body(c, r) < 0) {
        /* The server may have answered early (403, 413) and closed: try to
         * read that answer before giving up. */
        if (was_reused || cancelled(c)) {
            if (was_reused) *stale = 1;
            conn_close(c);
            return -1;
        }
        send_failed = 1;
    }

    /* Response head. */
    char line[8192];
    int lr = read_line(c, line, sizeof(line));
    if (lr != 1) {
        if (send_failed) { conn_close(c); return -1; }   /* keep the send error */
        if (was_reused && lr == 0) *stale = 1;
        set_err(c, lr == 0 ? "connection closed before response" : "read: %s", strerror(errno));
        conn_close(c);
        return -1;
    }
    if (strncmp(line, "HTTP/1.", 7) || strlen(line) < 12) {
        set_err(c, "malformed status line"); conn_close(c); return -1;
    }
    resp->status = atoi(line + 9);
    uint64_t clen = 0; int have_clen = 0, chunked = 0, close_after = 0;
    for (;;) {
        if (read_line(c, line, sizeof(line)) != 1) { set_err(c, "truncated headers"); conn_close(c); return -1; }
        if (!line[0]) break;
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = 0;
        char *v = colon + 1;
        while (*v == ' ' || *v == '\t') v++;
        for (char *q = line; *q; q++) *q = (char)tolower((unsigned char)*q);
        if (!strcmp(line, "content-length")) { clen = strtoull(v, NULL, 10); have_clen = 1; }
        else if (!strcmp(line, "transfer-encoding") && strstr(v, "chunked")) chunked = 1;
        else if (!strcmp(line, "connection") && (!strncasecmp(v, "close", 5))) close_after = 1;
        else if (!strcmp(line, "etag")) strip_etag(v, resp->etag, sizeof(resp->etag));
        else if (!strcmp(line, "x-amz-meta-fs3-source-etag"))
            snprintf(resp->src_etag, sizeof(resp->src_etag), "%s", v);
        else if (!strcmp(line, "x-amz-version-id"))
            snprintf(resp->version_id, sizeof(resp->version_id), "%s", v);
    }
    resp->content_length = clen;

    /* Body. */
    char *xml = NULL;
    sink_t s = { -1, NULL, 0, 0, 0, 0 };
    int ok_get = r->out_fd >= 0 && resp->status >= 200 && resp->status < 300;
    if (ok_get) { s.fd = r->out_fd; s.max = r->max_bytes; }
    else { xml = calloc(1, S3C_XML_CAP); s.mem = xml; }
    int body_rc = 0;
    int no_body = r->head || resp->status == 204 || resp->status == 304
                  || (resp->status >= 100 && resp->status < 200);
    if (!no_body) {
        if (chunked) body_rc = read_chunked(c, &s);
        else if (have_clen) body_rc = read_n(c, &s, clen);
        else {                                  /* read to EOF */
            close_after = 1;
            for (;;) {
                int f = fill(c);
                if (f < 0) { body_rc = -1; break; }
                if (f == 0) break;
                if (sink_put(c, &s, c->rbuf + c->rpos, c->rlen - c->rpos) < 0) { body_rc = -1; break; }
                c->rpos = c->rlen;
            }
        }
    }
    if (xml) {
        parse_xml_tag(xml, "Code", resp->code, sizeof(resp->code));
        parse_xml_tag(xml, "UploadId", resp->upload_id, sizeof(resp->upload_id));
        if (!resp->etag[0]) {
            char et[96] = "";
            parse_xml_tag(xml, "ETag", et, sizeof(et));
            if (et[0]) strip_etag(et, resp->etag, sizeof(resp->etag));
        }
        /* CompleteMultipartUpload can fail with 200 and an <Error> body. */
        if (resp->status == 200 && strstr(xml, "<Error>")) resp->status = 500;
        free(xml);
    }
    if (body_rc < 0) { conn_close(c); return -1; }
    if (close_after || send_failed) conn_close(c);
    else c->reused = 1;
    return 0;
}

static int do_request(s3c_t *c, const req_t *r, s3c_resp_t *resp) {
    int stale = 0;
    int rc = do_request_once(c, r, resp, &stale);
    if (rc < 0 && stale) {
        /* The server closed an idle keep-alive connection: one retry on a
         * fresh one. Bodies come from a file or memory, so they can be
         * re-sent. A GET into out_fd hasn't written anything yet. */
        rc = do_request_once(c, r, resp, &stale);
    }
    return rc;
}

static req_t req_init(const char *method, const char *bucket, const char *key) {
    req_t r;
    memset(&r, 0, sizeof(r));
    r.method = method; r.bucket = bucket; r.key = key;
    r.fd = -1; r.out_fd = -1;
    return r;
}

/* ===================================================================== */
/* Operations                                                            */
/* ===================================================================== */

int s3c_put_object(s3c_t *c, const char *bucket, const char *key, int fd, off_t off,
                   uint64_t len, const s3c_put_opts_t *o, s3c_resp_t *resp) {
    req_t r = req_init("PUT", bucket, key);
    r.fd = fd; r.off = off; r.len = len;
    r.content_type = o && o->content_type ? o->content_type : "application/octet-stream";
    if (o) { r.extra = o->headers; r.n_extra = o->n_headers; }
    return do_request(c, &r, resp);
}

int s3c_head_object(s3c_t *c, const char *bucket, const char *key, s3c_resp_t *resp) {
    req_t r = req_init("HEAD", bucket, key);
    r.head = 1;
    return do_request(c, &r, resp);
}

int s3c_get_object(s3c_t *c, const char *bucket, const char *key, int out_fd,
                   uint64_t max_bytes, s3c_resp_t *resp) {
    req_t r = req_init("GET", bucket, key);
    r.out_fd = out_fd; r.max_bytes = max_bytes;
    return do_request(c, &r, resp);
}

int s3c_delete_object(s3c_t *c, const char *bucket, const char *key, s3c_resp_t *resp) {
    req_t r = req_init("DELETE", bucket, key);
    return do_request(c, &r, resp);
}

int s3c_mpu_create(s3c_t *c, const char *bucket, const char *key, const s3c_put_opts_t *o,
                   s3c_resp_t *resp) {
    req_t r = req_init("POST", bucket, key);
    r.query = "uploads=";
    r.mem = ""; r.mem_len = 0;
    r.content_type = o && o->content_type ? o->content_type : "application/octet-stream";
    if (o) { r.extra = o->headers; r.n_extra = o->n_headers; }
    int rc = do_request(c, &r, resp);
    if (rc == 0 && resp->status == 200 && !resp->upload_id[0]) {
        set_err(c, "CreateMultipartUpload: no UploadId in response");
        resp->status = 502;
    }
    return rc;
}

int s3c_mpu_upload_part(s3c_t *c, const char *bucket, const char *key, const char *upload_id,
                        int part_no, int fd, off_t off, uint64_t len, s3c_resp_t *resp) {
    char q[600], eid[512];
    if (uri_encode_q(upload_id, eid, sizeof(eid)) < 0) { set_err(c, "upload id too long"); return -1; }
    snprintf(q, sizeof(q), "partNumber=%d&uploadId=%s", part_no, eid);
    req_t r = req_init("PUT", bucket, key);
    r.query = q;
    r.fd = fd; r.off = off; r.len = len;
    return do_request(c, &r, resp);
}

int s3c_mpu_complete(s3c_t *c, const char *bucket, const char *key, const char *upload_id,
                     char (*etags)[80], int n_parts, s3c_resp_t *resp) {
    char q[600], eid[512];
    if (uri_encode_q(upload_id, eid, sizeof(eid)) < 0) { set_err(c, "upload id too long"); return -1; }
    snprintf(q, sizeof(q), "uploadId=%s", eid);
    size_t cap = 128 + (size_t)n_parts * 160;
    char *xml = malloc(cap);
    if (!xml) { set_err(c, "out of memory"); return -1; }
    size_t o = (size_t)snprintf(xml, cap, "<CompleteMultipartUpload>");
    for (int i = 0; i < n_parts && o < cap; i++)
        o += (size_t)snprintf(xml + o, cap - o,
                              "<Part><PartNumber>%d</PartNumber><ETag>\"%s\"</ETag></Part>",
                              i + 1, etags[i]);
    if (o < cap) o += (size_t)snprintf(xml + o, cap - o, "</CompleteMultipartUpload>");
    if (o >= cap) { free(xml); set_err(c, "too many parts"); return -1; }
    req_t r = req_init("POST", bucket, key);
    r.query = q;
    r.mem = xml; r.mem_len = o;
    r.content_type = "application/xml";
    int rc = do_request(c, &r, resp);
    free(xml);
    return rc;
}

int s3c_mpu_abort(s3c_t *c, const char *bucket, const char *key, const char *upload_id,
                  s3c_resp_t *resp) {
    char q[600], eid[512];
    if (uri_encode_q(upload_id, eid, sizeof(eid)) < 0) { set_err(c, "upload id too long"); return -1; }
    snprintf(q, sizeof(q), "uploadId=%s", eid);
    req_t r = req_init("DELETE", bucket, key);
    r.query = q;
    return do_request(c, &r, resp);
}
