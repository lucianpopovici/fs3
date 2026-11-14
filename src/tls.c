/* src/tls.c — optional native TLS backend (item 7). See include/tls.h. */

#include "tls.h"
#include "conn.h"
#include "log.h"
#include "store.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifndef FS3_TLS

int tls_available(void) { return 0; }
tls_ctx_t *tls_ctx_new(const char *c, const char *k) { (void)c; (void)k; return NULL; }
void tls_ctx_free(tls_ctx_t *t) { (void)t; }
int  tls_conn_attach(struct conn *c, tls_ctx_t *t) { (void)c; (void)t; return -1; }
void tls_conn_free(struct conn *c) { (void)c; }
int  tls_handshake(struct conn *c) { (void)c; return -1; }
ssize_t tls_read(struct conn *c, void *b, size_t n) { (void)c; (void)b; (void)n; errno = EIO; return -1; }
ssize_t tls_write(struct conn *c, const void *b, size_t n) { (void)c; (void)b; (void)n; errno = EIO; return -1; }
size_t  tls_pending(const struct conn *c) { (void)c; return 0; }
ssize_t tls_send_body(struct conn *c, struct s3_reader *r, size_t m) { (void)c; (void)r; (void)m; errno = EIO; return -1; }

#else

#include <openssl/err.h>
#include <openssl/ssl.h>

struct tls_ctx { SSL_CTX *ctx; };

int tls_available(void) { return 1; }

static int alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                       const unsigned char *in, unsigned int inlen, void *arg) {
    (void)ssl; (void)arg;
    static const unsigned char h11[] = "\x08http/1.1";
    if (SSL_select_next_proto((unsigned char **)out, outlen, h11, sizeof(h11) - 1,
                              in, inlen) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;     /* only http/1.1 is spoken */
}

static void log_ssl_errors(const char *what) {
    unsigned long e;
    char buf[256];
    while ((e = ERR_get_error()) != 0) {
        ERR_error_string_n(e, buf, sizeof(buf));
        LOG_E("%s: %s", what, buf);
    }
}

tls_ctx_t *tls_ctx_new(const char *cert, const char *key) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { log_ssl_errors("SSL_CTX_new"); return NULL; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE
                             | SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION
#ifdef SSL_OP_ENABLE_KTLS
                             | SSL_OP_ENABLE_KTLS
#endif
                             );
    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE
                          | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (SSL_CTX_set_cipher_list(ctx, "ECDHE+AESGCM:ECDHE+CHACHA20") != 1
        || SSL_CTX_set1_groups_list(ctx, "X25519:P-256:P-384") != 1
        || SSL_CTX_use_certificate_chain_file(ctx, cert) != 1
        || SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(ctx) != 1) {
        log_ssl_errors("TLS context");
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_alpn_select_cb(ctx, alpn_select, NULL);
    tls_ctx_t *t = calloc(1, sizeof(*t));
    if (!t) { SSL_CTX_free(ctx); return NULL; }
    t->ctx = ctx;
    return t;
}

void tls_ctx_free(tls_ctx_t *t) {
    if (!t) return;
    SSL_CTX_free(t->ctx);     /* refcounted: live SSLs keep theirs */
    free(t);
}

int tls_conn_attach(struct conn *c, tls_ctx_t *t) {
    SSL *ssl = SSL_new(t->ctx);
    if (!ssl || SSL_set_fd(ssl, c->fd) != 1) { SSL_free(ssl); return -1; }
    SSL_set_accept_state(ssl);
    c->ssl = ssl;
    c->conn_tls = 1;
    c->tls_handshaking = 1;
    return 0;
}

void tls_conn_free(struct conn *c) {
    if (!c->ssl) return;
    /* One non-blocking close_notify attempt; never wait for the peer's. */
    if (!c->tls_handshaking) SSL_shutdown(c->ssl);
    SSL_free(c->ssl);
    c->ssl = NULL;
    free(c->tls_buf);
    c->tls_buf = NULL;
}

/* Map an SSL result: sets tls_want_write / errno; returns -1. */
static ssize_t ssl_fail(struct conn *c, int ret) {
    int err = SSL_get_error(c->ssl, ret);
    c->tls_want_write = 0;
    switch (err) {
    case SSL_ERROR_WANT_READ:  errno = EAGAIN; return -1;
    case SSL_ERROR_WANT_WRITE: c->tls_want_write = 1; errno = EAGAIN; return -1;
    case SSL_ERROR_ZERO_RETURN: return 0;
    case SSL_ERROR_SYSCALL:
        if (errno == 0) return 0;      /* unclean EOF */
        return -1;
    default:
        ERR_clear_error();
        errno = EPROTO;
        return -1;
    }
}

int tls_handshake(struct conn *c) {
    int r = SSL_accept(c->ssl);
    if (r == 1) {
        c->tls_handshaking = 0;
        c->tls_want_write = 0;
        return 1;
    }
    ssize_t f = ssl_fail(c, r);
    if (f < 0 && errno == EAGAIN) return 0;
    LOG_D("TLS handshake failed on %s", c->peer);
    return -1;
}

ssize_t tls_read(struct conn *c, void *buf, size_t n) {
    size_t got = 0;
    int r = SSL_read_ex(c->ssl, buf, n, &got);
    if (r == 1) { c->tls_want_write = 0; return (ssize_t)got; }
    return ssl_fail(c, r);
}

ssize_t tls_write(struct conn *c, const void *buf, size_t n) {
    size_t put = 0;
    int r = SSL_write_ex(c->ssl, buf, n, &put);
    if (r == 1) { c->tls_want_write = 0; return (ssize_t)put; }
    ssize_t f = ssl_fail(c, r);
    if (f == 0) { errno = EPIPE; return -1; }
    return f;
}

size_t tls_pending(const struct conn *c) {
    return c->ssl ? (size_t)SSL_pending(c->ssl) : 0;
}

#define TLS_BUF_SZ (64 * 1024)

ssize_t tls_send_body(struct conn *c, struct s3_reader *r, size_t max) {
    int fd;
    off_t off;
    uint64_t remaining;
#ifdef SSL_OP_ENABLE_KTLS
    if (!c->tls_buf_len && BIO_get_ktls_send(SSL_get_wbio(c->ssl))) {
        store_get_raw(r, &fd, &off, &remaining);
        if (!remaining) return 0;
        size_t want = remaining < max ? (size_t)remaining : max;
        ossl_ssize_t n = SSL_sendfile(c->ssl, fd, off, want, 0);
        if (n > 0) { store_get_advance(r, (uint64_t)n); return n; }
        return ssl_fail(c, (int)n);
    }
#endif
    (void)fd; (void)off; (void)remaining;
    if (c->tls_buf_pos >= c->tls_buf_len) {
        if (!c->tls_buf && !(c->tls_buf = malloc(TLS_BUF_SZ))) { errno = ENOMEM; return -1; }
        ssize_t n = store_get_read(r, c->tls_buf, TLS_BUF_SZ < max ? TLS_BUF_SZ : max);
        if (n <= 0) return n;
        c->tls_buf_len = (size_t)n;
        c->tls_buf_pos = 0;
    }
    ssize_t w = tls_write(c, c->tls_buf + c->tls_buf_pos, c->tls_buf_len - c->tls_buf_pos);
    if (w > 0) {
        c->tls_buf_pos += (size_t)w;
        if (c->tls_buf_pos >= c->tls_buf_len) c->tls_buf_pos = c->tls_buf_len = 0;
    }
    return w;
}

#endif
