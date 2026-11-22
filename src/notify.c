/* src/notify.c — bucket event notifications (webhooks). See include/notify.h. */
#include "notify.h"

#include "audit.h"
#include "checksum.h"
#include "json.h"
#include "log.h"
#include "s3client.h"
#include "store.h"
#include "tls.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define NT_HDR          8           /* u32 body length, u32 CRC32C */
#define NT_FIXED        16          /* u64 seq, u64 mtime */
#define NT_BODY_MAX     8192
#define NT_BATCH_BYTES  (256u << 10)
#define NT_COMPACT      (1u << 20)
#define NT_BACKOFF_MAX  600

/* ===================================================================== */
/* Rules                                                                 */
/* ===================================================================== */

static const struct { const char *name; unsigned bits; } EVNAMES[] = {
    { "s3:ObjectCreated:*", NOTIFY_EV_CREATED_PUT | NOTIFY_EV_CREATED_COPY | NOTIFY_EV_CREATED_MPU },
    { "s3:ObjectCreated:Put", NOTIFY_EV_CREATED_PUT },
    { "s3:ObjectCreated:Copy", NOTIFY_EV_CREATED_COPY },
    { "s3:ObjectCreated:CompleteMultipartUpload", NOTIFY_EV_CREATED_MPU },
    { "s3:ObjectRemoved:*", NOTIFY_EV_REMOVED_DELETE | NOTIFY_EV_REMOVED_MARKER },
    { "s3:ObjectRemoved:Delete", NOTIFY_EV_REMOVED_DELETE },
    { "s3:ObjectRemoved:DeleteMarkerCreated", NOTIFY_EV_REMOVED_MARKER },
    { "s3:LifecycleExpiration:*", NOTIFY_EV_LIFECYCLE_DELETE | NOTIFY_EV_LIFECYCLE_MARKER },
    { "s3:LifecycleExpiration:Delete", NOTIFY_EV_LIFECYCLE_DELETE },
    { "s3:LifecycleExpiration:DeleteMarkerCreated", NOTIFY_EV_LIFECYCLE_MARKER },
};

static int host_is_private(const char *h) {
    if (!strcmp(h, "localhost")) return 1;
    unsigned char a[16];
    if (inet_pton(AF_INET, h, a) == 1)
        return a[0] == 127 || a[0] == 10 || (a[0] == 172 && (a[1] & 0xf0) == 16)
            || (a[0] == 192 && a[1] == 168) || (a[0] == 169 && a[1] == 254)
            || (a[0] == 100 && (a[1] & 0xc0) == 64);
    if (inet_pton(AF_INET6, h, a) == 1) {
        static const unsigned char lo[16] = { [15] = 1 };
        return !memcmp(a, lo, 16) || (a[0] & 0xfe) == 0xfc || (a[0] == 0xfe && (a[1] & 0xc0) == 0x80);
    }
    return 0;
}

int notify_split_url(const char *url, char *base, size_t bcap, char *target, size_t tcap) {
    const char *p = !strncmp(url, "https://", 8) ? url + 8 : !strncmp(url, "http://", 7) ? url + 7 : NULL;
    if (!p) return -1;
    const char *slash = strchr(p, '/');
    size_t bl = slash ? (size_t)(slash - url) : strlen(url);
    if (bl >= bcap) return -1;
    memcpy(base, url, bl);
    base[bl] = 0;
    const char *t = slash ? slash : "/";
    if (strlen(t) >= tcap) return -1;
    for (const char *q = t; *q; q++)
        if ((unsigned char)*q <= 0x20 || (unsigned char)*q >= 0x7f || *q == '#') return -1;
    snprintf(target, tcap, "%s", t);
    return 0;
}

static int jstr(const json_t *o, const char *k, char *out, size_t cap, int req) {
    const json_t *v = json_get(o, k);
    if (!v || v->type == JSON_NULL) { if (req) return -1; out[0] = 0; return 0; }
    if (v->type != JSON_STR || v->str_n >= cap || memchr(v->str, 0, v->str_n)) return -1;
    memcpy(out, v->str, v->str_n);
    out[v->str_n] = 0;
    return 0;
}

static int jbool(const json_t *o, const char *k, int dflt, int *out) {
    const json_t *v = json_get(o, k);
    if (!v || v->type == JSON_NULL) { *out = dflt; return 0; }
    if (v->type != JSON_BOOL) return -1;
    *out = v->b;
    return 0;
}

int notify_rule_parse(const char *json, size_t n, const notify_rule_t *old, int tls,
                      notify_rule_t *r, char *err, size_t errcap) {
    memset(r, 0, sizeof(*r));
    json_t *j = json_parse(json, n, 4, 64);
    if (!j || j->type != JSON_OBJ) { json_free(j); snprintf(err, errcap, "body must be a JSON object"); return -1; }
    int bad = 0;
    char what[48] = "";
#define FAIL(k) do { if (!bad) { bad = 1; snprintf(what, sizeof(what), "%s", k); } } while (0)
    if (jstr(j, "endpoint", r->url, sizeof(r->url), 1) < 0) FAIL("endpoint");
    if (jstr(j, "prefix", r->prefix, sizeof(r->prefix), 0) < 0) FAIL("prefix");
    if (jstr(j, "suffix", r->suffix, sizeof(r->suffix), 0) < 0) FAIL("suffix");
    if (jstr(j, "secret", r->secret, sizeof(r->secret), 0) < 0) FAIL("secret");
    if (jbool(j, "verify_tls", 1, &r->verify_tls) < 0) FAIL("verify_tls");
    if (jbool(j, "allow_plain_http", 0, &r->allow_plain_http) < 0) FAIL("allow_plain_http");
    r->max_age_hours = 24;
    const json_t *ma = json_get(j, "max_age_hours");
    if (ma && ma->type != JSON_NULL) {
        if (ma->type != JSON_NUM) FAIL("max_age_hours");
        else {
            char tmp[32]; size_t l = ma->str_n < 31 ? ma->str_n : 31;
            memcpy(tmp, ma->str, l); tmp[l] = 0;
            char *end; long v = strtol(tmp, &end, 10);
            if (*end || v < 1 || v > 24 * 30) FAIL("max_age_hours");
            else r->max_age_hours = (int)v;
        }
    }
    const json_t *ev = json_get(j, "events");
    if (ev && ev->type != JSON_NULL) {
        if (ev->type != JSON_ARR || !ev->child) FAIL("events");
        for (const json_t *e = ev->child; !bad && e; e = e->next) {
            unsigned bits = 0;
            if (e->type == JSON_STR)
                for (size_t i = 0; i < sizeof(EVNAMES) / sizeof(*EVNAMES); i++)
                    if (strlen(EVNAMES[i].name) == e->str_n && !memcmp(EVNAMES[i].name, e->str, e->str_n))
                        bits = EVNAMES[i].bits;
            if (!bits) FAIL("events");
            r->events |= bits;
        }
    } else {
        r->events = EVNAMES[0].bits | EVNAMES[4].bits;
    }
    for (const json_t *c = j->child; !bad && c; c = c->next) {
        static const char *known[] = { "endpoint", "events", "prefix", "suffix", "secret",
            "secret_set", "verify_tls", "allow_plain_http", "max_age_hours", NULL };
        int ok = 0;
        for (int i = 0; known[i]; i++) if (c->key && !strcmp(c->key, known[i])) ok = 1;
        if (!ok) FAIL(c->key ? c->key : "?");
    }
#undef FAIL
    json_free(j);
    if (bad) { snprintf(err, errcap, "missing or invalid field \"%s\"", what); return -1; }

    char base[300], target[1024], e2[128];
    s3c_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    if (notify_split_url(r->url, base, sizeof(base), target, sizeof(target)) < 0
        || s3c_parse_endpoint(base, &ep, e2, sizeof(e2)) < 0) {
        snprintf(err, errcap, "endpoint must be http(s)://host[:port]/path with no spaces or fragment");
        return -1;
    }
    if (ep.https && !tls) { snprintf(err, errcap, "https endpoints need a TLS build of fs3"); return -1; }
    int priv = host_is_private(ep.host);
    if (!ep.https && !(r->allow_plain_http && priv)) {
        snprintf(err, errcap, "plain http is allowed only for loopback/private-address hosts "
                              "with \"allow_plain_http\": true");
        return -1;
    }
    if (ep.https && !r->verify_tls && !priv) {
        snprintf(err, errcap, "\"verify_tls\": false is allowed only for loopback/private-address hosts");
        return -1;
    }
    if (!r->secret[0] && old && old->secret[0]) memcpy(r->secret, old->secret, sizeof(r->secret));
    for (const char *p = r->secret; *p; p++)
        if ((unsigned char)*p < 0x20 || (unsigned char)*p == 0x7f) { snprintf(err, errcap, "invalid secret"); return -1; }
    for (const char *p = r->prefix; *p; p++)
        if ((unsigned char)*p < 0x20) { snprintf(err, errcap, "invalid prefix"); return -1; }
    for (const char *p = r->suffix; *p; p++)
        if ((unsigned char)*p < 0x20) { snprintf(err, errcap, "invalid suffix"); return -1; }
    return 0;
}

static size_t rule_json(const notify_rule_t *r, int with_secret, char *out, size_t cap) {
    size_t o = (size_t)snprintf(out, cap, "{\"endpoint\":");
    json_put_str(out, cap, &o, r->url);
    o += (size_t)snprintf(out + o, cap - o, ",\"events\":[");
    int first = 1;
    for (size_t i = 0; i < sizeof(EVNAMES) / sizeof(*EVNAMES); i++) {
        /* Most specific names that are fully selected, wildcards first. */
        unsigned b = EVNAMES[i].bits;
        int wildcard = strchr(EVNAMES[i].name, '*') != NULL;
        if ((r->events & b) != b) continue;
        int covered = 0;
        if (!wildcard)
            for (size_t k = 0; k < sizeof(EVNAMES) / sizeof(*EVNAMES); k++)
                if (strchr(EVNAMES[k].name, '*') && (EVNAMES[k].bits & b) == b
                    && (r->events & EVNAMES[k].bits) == EVNAMES[k].bits) covered = 1;
        if (covered) continue;
        o += (size_t)snprintf(out + o, cap - o, "%s", first ? "" : ",");
        json_put_str(out, cap, &o, EVNAMES[i].name);
        first = 0;
    }
    o += (size_t)snprintf(out + o, cap - o, "],\"prefix\":");
    json_put_str(out, cap, &o, r->prefix);
    o += (size_t)snprintf(out + o, cap - o, ",\"suffix\":");
    json_put_str(out, cap, &o, r->suffix);
    if (with_secret) {
        o += (size_t)snprintf(out + o, cap - o, ",\"secret\":");
        json_put_str(out, cap, &o, r->secret);
    } else {
        o += (size_t)snprintf(out + o, cap - o, ",\"secret_set\":%s", r->secret[0] ? "true" : "false");
    }
    o += (size_t)snprintf(out + o, cap - o, ",\"verify_tls\":%s,\"allow_plain_http\":%s,\"max_age_hours\":%d}",
                          r->verify_tls ? "true" : "false", r->allow_plain_http ? "true" : "false",
                          r->max_age_hours);
    return o < cap ? o : cap - 1;
}

/* ===================================================================== */
/* State                                                                 */
/* ===================================================================== */

typedef struct nb {
    struct nb    *next;
    char          name[64], id[33], dir[4200];
    notify_rule_t rule;
    int           dead, busy;
    int           jfd;
    uint64_t      jsize, next_seq, cursor_seq, cursor_off;
    int           dirty, journal_broken;
    time_t        backoff_until;
    int           backoff_s;
    uint64_t      n_sent, n_dropped, n_failed_attempts;
    time_t        last_ok;
    char          last_error[200];
    time_t        last_error_t;
} nb_t;

struct notify {
    notify_cfg_t    cfg;
    char            dir[4096];
    pthread_mutex_t mu;             /* leaf */
    pthread_cond_t  work_cv, sync_cv;
    nb_t           *head, *rr;
    int             n_rules;
    int             stop;
    pthread_t       worker, syncer;
    int             worker_up, syncer_up;
    time_t          last_gc;
};

static int stopping(notify_t *n) { return __atomic_load_n(&n->stop, __ATOMIC_RELAXED); }

static uint32_t crc32c(const uint8_t *p, size_t n) {
    uint8_t d[CKSUM_MAX_DIGEST];
    size_t dl = 0;
    if (cksum_oneshot(S3_CKSUM_CRC32C, p, n, d, &dl) != 0 || dl != 4) return 0;
    return ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) | ((uint32_t)d[2] << 8) | d[3];
}
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = v << 8 | p[i]; return v; }

/* Record: [u32 len][u32 crc][u64 seq][u64 mtime][json]. Returns size, 0
 * need more, -1 bad. */
static long rec_decode(const uint8_t *b, size_t n, uint64_t *seq, uint64_t *mt,
                       const char **json, size_t *jn) {
    if (n < NT_HDR) return 0;
    uint32_t len = get32(b);
    if (len < NT_FIXED + 2 || len > NT_FIXED + NT_BODY_MAX) return -1;
    if (n < NT_HDR + len) return 0;
    if (crc32c(b + NT_HDR, len) != get32(b + 4)) return -1;
    *seq = get64(b + NT_HDR);
    *mt = get64(b + NT_HDR + 8);
    *json = (const char *)b + NT_HDR + NT_FIXED;
    *jn = len - NT_FIXED;
    return (long)(NT_HDR + len);
}

static int fsync_path(const char *p) {
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int rc = fsync(fd);
    close(fd);
    return rc;
}

static void cursor_save(const char *dir, uint64_t seq) {
    char tmp[4400], fin[4400], buf[32];
    snprintf(fin, sizeof(fin), "%s/cursor", dir);
    snprintf(tmp, sizeof(tmp), "%s/.cursor.tmp", dir);
    int n = snprintf(buf, sizeof(buf), "%llu\n", (unsigned long long)seq);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return;
    if (write(fd, buf, (size_t)n) == n && fsync(fd) == 0) {
        close(fd);
        if (rename(tmp, fin) == 0) fsync_path(dir);
        return;
    }
    close(fd);
    unlink(tmp);
}

static void rm_rf(const char *dir) {
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.' && (!e->d_name[1] || (e->d_name[1] == '.' && !e->d_name[2]))) continue;
            char p[4400];
            snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(dir);
}

static int journal_open(nb_t *b) {
    char p[4400], buf[64] = "";
    snprintf(p, sizeof(p), "%s/cursor", b->dir);
    int cf = open(p, O_RDONLY | O_CLOEXEC);
    if (cf >= 0) {
        ssize_t r = read(cf, buf, sizeof(buf) - 1);
        close(cf);
        if (r > 0) { buf[r] = 0; b->cursor_seq = strtoull(buf, NULL, 10); }
    }
    snprintf(p, sizeof(p), "%s/queue", b->dir);
    b->jfd = open(p, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (b->jfd < 0) { LOG_E("notify: open %s: %s", p, strerror(errno)); return -1; }
    struct stat st;
    fstat(b->jfd, &st);
    uint64_t size = (uint64_t)st.st_size, off = 0, last = b->cursor_seq;
    int found = 0;
    uint8_t *rb = malloc(NT_BATCH_BYTES + NT_HDR + NT_FIXED + NT_BODY_MAX);
    if (!rb) return -1;
    b->cursor_off = 0;
    while (off < size) {
        ssize_t n = pread(b->jfd, rb, NT_BATCH_BYTES + NT_HDR + NT_FIXED + NT_BODY_MAX, (off_t)off);
        if (n <= 0) break;
        size_t pos = 0;
        long k = 0;
        uint64_t seq, mt; const char *js; size_t jn;
        while ((k = rec_decode(rb + pos, (size_t)n - pos, &seq, &mt, &js, &jn)) > 0) {
            if (seq > last) last = seq;
            if (!found && seq > b->cursor_seq) { found = 1; b->cursor_off = off + pos; }
            pos += (size_t)k;
        }
        off += pos;
        if (k < 0 || pos == 0) break;
    }
    free(rb);
    if (off < size) {
        LOG_W("notify: %s: dropping %llu byte(s) of torn journal tail", p, (unsigned long long)(size - off));
        if (ftruncate(b->jfd, (off_t)off) < 0) return -1;
    }
    b->jsize = off;
    if (!found) b->cursor_off = off;
    b->next_seq = last + 1;
    return 0;
}

static nb_t *find_name(notify_t *n, const char *name, size_t len) {
    for (nb_t *b = n->head; b; b = b->next)
        if (!b->dead && strlen(b->name) == len && !memcmp(b->name, name, len)) return b;
    return NULL;
}

static void nb_free(nb_t *b) {
    if (b->jfd >= 0) close(b->jfd);
    OPENSSL_cleanse(b->rule.secret, sizeof(b->rule.secret));
    free(b);
}

static nb_t *nb_load(notify_t *n, const char *name, const char *id, const notify_rule_t *rule) {
    nb_t *b = calloc(1, sizeof(*b));
    if (!b) return NULL;
    snprintf(b->name, sizeof(b->name), "%s", name);
    snprintf(b->id, sizeof(b->id), "%s", id);
    snprintf(b->dir, sizeof(b->dir), "%s/%s", n->dir, id);
    b->rule = *rule;
    b->jfd = -1;
    if ((mkdir(b->dir, 0700) < 0 && errno != EEXIST) || journal_open(b) < 0) {
        if (b->jfd >= 0) close(b->jfd);
        free(b);
        return NULL;
    }
    return b;
}

static int load_rule(notify_t *n, const char *bucket, notify_rule_t *out) {
    char *d = NULL;
    size_t len = 0;
    s3_str_t b = { bucket, strlen(bucket) };
    if (store_bucket_sidecar_read(n->cfg.store, b, "notification.json", 16384, &d, &len) != S3_OK) return 1;
    char err[200];
    int rc = notify_rule_parse(d, len, NULL, tls_available(), out, err, sizeof(err));
    OPENSSL_cleanse(d, len);
    free(d);
    if (rc < 0) { LOG_E("notify: bucket %s: stored rule rejected: %s", bucket, err); return -1; }
    return 0;
}

/* ===================================================================== */
/* Events                                                                */
/* ===================================================================== */

static unsigned event_bit(const store_change_t *ev, const char **name) {
    if (ev->op == STORE_CHANGE_PUT) {
        if (ev->origin == STORE_ORIGIN_COPY) { *name = "ObjectCreated:Copy"; return NOTIFY_EV_CREATED_COPY; }
        if (ev->origin == STORE_ORIGIN_MPU) { *name = "ObjectCreated:CompleteMultipartUpload"; return NOTIFY_EV_CREATED_MPU; }
        *name = "ObjectCreated:Put"; return NOTIFY_EV_CREATED_PUT;
    }
    if (ev->origin == STORE_ORIGIN_LIFECYCLE) {
        if (ev->delete_marker) { *name = "LifecycleExpiration:DeleteMarkerCreated"; return NOTIFY_EV_LIFECYCLE_MARKER; }
        *name = "LifecycleExpiration:Delete"; return NOTIFY_EV_LIFECYCLE_DELETE;
    }
    if (ev->delete_marker) { *name = "ObjectRemoved:DeleteMarkerCreated"; return NOTIFY_EV_REMOVED_MARKER; }
    *name = "ObjectRemoved:Delete"; return NOTIFY_EV_REMOVED_DELETE;
}

/* S3 event keys are URL-encoded with '+' for spaces. */
static size_t key_encode(s3_str_t k, char *out, size_t cap) {
    static const char H[] = "0123456789ABCDEF";
    size_t o = 0;
    for (size_t i = 0; i < k.n && o + 4 < cap; i++) {
        unsigned char c = (unsigned char)k.p[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~' || c == '/') out[o++] = (char)c;
        else if (c == ' ') out[o++] = '+';
        else { out[o++] = '%'; out[o++] = H[c >> 4]; out[o++] = H[c & 15]; }
    }
    out[o] = 0;
    return o;
}

static size_t event_json(const char *bucket, const char *name, const store_change_t *ev,
                         uint64_t seq, char *out, size_t cap) {
    char ts[40], ek[3200], et[48] = "";
    time_t t = (time_t)(ev->mtime_ms / 1000);
    struct tm tm;
    gmtime_r(&t, &tm);
    size_t tl = strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(ts + tl, sizeof(ts) - tl, ".%03uZ", (unsigned)(ev->mtime_ms % 1000));
    key_encode(ev->key, ek, sizeof(ek));
    if (ev->etag) {
        static const char HX[] = "0123456789abcdef";
        for (int i = 0; i < 16; i++) { et[2 * i] = HX[ev->etag[i] >> 4]; et[2 * i + 1] = HX[ev->etag[i] & 15]; }
        et[32] = 0;
        if (ev->part_count) snprintf(et + 32, 16, "-%u", ev->part_count);
    }
    size_t o = (size_t)snprintf(out, cap,
        "{\"Records\":[{\"eventVersion\":\"2.1\",\"eventSource\":\"fs3:s3\",\"awsRegion\":\"us-east-1\","
        "\"eventTime\":\"%s\",\"eventName\":\"%s\",\"s3\":{\"s3SchemaVersion\":\"1.0\",\"bucket\":{\"name\":",
        ts, name);
    json_put_str(out, cap, &o, bucket);
    o += (size_t)snprintf(out + o, cap - o, "},\"object\":{\"key\":");
    json_put_str(out, cap, &o, ek);
    if (ev->op == STORE_CHANGE_PUT)
        o += (size_t)snprintf(out + o, cap - o, ",\"size\":%llu,\"eTag\":\"%s\"",
                              (unsigned long long)ev->size, et);
    if (ev->version_id[0] && strcmp(ev->version_id, "null"))
        o += (size_t)snprintf(out + o, cap - o, ",\"versionId\":\"%s\"", ev->version_id);
    o += (size_t)snprintf(out + o, cap - o, ",\"sequencer\":\"%016llX\"}}}]}", (unsigned long long)seq);
    return o < cap ? o : 0;
}

/* mu held. */
static int nb_append(notify_t *n, nb_t *b, const char *json, size_t jn, uint64_t seq, uint64_t mt) {
    if (b->jfd < 0 || jn > NT_BODY_MAX) return -1;
    uint8_t rec[NT_HDR + NT_FIXED + NT_BODY_MAX];
    put64(rec + NT_HDR, seq);
    put64(rec + NT_HDR + 8, mt);
    memcpy(rec + NT_HDR + NT_FIXED, json, jn);
    uint32_t len = (uint32_t)(NT_FIXED + jn);
    put32(rec, len);
    put32(rec + 4, crc32c(rec + NT_HDR, len));
    ssize_t w = write(b->jfd, rec, NT_HDR + len);
    if (w != (ssize_t)(NT_HDR + len)) {
        if (w > 0 && ftruncate(b->jfd, (off_t)b->jsize) < 0) { /* dropped at next open */ }
        if (!b->journal_broken) LOG_E("notify: bucket %s: journal append failed: %s", b->name,
                                      w < 0 ? strerror(errno) : "short write");
        b->journal_broken = 1;
        return -1;
    }
    b->jsize += NT_HDR + len;
    b->next_seq = seq + 1;
    b->dirty = 1;
    pthread_cond_signal(&n->sync_cv);
    pthread_cond_signal(&n->work_cv);
    return 0;
}

static void on_change(void *user, const store_change_t *ev) {
    notify_t *n = user;
    if (!__atomic_load_n(&n->n_rules, __ATOMIC_RELAXED)) return;
    const char *name;
    unsigned bit = event_bit(ev, &name);
    char id[33];
    pthread_mutex_lock(&n->mu);
    nb_t *b = find_name(n, ev->bucket.p, ev->bucket.n);
    int match = 0;
    if (b && (b->rule.events & bit)) {
        size_t pl = strlen(b->rule.prefix), sl = strlen(b->rule.suffix);
        match = ev->key.n >= pl && !memcmp(ev->key.p, b->rule.prefix, pl)
             && ev->key.n >= sl && !memcmp(ev->key.p + ev->key.n - sl, b->rule.suffix, sl);
    }
    if (match) memcpy(id, b->id, sizeof(id));
    pthread_mutex_unlock(&n->mu);
    if (!match) return;
    s3_bucket_meta_t bm;
    if (store_bucket_meta(n->cfg.store, ev->bucket, &bm) != S3_OK || strcmp(bm.id, id)) return;
    char bucket[64];
    snprintf(bucket, sizeof(bucket), S3_STR_FMT, S3_STR_ARG(ev->bucket));
    char *json = malloc(NT_BODY_MAX);
    if (!json) return;
    pthread_mutex_lock(&n->mu);
    b = find_name(n, ev->bucket.p, ev->bucket.n);
    if (b && !strcmp(b->id, id)) {
        size_t jn = event_json(bucket, name, ev, b->next_seq, json, NT_BODY_MAX);
        if (jn) nb_append(n, b, json, jn, b->next_seq, ev->mtime_ms);
    }
    pthread_mutex_unlock(&n->mu);
    free(json);
}

/* ===================================================================== */
/* Delivery                                                              */
/* ===================================================================== */

static uint64_t wall_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000);
}

static s3c_t *client_for(notify_t *n, const notify_rule_t *r, char *target, size_t tcap) {
    char base[300], e2[128];
    s3c_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    if (notify_split_url(r->url, base, sizeof(base), target, tcap) < 0
        || s3c_parse_endpoint(base, &ep, e2, sizeof(e2)) < 0)
        return NULL;
    ep.verify_tls = r->verify_tls;
    if (n->cfg.ca_file) snprintf(ep.ca_file, sizeof(ep.ca_file), "%s", n->cfg.ca_file);
    ep.timeout_s = n->cfg.timeout_s > 0 ? n->cfg.timeout_s : 10;
    s3c_t *c = s3c_new(&ep);
    if (c) s3c_set_cancel(c, &n->stop);
    return c;
}

/* 0 delivered, 1 retry, 2 permanent (drop). */
static int deliver(s3c_t *c, const char *target, const notify_rule_t *r, const char *bucket_id,
                   uint64_t seq, const char *json, size_t jn, char *err, size_t errcap) {
    s3c_hdr_t h[3];
    size_t nh = 0;
    char sig[80], dl[64], evn[96] = "";
    /* The record body is not NUL-terminated. Test events carry "Event". */
    const char *en = memmem(json, jn, "\"eventName\":\"", 13);
    if (en) en += 13;
    else if ((en = memmem(json, jn, "\"Event\":\"", 9))) en += 9;
    if (en) {
        size_t k = 0, room = (size_t)(json + jn - en);
        while (k < room && en[k] != '"' && k + 1 < sizeof(evn)) { evn[k] = en[k]; k++; }
        evn[k] = 0;
        h[nh].name = "x-fs3-event"; h[nh].value = evn; nh++;
    }
    snprintf(dl, sizeof(dl), "%s-%llu", bucket_id, (unsigned long long)seq);
    h[nh].name = "x-fs3-delivery"; h[nh].value = dl; nh++;
    if (r->secret[0]) {
        unsigned char mac[32]; unsigned int ml = 32;
        HMAC(EVP_sha256(), r->secret, (int)strlen(r->secret), (const unsigned char *)json, jn, mac, &ml);
        static const char HX[] = "0123456789abcdef";
        memcpy(sig, "sha256=", 7);
        for (int i = 0; i < 32; i++) { sig[7 + 2 * i] = HX[mac[i] >> 4]; sig[8 + 2 * i] = HX[mac[i] & 15]; }
        sig[71] = 0;
        h[nh].name = "x-fs3-signature"; h[nh].value = sig; nh++;
    }
    s3c_resp_t resp;
    int rc = s3c_post_raw(c, target, "application/json", h, nh, json, jn, &resp);
    if (rc < 0) { snprintf(err, errcap, "POST: %s", s3c_err(c)); return 1; }
    if (resp.status >= 200 && resp.status < 300) return 0;
    snprintf(err, errcap, "POST: HTTP %d", resp.status);
    if (resp.status >= 500 || resp.status == 408 || resp.status == 429 || resp.status == 401
        || resp.status == 403 || resp.status == 404 || resp.status == 405)
        return 1;
    return 2;
}

static void run_queue(notify_t *n, nb_t *b) {
    pthread_mutex_lock(&n->mu);
    uint64_t start = b->cursor_off, end = b->jsize;
    int fd = b->jfd >= 0 ? dup(b->jfd) : -1;
    notify_rule_t rule = b->rule;
    char id[33], name[64];
    memcpy(id, b->id, sizeof(id));
    memcpy(name, b->name, sizeof(name));
    pthread_mutex_unlock(&n->mu);
    if (fd < 0 || start >= end) { if (fd >= 0) close(fd); OPENSSL_cleanse(&rule, sizeof(rule)); return; }
    size_t want = end - start > NT_BATCH_BYTES ? NT_BATCH_BYTES : (size_t)(end - start);
    uint8_t *buf = malloc(want);
    ssize_t got = buf ? pread(fd, buf, want, (off_t)start) : -1;
    close(fd);
    char target[1024], err[256] = "";
    s3c_t *c = got > 0 ? client_for(n, &rule, target, sizeof(target)) : NULL;
    size_t pos = 0;
    uint64_t done_seq = 0, done_off = start, sent = 0, dropped = 0;
    int retry = 0;
    while (c && !stopping(n)) {
        uint64_t seq, mt; const char *js; size_t jn;
        long k = rec_decode(buf + pos, (size_t)got - pos, &seq, &mt, &js, &jn);
        if (k <= 0) break;
        int rc = deliver(c, target, &rule, id, seq, js, jn, err, sizeof(err));
        if (rc == 1 && wall_ms() > mt + (uint64_t)rule.max_age_hours * 3600000ULL) rc = 3;
        if (rc == 1) { retry = 1; break; }
        if (rc == 0) sent++;
        else {
            dropped++;
            LOG_W("notify: bucket %s: event %llu dropped (%s)", name, (unsigned long long)seq,
                  rc == 3 ? "older than max_age_hours" : err);
            char ev[400];
            snprintf(ev, sizeof(ev), "notification bucket %s event %llu dropped: %s", name,
                     (unsigned long long)seq, rc == 3 ? "expired after retries" : err);
            audit_event("notify", ev);
        }
        pos += (size_t)k;
        done_seq = seq;
        done_off = start + pos;
    }
    s3c_free(c);
    free(buf);
    OPENSSL_cleanse(&rule, sizeof(rule));
    pthread_mutex_lock(&n->mu);
    if (done_seq > b->cursor_seq) { b->cursor_seq = done_seq; b->cursor_off = done_off; }
    b->n_sent += sent;
    b->n_dropped += dropped;
    if (sent) b->last_ok = time(NULL);
    if (retry || !c) {
        if (!c) snprintf(err, sizeof(err), "bad endpoint");
        b->n_failed_attempts++;
        snprintf(b->last_error, sizeof(b->last_error), "%.199s", err);
        b->last_error_t = time(NULL);
        b->backoff_s = b->backoff_s ? b->backoff_s * 2 : 1;
        if (b->backoff_s > NT_BACKOFF_MAX) b->backoff_s = NT_BACKOFF_MAX;
        b->backoff_until = time(NULL) + b->backoff_s;
    } else {
        b->backoff_s = 0;
        b->backoff_until = 0;
    }
    if (b->cursor_off == b->jsize && b->jsize >= NT_COMPACT && b->jfd >= 0
        && ftruncate(b->jfd, 0) == 0) { b->jsize = 0; b->cursor_off = 0; }
    uint64_t cs = b->cursor_seq;
    char dir[4200];
    snprintf(dir, sizeof(dir), "%s", b->dir);
    pthread_mutex_unlock(&n->mu);
    if (done_seq) cursor_save(dir, cs);
}

static void *worker_main(void *arg) {
    notify_t *n = arg;
    pthread_mutex_lock(&n->mu);
    while (!stopping(n)) {
        time_t now = time(NULL);
        nb_t *pick = NULL;
        nb_t *startb = n->rr && n->rr->next ? n->rr->next : n->head;
        for (nb_t *b = startb; b && !pick; b = b->next)
            if (!b->dead && !b->busy && now >= b->backoff_until && b->cursor_off < b->jsize) pick = b;
        for (nb_t *b = n->head; b && b != startb && !pick; b = b->next)
            if (!b->dead && !b->busy && now >= b->backoff_until && b->cursor_off < b->jsize) pick = b;
        if (!pick) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
            pthread_cond_timedwait(&n->work_cv, &n->mu, &ts);
            continue;
        }
        n->rr = pick;
        pick->busy = 1;
        pthread_mutex_unlock(&n->mu);
        run_queue(n, pick);
        pthread_mutex_lock(&n->mu);
        pick->busy = 0;
        if (pick->dead) {
            for (nb_t **pp = &n->head; *pp; pp = &(*pp)->next)
                if (*pp == pick) { *pp = pick->next; break; }
            if (n->rr == pick) n->rr = NULL;
            rm_rf(pick->dir);
            nb_free(pick);
        }
    }
    pthread_mutex_unlock(&n->mu);
    return NULL;
}

static void *syncer_main(void *arg) {
    notify_t *n = arg;
    pthread_mutex_lock(&n->mu);
    while (!stopping(n)) {
        int any = 0;
        for (nb_t *b = n->head; b; b = b->next) if (b->dirty) any = 1;
        if (!any) { pthread_cond_wait(&n->sync_cv, &n->mu); continue; }
        pthread_mutex_unlock(&n->mu);
        struct timespec d = { 0, 10 * 1000000 };
        nanosleep(&d, NULL);
        pthread_mutex_lock(&n->mu);
        int fds[64], k = 0;
        for (nb_t *b = n->head; b && k < 64; b = b->next)
            if (b->dirty && b->jfd >= 0) { b->dirty = 0; fds[k++] = dup(b->jfd); }
        pthread_mutex_unlock(&n->mu);
        for (int i = 0; i < k; i++) if (fds[i] >= 0) { fdatasync(fds[i]); close(fds[i]); }
        pthread_mutex_lock(&n->mu);
    }
    pthread_mutex_unlock(&n->mu);
    return NULL;
}

/* ===================================================================== */
/* Lifecycle                                                             */
/* ===================================================================== */

notify_t *notify_create(const notify_cfg_t *cfg) {
    notify_t *n = calloc(1, sizeof(*n));
    if (!n) return NULL;
    n->cfg = *cfg;
    pthread_mutex_init(&n->mu, NULL);
    pthread_cond_init(&n->work_cv, NULL);
    pthread_cond_init(&n->sync_cv, NULL);
    snprintf(n->dir, sizeof(n->dir), "%s/notify", cfg->root);
    if (!cfg->enabled) return n;
    if (mkdir(n->dir, 0700) < 0 && errno != EEXIST) {
        LOG_E("notify: mkdir %s: %s", n->dir, strerror(errno));
        notify_destroy(n);
        return NULL;
    }
    s3_bucket_info_t *bl = NULL;
    size_t nbk = 0;
    if (store_list_buckets(cfg->store, &bl, &nbk) == S3_OK) {
        for (size_t i = 0; i < nbk; i++) {
            notify_rule_t rule;
            if (load_rule(n, bl[i].name, &rule) != 0) continue;
            s3_bucket_meta_t bm;
            s3_str_t bn = { bl[i].name, strlen(bl[i].name) };
            if (store_bucket_meta(cfg->store, bn, &bm) != S3_OK || !bm.id[0]) continue;
            nb_t *b = nb_load(n, bl[i].name, bm.id, &rule);
            OPENSSL_cleanse(&rule, sizeof(rule));
            if (!b) continue;
            b->next = n->head;
            n->head = b;
            n->n_rules++;
            LOG_I("notify: bucket %s -> %s (%llu queued)", b->name, b->rule.url,
                  (unsigned long long)(b->next_seq - 1 - b->cursor_seq));
        }
        store_buckets_free(bl, nbk);
    }
    store_add_change_hook(cfg->store, on_change, n);
    return n;
}

int notify_start(notify_t *n) {
    if (!n || !n->cfg.enabled) return 0;
    if (pthread_create(&n->syncer, NULL, syncer_main, n) != 0) return -1;
    n->syncer_up = 1;
    if (pthread_create(&n->worker, NULL, worker_main, n) != 0) return -1;
    n->worker_up = 1;
    return 0;
}

void notify_destroy(notify_t *n) {
    if (!n) return;
    store_remove_change_hook(n->cfg.store, n);
    pthread_mutex_lock(&n->mu);
    __atomic_store_n(&n->stop, 1, __ATOMIC_RELAXED);
    pthread_cond_broadcast(&n->work_cv);
    pthread_cond_broadcast(&n->sync_cv);
    pthread_mutex_unlock(&n->mu);
    if (n->worker_up) pthread_join(n->worker, NULL);
    if (n->syncer_up) pthread_join(n->syncer, NULL);
    while (n->head) {
        nb_t *b = n->head;
        n->head = b->next;
        if (b->jfd >= 0) fdatasync(b->jfd);
        nb_free(b);
    }
    pthread_mutex_destroy(&n->mu);
    pthread_cond_destroy(&n->work_cv);
    pthread_cond_destroy(&n->sync_cv);
    free(n);
}

/* mu held. */
static void nb_kill(notify_t *n, nb_t *b) {
    if (b->dead) return;
    b->dead = 1;
    __atomic_fetch_sub(&n->n_rules, 1, __ATOMIC_RELAXED);
    if (b->busy) return;
    for (nb_t **pp = &n->head; *pp; pp = &(*pp)->next)
        if (*pp == b) { *pp = b->next; break; }
    if (n->rr == b) n->rr = NULL;
    rm_rf(b->dir);
    nb_free(b);
}

void notify_tick(notify_t *n, time_t now) {
    if (!n || !n->cfg.enabled || now - n->last_gc < 10) return;
    n->last_gc = now;
    pthread_mutex_lock(&n->mu);
    for (nb_t *b = n->head, *nx; b; b = nx) {
        nx = b->next;
        if (b->dead) continue;
        s3_bucket_meta_t bm;
        s3_str_t bn = { b->name, strlen(b->name) };
        if (store_bucket_meta(n->cfg.store, bn, &bm) != S3_OK || strcmp(bm.id, b->id)) {
            LOG_I("notify: bucket %s is gone; dropping its rule and queue", b->name);
            nb_kill(n, b);
        }
    }
    pthread_mutex_unlock(&n->mu);
}

/* ===================================================================== */
/* Admin API                                                             */
/* ===================================================================== */

static char *jerr(int *status, int code, const char *msg) {
    *status = code;
    char *o = malloc(600);
    if (!o) return NULL;
    size_t k = (size_t)snprintf(o, 600, "{\"error\":");
    json_put_str(o, 600, &k, msg);
    snprintf(o + k, 600 - k, "}\n");
    return o;
}

static void audit_rule(const char *bucket, const char *what, const notify_rule_t *r) {
    char ev[1400];
    if (r) snprintf(ev, sizeof(ev), "bucket %s notification %s -> %.900s events=0x%x prefix \"%.100s\"",
                    bucket, what, r->url, r->events, r->prefix);
    else snprintf(ev, sizeof(ev), "bucket %s notification %s", bucket, what);
    LOG_I("admin: %s", ev);
    audit_event("admin-api", ev);
}

char *notify_admin(notify_t *n, const char *method, const char *bucket, const char *sub,
                   const char *body, size_t body_n, int *status) {
    if (!n || !n->cfg.enabled) return jerr(status, 501, "event notifications are disabled (--notify off)");
    s3_str_t bn = { bucket, strlen(bucket) };
    s3_bucket_meta_t bm;
    if (store_bucket_meta(n->cfg.store, bn, &bm) != S3_OK) return jerr(status, 404, "no such bucket");
    if (!bm.id[0]) return jerr(status, 409, "bucket has no id yet; set its owner first");

    if (!strcmp(sub, "status") || !strcmp(sub, "test")) {
        int test = !strcmp(sub, "test");
        if (strcmp(method, test ? "POST" : "GET")) return jerr(status, 405, test ? "use POST" : "use GET");
        pthread_mutex_lock(&n->mu);
        nb_t *b = find_name(n, bucket, strlen(bucket));
        if (!b) { pthread_mutex_unlock(&n->mu); return jerr(status, 404, "bucket has no notification rule"); }
        if (test) {
            char js[512], ts[40];
            time_t t = time(NULL);
            struct tm tm;
            gmtime_r(&t, &tm);
            strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S.000Z", &tm);
            size_t o = (size_t)snprintf(js, sizeof(js), "{\"Service\":\"fs3\",\"Event\":\"s3:TestEvent\","
                                        "\"Time\":\"%s\",\"Bucket\":", ts);
            json_put_str(js, sizeof(js), &o, bucket);
            o += (size_t)snprintf(js + o, sizeof(js) - o, "}");
            nb_append(n, b, js, o, b->next_seq, wall_ms());
            b->backoff_until = 0;
        }
        char *out = malloc(2048);
        if (out) {
            uint64_t q = b->next_seq - 1 - b->cursor_seq;
            size_t o = (size_t)snprintf(out, 2048, "{\"endpoint\":");
            json_put_str(out, 2048, &o, b->rule.url);
            o += (size_t)snprintf(out + o, 2048 - o,
                ",\"queue\":%llu,\"sent\":%llu,\"dropped\":%llu,\"failed_attempts\":%llu,\"last_ok\":%lld,"
                "\"backoff_until\":%lld,\"journal_ok\":%s,\"last_error\":",
                (unsigned long long)q, (unsigned long long)b->n_sent, (unsigned long long)b->n_dropped,
                (unsigned long long)b->n_failed_attempts, (long long)b->last_ok,
                (long long)(b->backoff_until > time(NULL) ? b->backoff_until : 0),
                b->journal_broken ? "false" : "true");
            json_put_str(out, 2048, &o, b->last_error);
            o += (size_t)snprintf(out + o, 2048 - o, ",\"last_error_time\":%lld}\n", (long long)b->last_error_t);
        }
        pthread_mutex_unlock(&n->mu);
        *status = test ? 202 : 200;
        return out;
    }
    if (*sub) return jerr(status, 404, "no such endpoint");

    if (!strcmp(method, "GET")) {
        notify_rule_t r;
        int lr = load_rule(n, bucket, &r);
        if (lr) return jerr(status, 404, lr > 0 ? "bucket has no notification rule" : "stored rule is invalid");
        char *out = malloc(4096);
        if (out) { size_t o = rule_json(&r, 0, out, 4094); out[o++] = '\n'; out[o] = 0; }
        OPENSSL_cleanse(&r, sizeof(r));
        *status = 200;
        return out;
    }
    if (!strcmp(method, "DELETE")) {
        notify_rule_t g;
        int had = load_rule(n, bucket, &g) != 1;
        OPENSSL_cleanse(&g, sizeof(g));
        if (had) store_bucket_sidecar_delete(n->cfg.store, bn, "notification.json");
        pthread_mutex_lock(&n->mu);
        nb_t *b = find_name(n, bucket, strlen(bucket));
        if (b) nb_kill(n, b);
        pthread_mutex_unlock(&n->mu);
        if (!had && !b) return jerr(status, 404, "bucket has no notification rule");
        audit_rule(bucket, "removed", NULL);
        *status = 200;
        return strdup("{\"ok\":true}\n");
    }
    if (strcmp(method, "PUT")) return jerr(status, 405, "use GET, PUT or DELETE");
    notify_rule_t old, r;
    int have_old = load_rule(n, bucket, &old) == 0;
    char err[300];
    int rc = notify_rule_parse(body, body_n, have_old ? &old : NULL, tls_available(), &r, err, sizeof(err));
    OPENSSL_cleanse(&old, sizeof(old));
    if (rc < 0) return jerr(status, 400, err);
    char stored[4096];
    size_t sn = rule_json(&r, 1, stored, sizeof(stored));
    s3_err_t e = store_bucket_sidecar_write(n->cfg.store, bn, "notification.json", stored, sn);
    OPENSSL_cleanse(stored, sizeof(stored));
    if (e != S3_OK) { OPENSSL_cleanse(&r, sizeof(r)); return jerr(status, 500, "cannot store the rule"); }
    pthread_mutex_lock(&n->mu);
    nb_t *b = find_name(n, bucket, strlen(bucket));
    if (b && !strcmp(b->id, bm.id)) {
        b->rule = r;
        b->backoff_until = 0;
        b->backoff_s = 0;
    } else {
        if (b) nb_kill(n, b);
        b = nb_load(n, bucket, bm.id, &r);
        if (b) { b->next = n->head; n->head = b; __atomic_fetch_add(&n->n_rules, 1, __ATOMIC_RELAXED); }
    }
    pthread_cond_broadcast(&n->work_cv);
    pthread_mutex_unlock(&n->mu);
    audit_rule(bucket, "set", &r);
    char *out = malloc(4096);
    if (out) { size_t o = rule_json(&r, 0, out, 4094); out[o++] = '\n'; out[o] = 0; }
    OPENSSL_cleanse(&r, sizeof(r));
    if (!b) { free(out); return jerr(status, 500, "rule stored but its queue could not be created"); }
    *status = 200;
    return out;
}

int notify_metrics(notify_t *n, char *out, size_t cap) {
    if (!n || !n->cfg.enabled) return 0;
    size_t o = 0;
#define P(...) do { int _k = snprintf(out + o, cap - o, __VA_ARGS__); \
                    if (_k < 0 || (size_t)_k >= cap - o) { pthread_mutex_unlock(&n->mu); return -1; } \
                    o += (size_t)_k; } while (0)
    pthread_mutex_lock(&n->mu);
    P("# HELP fs3_notify_queue_depth Event notifications not yet delivered.\n"
      "# TYPE fs3_notify_queue_depth gauge\n");
    for (nb_t *b = n->head; b; b = b->next) if (!b->dead)
        P("fs3_notify_queue_depth{bucket=\"%s\"} %llu\n", b->name, (unsigned long long)(b->next_seq - 1 - b->cursor_seq));
    P("# HELP fs3_notify_events_total Event notifications by result.\n# TYPE fs3_notify_events_total counter\n");
    for (nb_t *b = n->head; b; b = b->next) if (!b->dead) {
        P("fs3_notify_events_total{bucket=\"%s\",result=\"sent\"} %llu\n", b->name, (unsigned long long)b->n_sent);
        P("fs3_notify_events_total{bucket=\"%s\",result=\"dropped\"} %llu\n", b->name, (unsigned long long)b->n_dropped);
    }
    P("# HELP fs3_notify_failed_attempts_total Failed delivery attempts (retried).\n"
      "# TYPE fs3_notify_failed_attempts_total counter\n");
    for (nb_t *b = n->head; b; b = b->next) if (!b->dead)
        P("fs3_notify_failed_attempts_total{bucket=\"%s\"} %llu\n", b->name, (unsigned long long)b->n_failed_attempts);
    pthread_mutex_unlock(&n->mu);
#undef P
    return (int)o;
}
