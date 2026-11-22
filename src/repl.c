/* src/repl.c — asynchronous one-way bucket replication. See include/repl.h. */
#include "repl.h"

#include "audit.h"
#include "checksum.h"
#include "json.h"
#include "log.h"
#include "objmeta.h"
#include "s3client.h"
#include "store.h"
#include "ssekeys.h"
#include "tls.h"

#include <arpa/inet.h>
#include <openssl/crypto.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define REPL_BATCH_BYTES   (1u << 20)      /* journal bytes read per batch */
#define REPL_COMPACT_BYTES (1u << 20)      /* truncate a fully-consumed journal past this */
#define REPL_ERR_RING      10
#define REPL_BACKOFF_MAX   600
#define REPL_RECOVER_SLACK_MS 5000         /* re-queue objects this much older than the mark */

/* ===================================================================== */
/* Journal records                                                       */
/* ===================================================================== */

static void put_u16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put_u32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put_u64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint16_t get_u16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static uint32_t crc32c(const uint8_t *p, size_t n) {
    uint8_t d[CKSUM_MAX_DIGEST];
    size_t dl = 0;
    if (cksum_oneshot(S3_CKSUM_CRC32C, p, n, d, &dl) != 0 || dl != 4) return 0;
    return ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) | ((uint32_t)d[2] << 8) | d[3];
}

size_t repl_rec_encode(const repl_rec_t *rec, uint8_t *out, size_t cap) {
    size_t body = REPL_REC_FIXED + rec->key_len;
    if (rec->key_len > REPL_KEY_MAX || cap < REPL_REC_HDR + body) return 0;
    uint8_t *b = out + REPL_REC_HDR;
    put_u64(b, rec->seq);
    put_u64(b + 8, rec->mtime_ms);
    b[16] = (uint8_t)rec->op;
    put_u16(b + 17, (uint16_t)rec->key_len);
    memcpy(b + REPL_REC_FIXED, rec->key, rec->key_len);
    put_u32(out, (uint32_t)body);
    put_u32(out + 4, crc32c(b, body));
    return REPL_REC_HDR + body;
}

long repl_rec_decode(const uint8_t *buf, size_t n, repl_rec_t *out) {
    if (n < REPL_REC_HDR) return 0;
    uint32_t body = get_u32(buf);
    if (body < REPL_REC_FIXED + 1 || body > REPL_REC_FIXED + REPL_KEY_MAX) return -1;
    if (n < REPL_REC_HDR + body) return 0;
    const uint8_t *b = buf + REPL_REC_HDR;
    if (crc32c(b, body) != get_u32(buf + 4)) return -1;
    uint16_t kl = get_u16(b + 17);
    if (kl != body - REPL_REC_FIXED) return -1;
    if (b[16] != STORE_CHANGE_PUT && b[16] != STORE_CHANGE_DELETE) return -1;
    if (memchr(b + REPL_REC_FIXED, 0, kl)) return -1;
    out->seq = get_u64(b);
    out->mtime_ms = get_u64(b + 8);
    out->op = b[16];
    out->key_len = kl;
    memcpy(out->key, b + REPL_REC_FIXED, kl);
    out->key[kl] = 0;
    return (long)(REPL_REC_HDR + body);
}

/* ===================================================================== */
/* Rules                                                                 */
/* ===================================================================== */

/* Loopback, RFC 1918, link-local, CGNAT, ULA, or "localhost". */
static int host_is_private(const char *h) {
    if (!strcmp(h, "localhost")) return 1;
    unsigned char a[16];
    if (inet_pton(AF_INET, h, a) == 1) {
        return a[0] == 127 || a[0] == 10 || (a[0] == 172 && (a[1] & 0xf0) == 16)
            || (a[0] == 192 && a[1] == 168) || (a[0] == 169 && a[1] == 254)
            || (a[0] == 100 && (a[1] & 0xc0) == 64);
    }
    if (inet_pton(AF_INET6, h, a) == 1) {
        static const unsigned char lo[16] = { [15] = 1 };
        return !memcmp(a, lo, 16) || (a[0] & 0xfe) == 0xfc || (a[0] == 0xfe && (a[1] & 0xc0) == 0x80);
    }
    return 0;
}

static int printable_token(const char *s, size_t maxlen) {
    size_t n = strlen(s);
    if (n == 0 || n > maxlen) return 0;
    for (const char *p = s; *p; p++)
        if ((unsigned char)*p <= 0x20 || (unsigned char)*p >= 0x7f) return 0;
    return 1;
}

static int json_bool_field(const json_t *o, const char *k, int dflt, int *out) {
    const json_t *v = json_get(o, k);
    if (!v || v->type == JSON_NULL) { *out = dflt; return 0; }
    if (v->type != JSON_BOOL) return -1;
    *out = v->b;
    return 0;
}

static int json_str_field(const json_t *o, const char *k, char *out, size_t cap, int required) {
    const json_t *v = json_get(o, k);
    if (!v || v->type == JSON_NULL) { if (required) return -1; out[0] = 0; return 0; }
    if (v->type != JSON_STR || v->str_n >= cap || memchr(v->str, 0, v->str_n)) return -1;
    memcpy(out, v->str, v->str_n);
    out[v->str_n] = 0;
    return 0;
}

int repl_rule_parse(const char *json, size_t n, const repl_rule_t *old, int tls,
                    repl_rule_t *r, char *err, size_t errcap) {
    memset(r, 0, sizeof(*r));
    json_t *j = json_parse(json, n, 4, 64);
    if (!j || j->type != JSON_OBJ) { json_free(j); snprintf(err, errcap, "body must be a JSON object"); return -1; }
    char addressing[16] = "", unknown[48];
    int bad = 0;
    const char *what = "";
#define REQ(k, f, req) if (!bad && json_str_field(j, k, r->f, sizeof(r->f), req) < 0) { bad = 1; what = k; }
    REQ("endpoint", endpoint, 1);
    REQ("bucket", bucket, 1);
    REQ("access_key", access_key, 1);
    REQ("secret_key", secret_key, 0);
    REQ("region", region, 0);
    REQ("prefix", prefix, 0);
    REQ("storage_class", storage_class, 0);
#undef REQ
    if (!bad && json_str_field(j, "addressing", addressing, sizeof(addressing), 0) < 0) { bad = 1; what = "addressing"; }
    if (!bad && json_bool_field(j, "verify_tls", 1, &r->verify_tls) < 0) { bad = 1; what = "verify_tls"; }
    if (!bad && json_bool_field(j, "deletes", 1, &r->deletes) < 0) { bad = 1; what = "deletes"; }
    if (!bad && json_bool_field(j, "allow_plain_http", 0, &r->allow_plain_http) < 0) { bad = 1; what = "allow_plain_http"; }
    for (const json_t *c = j->child; !bad && c; c = c->next) {
        static const char *known[] = { "endpoint", "bucket", "access_key", "secret_key", "region",
            "prefix", "storage_class", "addressing", "verify_tls", "deletes", "allow_plain_http",
            "secret_key_set", NULL };
        int ok = 0;
        for (int i = 0; known[i]; i++) if (c->key && !strcmp(c->key, known[i])) ok = 1;
        if (!ok) {
            bad = 1;
            snprintf(unknown, sizeof(unknown), "%s", c->key ? c->key : "?");
            what = unknown;           /* c->key dies with json_free */
        }
    }
    json_free(j);
    if (bad) { snprintf(err, errcap, "missing or invalid field \"%.40s\"", what); return -1; }

    s3c_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    char e2[128];
    if (s3c_parse_endpoint(r->endpoint, &ep, e2, sizeof(e2)) < 0) {
        snprintf(err, errcap, "endpoint: %s", e2);
        return -1;
    }
    size_t el = strlen(r->endpoint);
    if (el && r->endpoint[el - 1] == '/') r->endpoint[el - 1] = 0;
    if (ep.https && !tls) {
        snprintf(err, errcap, "https endpoints need a TLS build of fs3 (fs3 --build-info shows tls=yes)");
        return -1;
    }
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
    if (!r->region[0]) snprintf(r->region, sizeof(r->region), "us-east-1");
    for (const char *p = r->region; *p; p++)
        if (!(islower((unsigned char)*p) || isdigit((unsigned char)*p) || *p == '-')) {
            snprintf(err, errcap, "region must match [a-z0-9-]+");
            return -1;
        }
    s3_str_t bn = { r->bucket, strlen(r->bucket) };
    if (!store_valid_bucket_name(bn)) { snprintf(err, errcap, "invalid remote bucket name"); return -1; }
    if (!printable_token(r->access_key, 128)) { snprintf(err, errcap, "invalid access_key"); return -1; }
    if (!r->secret_key[0]) {
        if (old && !strcmp(old->access_key, r->access_key) && old->secret_key[0])
            memcpy(r->secret_key, old->secret_key, sizeof(r->secret_key));
        else { snprintf(err, errcap, "secret_key is required"); return -1; }
    }
    if (!printable_token(r->secret_key, 256)) { snprintf(err, errcap, "invalid secret_key"); return -1; }
    if (!strcmp(addressing, "virtual")) r->virtual_host = 1;
    else if (addressing[0] && strcmp(addressing, "path")) {
        snprintf(err, errcap, "addressing must be \"path\" or \"virtual\"");
        return -1;
    }
    if (r->virtual_host && strchr(r->bucket, '.') && ep.https) {
        snprintf(err, errcap, "virtual-host addressing with a dotted bucket name breaks TLS name checks; use path");
        return -1;
    }
    for (const char *p = r->storage_class; *p; p++)
        if (!(isupper((unsigned char)*p) || isdigit((unsigned char)*p) || *p == '_')) {
            snprintf(err, errcap, "storage_class must match [A-Z0-9_]+");
            return -1;
        }
    if (!objmeta_valid_value(r->prefix, strlen(r->prefix))) {
        snprintf(err, errcap, "invalid prefix");
        return -1;
    }
    return 0;
}

/* Stored form (includes the secret; the sidecar is mode 0600). */
static size_t rule_json(const repl_rule_t *r, int with_secret, char *out, size_t cap) {
    size_t o = 0;
#define S(k, v) do { o += (size_t)snprintf(out + o, cap - o, "%s\"" k "\":", o > 1 ? "," : ""); \
                     json_put_str(out, cap, &o, v); } while (0)
    o += (size_t)snprintf(out, cap, "{");
    S("endpoint", r->endpoint);
    S("region", r->region);
    S("bucket", r->bucket);
    S("access_key", r->access_key);
    if (with_secret) S("secret_key", r->secret_key);
    S("prefix", r->prefix);
    S("addressing", r->virtual_host ? "virtual" : "path");
    if (r->storage_class[0]) S("storage_class", r->storage_class);
#undef S
    o += (size_t)snprintf(out + o, cap - o, ",\"verify_tls\":%s,\"deletes\":%s,\"allow_plain_http\":%s",
                          r->verify_tls ? "true" : "false", r->deletes ? "true" : "false",
                          r->allow_plain_http ? "true" : "false");
    if (!with_secret) o += (size_t)snprintf(out + o, cap - o, ",\"secret_key_set\":true");
    o += (size_t)snprintf(out + o, cap - o, "}");
    return o < cap ? o : cap - 1;
}

/* ===================================================================== */
/* State                                                                 */
/* ===================================================================== */

typedef struct {
    time_t t;
    char   key[160];
    char   msg[200];
} repl_err_t;

typedef struct rb {
    struct rb  *next;
    char        name[64];
    char        id[33];
    char        dir[4200];
    repl_rule_t rule;
    unsigned    gen;              /* bumped on rule change */
    int         dead;             /* rule removed; freed when idle */

    int         jfd;
    uint64_t    jsize;            /* journal bytes */
    uint64_t    next_seq;
    uint64_t    max_mtime;        /* newest record ever written (high-water) */
    int         dirty;            /* appended since the last fdatasync */
    int         journal_broken;   /* an append failed: a backfill is needed */

    uint64_t    cursor_seq;       /* last replicated record */
    uint64_t    cursor_off;       /* journal offset after it */
    uint64_t    oldest_ms;        /* mtime of the first unreplicated record */

    int         busy;
    int         need_recovery;
    int         backfill_req, backfill_running;
    uint64_t    bf_scanned, bf_queued;
    time_t      bf_done;
    time_t      backoff_until;
    int         backoff_s;

    uint64_t    n_put, n_del, n_fail, n_skip_ssec, n_skip_same, bytes;
    time_t      last_ok;
    repl_err_t  errs[REPL_ERR_RING];
    unsigned    n_errs;           /* total, ring index = n_errs % RING */
    char        last_error[200];
    time_t      last_error_t;
} rb_t;

struct repl {
    repl_cfg_t      cfg;
    char            dir[4096];
    pthread_mutex_t mu;            /* leaf: guards the rb list and every rb field */
    pthread_cond_t  work_cv;       /* workers */
    pthread_cond_t  sync_cv;       /* group commit */
    rb_t           *head;
    int             n_rules;       /* atomic read in the hook fast path */
    int             stop;
    int             started;
    pthread_t      *threads;
    int             n_threads;
    pthread_t       syncer;
    int             syncer_up;
    rb_t           *rr;            /* round-robin position */
    pthread_mutex_t rate_mu;
    double          rate_next;     /* monotonic seconds when the next byte may go */
    time_t          last_gc;
};

static double mono_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}
static uint64_t wall_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000);
}

static int stopping(repl_t *r) { return __atomic_load_n(&r->stop, __ATOMIC_RELAXED); }

static int fsync_path(const char *p) {
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int rc = fsync(fd);
    close(fd);
    return rc;
}

static int write_atomic(const char *dir, const char *name, const char *data, size_t n) {
    char tmp[4400], fin[4400];
    snprintf(fin, sizeof(fin), "%s/%s", dir, name);
    snprintf(tmp, sizeof(tmp), "%s/.%s.tmp", dir, name);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    ssize_t w = write(fd, data, n);
    if (w != (ssize_t)n || fsync(fd) < 0) { close(fd); unlink(tmp); return -1; }
    close(fd);
    if (rename(tmp, fin) < 0) { unlink(tmp); return -1; }
    fsync_path(dir);
    return 0;
}

static void rm_rf_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            char p[4400];
            snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
            unlink(p);
        }
        closedir(d);
    }
    rmdir(dir);
}

static void rb_error(rb_t *b, const char *key, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void rb_error(rb_t *b, const char *key, const char *fmt, ...) {
    repl_err_t *e = &b->errs[b->n_errs % REPL_ERR_RING];
    b->n_errs++;
    e->t = time(NULL);
    snprintf(e->key, sizeof(e->key), "%s", key ? key : "");
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e->msg, sizeof(e->msg), fmt, ap);
    va_end(ap);
    snprintf(b->last_error, sizeof(b->last_error), "%s", e->msg);
    b->last_error_t = e->t;
}

/* Cursor file: "<seq> <max_mtime>\n". */
static void cursor_load(rb_t *b) {
    char p[4400], buf[128] = "";
    snprintf(p, sizeof(p), "%s/cursor", b->dir);
    int fd = open(p, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = 0;
    unsigned long long seq = 0, mt = 0;
    if (sscanf(buf, "%llu %llu", &seq, &mt) >= 1) {
        b->cursor_seq = seq;
        if (mt > b->max_mtime) b->max_mtime = mt;
    }
}

static void cursor_save(const char *dir, uint64_t seq, uint64_t mt) {
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "%llu %llu\n", (unsigned long long)seq, (unsigned long long)mt);
    if (write_atomic(dir, "cursor", buf, (size_t)n) < 0)
        LOG_W("replication: cannot write %s/cursor: %s", dir, strerror(errno));
}

/* Open (creating) the journal, drop a torn tail, find next_seq and the
 * cursor offset (first record with seq > cursor_seq). */
static int journal_open(rb_t *b) {
    char p[4400];
    snprintf(p, sizeof(p), "%s/queue", b->dir);
    b->jfd = open(p, O_RDWR | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (b->jfd < 0) { LOG_E("replication: open %s: %s", p, strerror(errno)); return -1; }
    struct stat st;
    fstat(b->jfd, &st);
    uint64_t size = (uint64_t)st.st_size, off = 0;
    uint8_t *buf = malloc(REPL_BATCH_BYTES + 4096);
    if (!buf) return -1;
    uint64_t last_seq = b->cursor_seq;
    int found_cursor = 0;
    b->cursor_off = 0;
    while (off < size) {
        ssize_t n = pread(b->jfd, buf, REPL_BATCH_BYTES + 4096, (off_t)off);
        if (n <= 0) break;
        size_t pos = 0;
        long k = 0;
        repl_rec_t rec;
        while ((k = repl_rec_decode(buf + pos, (size_t)n - pos, &rec)) > 0) {
            if (rec.seq > last_seq) last_seq = rec.seq;
            if (rec.mtime_ms > b->max_mtime) b->max_mtime = rec.mtime_ms;
            if (!found_cursor && rec.seq > b->cursor_seq) {
                found_cursor = 1;
                b->cursor_off = off + pos;
                b->oldest_ms = rec.mtime_ms;
            }
            pos += (size_t)k;
        }
        off += pos;
        if (k < 0 || pos == 0) break;          /* corrupt, or a torn record at EOF */
    }
    free(buf);
    if (off < size) {
        LOG_W("replication: %s: dropping %llu byte(s) of torn/corrupt journal tail", p,
              (unsigned long long)(size - off));
        if (ftruncate(b->jfd, (off_t)off) < 0) { LOG_E("ftruncate %s: %s", p, strerror(errno)); return -1; }
        fdatasync(b->jfd);
        b->need_recovery = 1;
    }
    b->jsize = off;
    if (!found_cursor) b->cursor_off = off;
    b->next_seq = last_seq + 1;
    return 0;
}

static rb_t *find_name(repl_t *r, const char *name, size_t n) {
    for (rb_t *b = r->head; b; b = b->next)
        if (!b->dead && strlen(b->name) == n && !memcmp(b->name, name, n)) return b;
    return NULL;
}

/* Called with r->mu held. */
static int rb_append(repl_t *r, rb_t *b, int op, const char *key, size_t kn, uint64_t mtime) {
    if (b->jfd < 0 || kn > REPL_KEY_MAX) return -1;
    uint8_t buf[REPL_REC_HDR + REPL_REC_FIXED + REPL_KEY_MAX];
    repl_rec_t rec = { .seq = b->next_seq, .mtime_ms = mtime, .op = op, .key_len = kn };
    memcpy(rec.key, key, kn);
    size_t n = repl_rec_encode(&rec, buf, sizeof(buf));
    ssize_t w = write(b->jfd, buf, n);
    if (w != (ssize_t)n) {
        if (w > 0 && ftruncate(b->jfd, (off_t)b->jsize) < 0) { /* torn: dropped at next open */ }
        if (!b->journal_broken)
            LOG_E("replication: bucket %s: journal append failed (%s); a backfill will catch up",
                  b->name, w < 0 ? strerror(errno) : "short write");
        b->journal_broken = 1;
        return -1;
    }
    if (b->cursor_off == b->jsize) b->oldest_ms = mtime;
    b->jsize += n;
    b->next_seq++;
    if (mtime > b->max_mtime) b->max_mtime = mtime;
    b->dirty = 1;
    pthread_cond_signal(&r->sync_cv);
    pthread_cond_signal(&r->work_cv);
    return 0;
}

/* The store's change hook: runs under the key's stripe lock. */
static void on_change(void *user, const store_change_t *ev) {
    repl_t *r = user;
    s3_str_t bucket = ev->bucket, key = ev->key;
    int op = ev->op;
    uint64_t mtime_ms = ev->mtime_ms;
    if (!__atomic_load_n(&r->n_rules, __ATOMIC_RELAXED)) return;
    char id[33];
    pthread_mutex_lock(&r->mu);
    rb_t *b = find_name(r, bucket.p, bucket.n);
    int match = b && key.n >= strlen(b->rule.prefix)
                && !memcmp(key.p, b->rule.prefix, strlen(b->rule.prefix));
    if (match) memcpy(id, b->id, sizeof(id));
    pthread_mutex_unlock(&r->mu);
    if (!match) return;
    /* A deleted and re-created bucket of the same name must not feed the
     * old rule (the tick drops it shortly). No lock held here: reads
     * buckets/<b>/meta, which is in the page cache. */
    s3_bucket_meta_t bm;
    if (store_bucket_meta(r->cfg.store, bucket, &bm) != S3_OK || strcmp(bm.id, id)) return;
    pthread_mutex_lock(&r->mu);
    b = find_name(r, bucket.p, bucket.n);
    if (b && !strcmp(b->id, id)) rb_append(r, b, op, key.p, key.n, mtime_ms);
    pthread_mutex_unlock(&r->mu);
}

static rb_t *rb_load(repl_t *r, const char *name, const repl_rule_t *rule, const char *id) {
    rb_t *b = calloc(1, sizeof(*b));
    if (!b) return NULL;
    snprintf(b->name, sizeof(b->name), "%s", name);
    snprintf(b->id, sizeof(b->id), "%s", id);
    snprintf(b->dir, sizeof(b->dir), "%s/%s", r->dir, id);
    b->rule = *rule;
    b->jfd = -1;
    if (mkdir(b->dir, 0700) < 0 && errno != EEXIST) {
        LOG_E("replication: mkdir %s: %s", b->dir, strerror(errno));
        free(b);
        return NULL;
    }
    char p[4400];
    snprintf(p, sizeof(p), "%s/clean", b->dir);
    int clean = access(p, F_OK) == 0;
    snprintf(p, sizeof(p), "%s/cursor", b->dir);
    int existed = access(p, F_OK) == 0;
    cursor_load(b);
    if (journal_open(b) < 0) { if (b->jfd >= 0) close(b->jfd); free(b); return NULL; }
    if (!existed) {
        /* New rule: start the journal here; the high-water mark is now.
         * Existing objects are the backfill's job (POST .../sync). */
        b->max_mtime = wall_ms();
        cursor_save(b->dir, b->cursor_seq, b->max_mtime);
    } else if (!clean) {
        b->need_recovery = 1;
    }
    snprintf(p, sizeof(p), "%s/clean", b->dir);
    if (clean) { unlink(p); fsync_path(b->dir); }
    snprintf(p, sizeof(p), "%s/backfill", b->dir);
    if (access(p, F_OK) == 0) b->backfill_req = 1;     /* interrupted backfill: start over */
    return b;
}

static void rb_free(rb_t *b) {
    if (!b) return;
    if (b->jfd >= 0) close(b->jfd);
    memset(b->rule.secret_key, 0, sizeof(b->rule.secret_key));
    free(b);
}

static int load_rule(repl_t *r, const char *bucket, repl_rule_t *out) {
    char *d = NULL;
    size_t n = 0;
    s3_str_t b = { bucket, strlen(bucket) };
    if (store_bucket_sidecar_read(r->cfg.store, b, "replication.json", 16384, &d, &n) != S3_OK) return 1;
    char err[200];
    int rc = repl_rule_parse(d, n, NULL, tls_available(), out, err, sizeof(err));
    memset(d, 0, n);
    free(d);
    if (rc < 0) { LOG_E("replication: bucket %s: stored rule rejected: %s", bucket, err); return -1; }
    return 0;
}

/* ===================================================================== */
/* Lifecycle                                                             */
/* ===================================================================== */

repl_t *repl_create(const repl_cfg_t *cfg) {
    repl_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->cfg = *cfg;
    if (!r->cfg.part_size) r->cfg.part_size = 16ULL << 20;
    if (r->cfg.timeout_s <= 0) r->cfg.timeout_s = 30;
    pthread_mutex_init(&r->mu, NULL);
    pthread_mutex_init(&r->rate_mu, NULL);
    pthread_cond_init(&r->work_cv, NULL);
    pthread_cond_init(&r->sync_cv, NULL);
    snprintf(r->dir, sizeof(r->dir), "%s/repl", cfg->root);
    if (cfg->workers <= 0) return r;
    if (mkdir(r->dir, 0700) < 0 && errno != EEXIST) {
        LOG_E("replication: mkdir %s: %s", r->dir, strerror(errno));
        repl_destroy(r);
        return NULL;
    }
    s3_bucket_info_t *bl = NULL;
    size_t nb = 0;
    if (store_list_buckets(cfg->store, &bl, &nb) == S3_OK) {
        for (size_t i = 0; i < nb; i++) {
            repl_rule_t rule;
            if (load_rule(r, bl[i].name, &rule) != 0) continue;
            s3_bucket_meta_t bm;
            s3_str_t bn = { bl[i].name, strlen(bl[i].name) };
            if (store_bucket_meta(cfg->store, bn, &bm) != S3_OK || !bm.id[0]) continue;
            rb_t *b = rb_load(r, bl[i].name, &rule, bm.id);
            memset(rule.secret_key, 0, sizeof(rule.secret_key));
            if (!b) continue;
            b->next = r->head;
            r->head = b;
            r->n_rules++;
            LOG_I("replication: bucket %s -> %s/%s (%llu queued%s)", b->name, b->rule.endpoint,
                  b->rule.bucket, (unsigned long long)(b->next_seq - 1 - b->cursor_seq),
                  b->need_recovery ? ", recovery scan pending" : "");
        }
        store_buckets_free(bl, nb);
    }
    store_add_change_hook(cfg->store, on_change, r);
    return r;
}

static void *worker_main(void *arg);
static void *syncer_main(void *arg);

int repl_start(repl_t *r) {
    if (!r || r->cfg.workers <= 0) return 0;
    r->threads = calloc((size_t)r->cfg.workers, sizeof(pthread_t));
    if (!r->threads) return -1;
    if (pthread_create(&r->syncer, NULL, syncer_main, r) != 0) return -1;
    r->syncer_up = 1;
    for (int i = 0; i < r->cfg.workers; i++) {
        if (pthread_create(&r->threads[i], NULL, worker_main, r) != 0) return -1;
        r->n_threads++;
    }
    r->started = 1;
    LOG_I("replication: %d worker(s), rate %s", r->cfg.workers,
          r->cfg.rate ? "limited" : "unlimited");
    return 0;
}

void repl_destroy(repl_t *r) {
    if (!r) return;
    store_remove_change_hook(r->cfg.store, r);
    pthread_mutex_lock(&r->mu);
    __atomic_store_n(&r->stop, 1, __ATOMIC_RELAXED);
    pthread_cond_broadcast(&r->work_cv);
    pthread_cond_broadcast(&r->sync_cv);
    pthread_mutex_unlock(&r->mu);
    for (int i = 0; i < r->n_threads; i++) pthread_join(r->threads[i], NULL);
    if (r->syncer_up) pthread_join(r->syncer, NULL);
    free(r->threads);
    while (r->head) {
        rb_t *b = r->head;
        r->head = b->next;
        if (b->jfd >= 0 && !b->dead) {
            int ok = fdatasync(b->jfd) == 0 && !b->journal_broken;
            if (ok) {
                char p[4400];
                snprintf(p, sizeof(p), "%s/clean", b->dir);
                int fd = open(p, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
                if (fd >= 0) { fsync(fd); close(fd); fsync_path(b->dir); }
            }
        }
        rb_free(b);
    }
    pthread_mutex_destroy(&r->mu);
    pthread_mutex_destroy(&r->rate_mu);
    pthread_cond_destroy(&r->work_cv);
    pthread_cond_destroy(&r->sync_cv);
    free(r);
}

/* Group commit: fdatasync dirty journals at most every 10 ms. */
static void *syncer_main(void *arg) {
    repl_t *r = arg;
    pthread_mutex_lock(&r->mu);
    while (!stopping(r)) {
        int any = 0;
        for (rb_t *b = r->head; b; b = b->next) if (b->dirty) any = 1;
        if (!any) { pthread_cond_wait(&r->sync_cv, &r->mu); continue; }
        pthread_mutex_unlock(&r->mu);
        struct timespec d = { 0, 10 * 1000000 };
        nanosleep(&d, NULL);
        pthread_mutex_lock(&r->mu);
        int fds[64], n = 0;
        for (rb_t *b = r->head; b && n < 64; b = b->next)
            if (b->dirty && b->jfd >= 0) {
                b->dirty = 0;
                fds[n++] = dup(b->jfd);
            }
        pthread_mutex_unlock(&r->mu);
        for (int i = 0; i < n; i++) if (fds[i] >= 0) { fdatasync(fds[i]); close(fds[i]); }
        pthread_mutex_lock(&r->mu);
    }
    pthread_mutex_unlock(&r->mu);
    return NULL;
}

/* ===================================================================== */
/* Replicating one key                                                   */
/* ===================================================================== */

enum { RS_OK = 0, RS_RETRY, RS_FAIL, RS_SKIP, RS_GONE };

typedef struct {
    repl_t     *r;
    rb_t       *b;              /* only name/rule copies are used off-lock */
    char        bucket[64];
    repl_rule_t rule;
    s3c_t      *c;
    char        err[256];
    uint64_t    bytes;
    int         did_put, did_del, skip_ssec, skip_same;
} wctx_t;

static void rate_wait(repl_t *r, uint64_t n) {
    if (!r->cfg.rate || !n) return;
    pthread_mutex_lock(&r->rate_mu);
    double now = mono_now();
    if (r->rate_next < now) r->rate_next = now;
    double start = r->rate_next;
    r->rate_next += (double)n / (double)r->cfg.rate;
    pthread_mutex_unlock(&r->rate_mu);
    while (!stopping(r)) {
        double wait = start - mono_now();
        if (wait <= 0) break;
        struct timespec d = { 0, (long)((wait > 0.2 ? 0.2 : wait) * 1e9) };
        nanosleep(&d, NULL);
    }
}

/* 4xx codes that mean the rule (not this object) is wrong: keep the
 * record and back off. */
static int rule_level_error(const s3c_resp_t *resp) {
    static const char *codes[] = { "InvalidAccessKeyId", "SignatureDoesNotMatch", "NoSuchBucket",
        "AuthorizationHeaderMalformed", "RequestTimeTooSkewed", "InvalidToken", "ExpiredToken",
        "PermanentRedirect", "AccountProblem", "AllAccessDisabled", NULL };
    if (resp->status == 301 || resp->status == 307) return 1;
    for (int i = 0; codes[i]; i++) if (!strcmp(resp->code, codes[i])) return 1;
    return 0;
}

static int classify(wctx_t *w, int rc, const s3c_resp_t *resp, const char *what) {
    if (rc < 0) {
        snprintf(w->err, sizeof(w->err), "%s: %s", what, s3c_err(w->c));
        return RS_RETRY;
    }
    if (resp->status >= 200 && resp->status < 300) return RS_OK;
    snprintf(w->err, sizeof(w->err), "%s: HTTP %d%s%s", what, resp->status,
             resp->code[0] ? " " : "", resp->code);
    if (s3c_retryable(rc, resp) || rule_level_error(resp)) return RS_RETRY;
    return RS_FAIL;
}

typedef struct { s3c_hdr_t h[40]; char store[40][2][1100]; size_t n; size_t meta_bytes; } hdrs_t;

static void hdr_add(hdrs_t *h, const char *name, const char *value) {
    if (h->n >= 40 || strlen(name) >= 1100 || strlen(value) >= 1024) return;
    char *nm = h->store[h->n][0], *vl = h->store[h->n][1];
    size_t i = 0;
    for (; name[i]; i++) nm[i] = (char)tolower((unsigned char)name[i]);
    nm[i] = 0;
    snprintf(vl, 1100, "%s", value);
    h->h[h->n].name = nm;
    h->h[h->n].value = vl;
    h->n++;
}

static int meta_cb(void *ctx, int std_id, const char *name, const char *value) {
    hdrs_t *h = ctx;
    if (!std_id) h->meta_bytes += strlen(name) - 11 + strlen(value);
    hdr_add(h, name, value);
    return 0;
}

static void etag_hex(const s3_obj_meta_t *m, char out[48]) {
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) { out[2 * i] = H[m->etag[i] >> 4]; out[2 * i + 1] = H[m->etag[i] & 15]; }
    out[32] = 0;
    if (m->part_count) snprintf(out + 32, 16, "-%u", m->part_count);
}

/* Spool a transformed (compressed) payload into a temp file. */
static int spool(wctx_t *w, s3_reader_t *rd, char *path, size_t cap) {
    snprintf(path, cap, "%s/tmp.XXXXXX", w->r->dir);
    int fd = mkstemp(path);
    if (fd < 0) { snprintf(w->err, sizeof(w->err), "temp file: %s", strerror(errno)); return -1; }
    unlink(path);
    char *buf = malloc(1 << 16);
    if (!buf) { close(fd); return -1; }
    for (;;) {
        ssize_t n = store_get_read(rd, buf, 1 << 16);
        if (n < 0) { snprintf(w->err, sizeof(w->err), "read local object"); close(fd); fd = -1; break; }
        if (n == 0) break;
        if (write(fd, buf, (size_t)n) != n) {
            snprintf(w->err, sizeof(w->err), "temp file: %s", strerror(errno));
            close(fd); fd = -1; break;
        }
    }
    free(buf);
    return fd;
}

static int put_object(wctx_t *w, const char *key, int hint_del) {
    s3_str_t bn = { w->bucket, strlen(w->bucket) }, kn = { key, strlen(key) };
    s3_reader_t *rd = NULL;
    s3_obj_meta_t m;
    s3_err_t e = store_get_open(w->r->cfg.store, bn, kn, &rd, &m);
    if (e == S3_ERR_NO_SUCH_BUCKET) return RS_GONE;
    if (e == S3_ERR_NO_SUCH_KEY) {
        /* Gone (or a delete marker): mirror the delete. */
        if (!w->rule.deletes) return RS_SKIP;
        s3c_resp_t resp;
        int rc = s3c_delete_object(w->c, w->rule.bucket, key, &resp);
        if (rc == 0 && resp.status == 404) return RS_OK;
        int k = classify(w, rc, &resp, "DELETE");
        if (k == RS_OK) w->did_del = 1;
        return k;
    }
    if (e != S3_OK) {
        snprintf(w->err, sizeof(w->err), "open local object: error %d", (int)e);
        return RS_RETRY;
    }
    int sse_s3 = 0;
    if (m.flags & S3_OBJF_SSEC) {
        /* SSE-S3 (fs3 holds the key): replicate the plaintext; the target
         * applies its own encryption. SSE-C: fs3 has no key; skip. */
        uint8_t *t = NULL, skey[32];
        size_t tn = 0;
        char kid[SSEKEYS_ID_MAX + 1];
        if (store_reader_tlv(rd, &t, &tn) == S3_OK && ssekeys_tlv_find(t, tn, kid) == 1
            && ssekeys_find(kid, skey) == 0) {
            s3_str_t bn2 = { w->bucket, strlen(w->bucket) };
            sse_s3 = store_reader_ssec(w->r->cfg.store, bn2, rd, skey) == S3_OK;
            OPENSSL_cleanse(skey, sizeof(skey));
        }
        free(t);
        if (!sse_s3) { store_get_close(rd); w->skip_ssec = 1; return RS_SKIP; }
    }

    char local_etag[48];
    etag_hex(&m, local_etag);
    s3c_resp_t resp;
    if (hint_del) {
        /* A delete changed this key but an object is current again (an
         * older version was promoted, or a noncurrent version went away):
         * upload only if the replica doesn't already hold it. */
        int rc = s3c_head_object(w->c, w->rule.bucket, key, &resp);
        if (rc == 0 && resp.status == 200 && resp.content_length == m.size
            && (!strcmp(resp.src_etag, local_etag) || (!m.part_count && !strcmp(resp.etag, local_etag)))) {
            store_get_close(rd);
            w->skip_same = 1;
            return RS_OK;
        }
    }

    hdrs_t *h = calloc(1, sizeof(*h));
    if (!h) { store_get_close(rd); return RS_RETRY; }
    uint8_t *tlv = NULL;
    size_t tn = 0;
    if (store_reader_tlv(rd, &tlv, &tn) == S3_OK && tlv) {
        objmeta_walk(tlv, tn, 1, ~0u, meta_cb, h);
        free(tlv);
    }
    if (h->meta_bytes + 64 <= OBJMETA_MAX_USER) hdr_add(h, "x-amz-meta-fs3-source-etag", local_etag);
    if (w->rule.storage_class[0]) hdr_add(h, "x-amz-storage-class", w->rule.storage_class);
    int raw = !(m.flags & S3_OBJF_ZSTD) && !sse_s3;
    if (raw && !m.part_count) {
        char b64[32];
        size_t bl = base64_encode(m.etag, 16, b64);
        b64[bl] = 0;
        hdr_add(h, "content-md5", b64);
    }
    s3c_put_opts_t po = { .content_type = m.content_type[0] ? m.content_type : NULL,
                          .headers = h->h, .n_headers = h->n };

    int fd = -1, own_fd = 0;
    off_t off = 0;
    uint64_t len = 0;
    char tmp[4400];
    if (raw) {
        uint64_t rem = 0;
        store_get_raw(rd, &fd, &off, &rem);
        len = rem;
    } else {
        fd = spool(w, rd, tmp, sizeof(tmp));
        if (fd < 0) { free(h); store_get_close(rd); return RS_RETRY; }
        own_fd = 1;
        len = m.size;
    }

    int result;
    uint64_t ps = w->r->cfg.part_size;
    if (len <= ps * 4) {
        rate_wait(w->r, len);
        int rc = s3c_put_object(w->c, w->rule.bucket, key, fd, off, len, &po, &resp);
        result = classify(w, rc, &resp, "PUT");
    } else {
        int rc = s3c_mpu_create(w->c, w->rule.bucket, key, &po, &resp);
        result = classify(w, rc, &resp, "CreateMultipartUpload");
        char uid[256];
        snprintf(uid, sizeof(uid), "%s", resp.upload_id);
        int np = (int)((len + ps - 1) / ps);
        char (*etags)[80] = result == RS_OK ? calloc((size_t)np, 80) : NULL;
        if (result == RS_OK && !etags) result = RS_RETRY;
        for (int p = 0; result == RS_OK && p < np; p++) {
            uint64_t po_off = (uint64_t)p * ps, pl = len - po_off < ps ? len - po_off : ps;
            int tries = 0;
            do {
                rate_wait(w->r, pl);
                rc = s3c_mpu_upload_part(w->c, w->rule.bucket, key, uid, p + 1, fd,
                                         off + (off_t)po_off, pl, &resp);
                result = classify(w, rc, &resp, "UploadPart");
            } while (result == RS_RETRY && ++tries < 3 && !stopping(w->r));
            if (result == RS_OK) snprintf(etags[p], 80, "%s", resp.etag);
        }
        if (result == RS_OK) {
            rc = s3c_mpu_complete(w->c, w->rule.bucket, key, uid, etags, np, &resp);
            result = classify(w, rc, &resp, "CompleteMultipartUpload");
        }
        if (result != RS_OK && uid[0]) {
            s3c_resp_t ar;
            s3c_mpu_abort(w->c, w->rule.bucket, key, uid, &ar);
        }
        free(etags);
    }
    if (result == RS_OK) { w->did_put = 1; w->bytes += len; }
    if (own_fd) close(fd);
    free(h);
    store_get_close(rd);
    return result;
}

/* ===================================================================== */
/* Worker                                                                */
/* ===================================================================== */

typedef struct { uint64_t seq, mtime; int op; char *key; size_t idx; int skip; } item_t;

static int item_key_cmp(const void *a, const void *b) {
    const item_t *x = a, *y = b;
    int c = strcmp(x->key, y->key);
    if (c) return c;
    return x->seq < y->seq ? -1 : x->seq > y->seq;
}
static int item_idx_cmp(const void *a, const void *b) {
    const item_t *x = a, *y = b;
    return x->idx < y->idx ? -1 : x->idx > y->idx;
}

static void finish_batch(repl_t *r, rb_t *b, const wctx_t *w, uint64_t seq, uint64_t off,
                         uint64_t next_oldest, int result) {
    pthread_mutex_lock(&r->mu);
    if (seq > b->cursor_seq) { b->cursor_seq = seq; b->cursor_off = off; }
    b->oldest_ms = b->cursor_off < b->jsize ? next_oldest : 0;
    b->bytes += w->bytes;
    if (result == RS_RETRY) {
        b->backoff_s = b->backoff_s ? b->backoff_s * 2 : 1;
        if (b->backoff_s > REPL_BACKOFF_MAX) b->backoff_s = REPL_BACKOFF_MAX;
        b->backoff_until = time(NULL) + b->backoff_s;
    } else {
        b->backoff_s = 0;
        b->backoff_until = 0;
    }
    /* Compact a fully replicated journal. */
    if (b->cursor_off == b->jsize && b->jsize >= REPL_COMPACT_BYTES && b->jfd >= 0) {
        if (ftruncate(b->jfd, 0) == 0) { b->jsize = 0; b->cursor_off = 0; b->dirty = 1; }
    }
    uint64_t cs = b->cursor_seq, mt = b->max_mtime;
    char dir[4200];
    snprintf(dir, sizeof(dir), "%s", b->dir);
    pthread_mutex_unlock(&r->mu);
    cursor_save(dir, cs, mt);
}

static s3c_t *client_for(repl_t *r, const repl_rule_t *rule) {
    s3c_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    char err[128];
    if (s3c_parse_endpoint(rule->endpoint, &ep, err, sizeof(err)) < 0) return NULL;
    snprintf(ep.region, sizeof(ep.region), "%s", rule->region);
    snprintf(ep.access_key, sizeof(ep.access_key), "%s", rule->access_key);
    snprintf(ep.secret_key, sizeof(ep.secret_key), "%s", rule->secret_key);
    ep.virtual_host = rule->virtual_host;
    ep.verify_tls = rule->verify_tls;
    if (r->cfg.ca_file) snprintf(ep.ca_file, sizeof(ep.ca_file), "%s", r->cfg.ca_file);
    ep.timeout_s = r->cfg.timeout_s;
    s3c_t *c = s3c_new(&ep);
    memset(ep.secret_key, 0, sizeof(ep.secret_key));
    if (c) s3c_set_cancel(c, &r->stop);
    return c;
}

/* Record the outcome of one key in the bucket's counters (mu held by caller). */
static void count_result(rb_t *b, wctx_t *w, int res, const char *key) {
    if (res == RS_OK) {
        if (w->did_put) b->n_put++;
        if (w->did_del) b->n_del++;
        if (w->skip_same) b->n_skip_same++;
        b->last_ok = time(NULL);
    } else if (res == RS_SKIP) {
        if (w->skip_ssec) b->n_skip_ssec++;
    } else if (res == RS_FAIL) {
        b->n_fail++;
        rb_error(b, key, "%s", w->err);
    } else if (res == RS_RETRY) {
        rb_error(b, key, "%s (will retry)", w->err);
    }
}

static void process_key(repl_t *r, rb_t *b, wctx_t *w, const char *key, int op, int *result) {
    w->did_put = w->did_del = w->skip_ssec = w->skip_same = 0;
    w->err[0] = 0;
    int res = put_object(w, key, op == STORE_CHANGE_DELETE);
    if (res == RS_FAIL) {
        LOG_W("replication: bucket %s key %.200s: %s (skipped)", w->bucket, key, w->err);
        char ev[600];
        snprintf(ev, sizeof(ev), "replication bucket %s key %.200s failed: %s", w->bucket, key, w->err);
        audit_event("replication", ev);
    } else if (res == RS_RETRY) {
        LOG_W("replication: bucket %s: %s; backing off", w->bucket, w->err);
    }
    pthread_mutex_lock(&r->mu);
    count_result(b, w, res, key);
    pthread_mutex_unlock(&r->mu);
    *result = res;
}

/* Process one batch of journal records. */
static void run_queue(repl_t *r, rb_t *b, wctx_t *w) {
    pthread_mutex_lock(&r->mu);
    uint64_t start = b->cursor_off, end = b->jsize;
    int fd = b->jfd >= 0 ? dup(b->jfd) : -1;
    pthread_mutex_unlock(&r->mu);
    if (fd < 0 || start >= end) { if (fd >= 0) close(fd); return; }
    size_t want = end - start > REPL_BATCH_BYTES ? REPL_BATCH_BYTES : (size_t)(end - start);
    uint8_t *buf = malloc(want);
    ssize_t n = buf ? pread(fd, buf, want, (off_t)start) : -1;
    close(fd);
    if (n <= 0) { free(buf); return; }

    size_t cap = 256, ni = 0, pos = 0;
    item_t *it = malloc(cap * sizeof(*it));
    uint64_t *offs = malloc(cap * sizeof(*offs));
    repl_rec_t rec;
    long k;
    while (it && offs && (k = repl_rec_decode(buf + pos, (size_t)n - pos, &rec)) > 0) {
        if (ni == cap) {
            cap *= 2;
            item_t *ni2 = realloc(it, cap * sizeof(*it));
            uint64_t *no2 = realloc(offs, cap * sizeof(*offs));
            if (ni2) it = ni2;
            if (no2) offs = no2;
            if (!ni2 || !no2) break;
        }
        it[ni] = (item_t){ rec.seq, rec.mtime_ms, rec.op, strdup(rec.key), ni, 0 };
        if (!it[ni].key) break;
        pos += (size_t)k;
        offs[ni] = start + pos;
        ni++;
    }
    free(buf);
    if (!it || !offs || ni == 0) {
        for (size_t i = 0; it && i < ni; i++) free(it[i].key);
        free(it); free(offs);
        return;
    }
    /* Coalesce: only the last record of each key in the batch is worked;
     * the delete hint survives if any record for the key was a delete. */
    qsort(it, ni, sizeof(*it), item_key_cmp);
    for (size_t i = 0; i + 1 < ni; i++)
        if (!strcmp(it[i].key, it[i + 1].key)) {
            it[i].skip = 1;
            if (it[i].op == STORE_CHANGE_DELETE) it[i + 1].op = STORE_CHANGE_DELETE;
        }
    qsort(it, ni, sizeof(*it), item_idx_cmp);

    uint64_t done_seq = 0, done_off = start, next_oldest = 0;
    int result = RS_OK;
    for (size_t i = 0; i < ni; i++) {
        if (stopping(r)) { result = RS_RETRY; next_oldest = it[i].mtime; break; }
        if (!it[i].skip) {
            int res;
            process_key(r, b, w, it[i].key, it[i].op, &res);
            if (res == RS_RETRY) { result = RS_RETRY; next_oldest = it[i].mtime; break; }
            if (res == RS_GONE) { result = RS_GONE; break; }
        }
        done_seq = it[i].seq;
        done_off = offs[i];
        next_oldest = i + 1 < ni ? it[i + 1].mtime : 0;
    }
    for (size_t i = 0; i < ni; i++) free(it[i].key);
    free(it);
    free(offs);
    if (result != RS_GONE) finish_batch(r, b, w, done_seq, done_off, next_oldest, result);
}

/* Walk the bucket; replicate objects missing or different on the replica.
 * recovery_since > 0: instead queue every object newer than that. */
typedef struct { repl_t *r; rb_t *b; wctx_t *w; uint64_t since; int recovery; int fail; } walk_t;

static int walk_cb(void *user, s3_str_t key, const s3_obj_meta_t *m) {
    walk_t *wk = user;
    if (stopping(wk->r)) return 1;
    if (key.n > REPL_KEY_MAX) return 0;
    size_t pl = strlen(wk->w->rule.prefix);
    if (key.n < pl || memcmp(key.p, wk->w->rule.prefix, pl)) return 0;
    if (m->flags & S3_OBJF_DELETE_MARKER) return 0;
    if (wk->recovery) {
        if (m->mtime_ms + REPL_RECOVER_SLACK_MS < wk->since) return 0;
        pthread_mutex_lock(&wk->r->mu);
        rb_append(wk->r, wk->b, STORE_CHANGE_PUT, key.p, key.n, m->mtime_ms);
        pthread_mutex_unlock(&wk->r->mu);
        return 0;
    }
    char k[REPL_KEY_MAX + 1];
    memcpy(k, key.p, key.n);
    k[key.n] = 0;
    pthread_mutex_lock(&wk->r->mu);
    wk->b->bf_scanned++;
    pthread_mutex_unlock(&wk->r->mu);
    /* SSE objects are compared like the rest: an SSE-S3 ETag is the
     * plaintext MD5; SSE-C ones end up skipped (and counted) by the worker. */
    char le[48];
    etag_hex(m, le);
    s3c_resp_t resp;
    int rc = s3c_head_object(wk->w->c, wk->w->rule.bucket, k, &resp);
    if (rc == 0 && resp.status == 200 && resp.content_length == m->size
        && (!strcmp(resp.src_etag, le) || (!m->part_count && !strcmp(resp.etag, le))))
        return 0;
    if (rc < 0 || (resp.status != 200 && resp.status != 404)) {
        wk->w->err[0] = 0;
        if (classify(wk->w, rc, &resp, "HEAD") == RS_RETRY) { wk->fail = 1; return 1; }
    }
    /* Queue it: the journal gives ordering against concurrent changes and
     * retry/backoff for free. */
    pthread_mutex_lock(&wk->r->mu);
    rb_append(wk->r, wk->b, STORE_CHANGE_PUT, key.p, key.n, m->mtime_ms);
    wk->b->bf_queued++;
    pthread_mutex_unlock(&wk->r->mu);
    return 0;
}

static void run_walk(repl_t *r, rb_t *b, wctx_t *w, int recovery) {
    walk_t wk = { r, b, w, 0, recovery, 0 };
    pthread_mutex_lock(&r->mu);
    wk.since = b->max_mtime;
    pthread_mutex_unlock(&r->mu);
    s3_str_t bn = { w->bucket, strlen(w->bucket) };
    s3_err_t e = store_walk_objects(r->cfg.store, bn, walk_cb, &wk);
    pthread_mutex_lock(&r->mu);
    if (recovery) {
        if (e == S3_OK && !stopping(r)) b->need_recovery = 0;
        LOG_I("replication: bucket %s: recovery scan done (%llu queued)", b->name,
              (unsigned long long)(b->next_seq - 1 - b->cursor_seq));
    } else if (e == S3_OK && !wk.fail && !stopping(r)) {
        b->backfill_running = 0;
        b->backfill_req = 0;
        b->journal_broken = 0;
        b->bf_done = time(NULL);
        char p[4400];
        snprintf(p, sizeof(p), "%s/backfill", b->dir);
        unlink(p);
        LOG_I("replication: bucket %s: backfill scanned %llu object(s), queued %llu", b->name,
              (unsigned long long)b->bf_scanned, (unsigned long long)b->bf_queued);
    } else if (wk.fail) {
        rb_error(b, NULL, "backfill: %s (will retry)", w->err);
        b->backoff_s = b->backoff_s ? b->backoff_s * 2 : 1;
        if (b->backoff_s > REPL_BACKOFF_MAX) b->backoff_s = REPL_BACKOFF_MAX;
        b->backoff_until = time(NULL) + b->backoff_s;
    }
    pthread_mutex_unlock(&r->mu);
}

static int runnable(const rb_t *b, time_t now) {
    if (b->dead || b->busy || now < b->backoff_until) return 0;
    return b->need_recovery || b->backfill_req || b->cursor_off < b->jsize;
}

static void *worker_main(void *arg) {
    repl_t *r = arg;
    pthread_mutex_lock(&r->mu);
    while (!stopping(r)) {
        time_t now = time(NULL);
        rb_t *pick = NULL;
        /* Round-robin from after the last bucket served. */
        rb_t *startb = r->rr && r->rr->next ? r->rr->next : r->head;
        for (rb_t *b = startb; b && !pick; b = b->next) if (runnable(b, now)) pick = b;
        for (rb_t *b = r->head; b && b != startb && !pick; b = b->next) if (runnable(b, now)) pick = b;
        if (!pick) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
            pthread_cond_timedwait(&r->work_cv, &r->mu, &ts);
            continue;
        }
        r->rr = pick;
        pick->busy = 1;
        int recovery = pick->need_recovery, backfill = !recovery && pick->backfill_req;
        if (backfill && !pick->backfill_running) {
            pick->backfill_running = 1;
            pick->bf_scanned = pick->bf_queued = 0;
        }
        wctx_t *w = calloc(1, sizeof(*w));
        if (w) {
            w->r = r;
            w->b = pick;
            snprintf(w->bucket, sizeof(w->bucket), "%s", pick->name);
            w->rule = pick->rule;
        }
        pthread_mutex_unlock(&r->mu);

        if (w) {
            w->c = client_for(r, &w->rule);
            if (recovery) run_walk(r, pick, w, 1);
            else if (backfill && w->c) run_walk(r, pick, w, 0);
            else if (w->c) run_queue(r, pick, w);
            s3c_free(w->c);
            memset(w->rule.secret_key, 0, sizeof(w->rule.secret_key));
            free(w);
        }

        pthread_mutex_lock(&r->mu);
        pick->busy = 0;
        if (pick->dead) {
            /* Rule removed while we worked on it: unlink and free. */
            for (rb_t **pp = &r->head; *pp; pp = &(*pp)->next)
                if (*pp == pick) { *pp = pick->next; break; }
            if (r->rr == pick) r->rr = NULL;
            rm_rf_dir(pick->dir);
            rb_free(pick);
        }
    }
    pthread_mutex_unlock(&r->mu);
    return NULL;
}

/* ===================================================================== */
/* Self-healing scrub                                                    */
/* ===================================================================== */

int repl_scrub_repair(void *user, const char *bucket, const char *key, uint64_t ino,
                      uint64_t size, char *why, size_t whycap) {
    repl_t *r = user;
    if (!r || r->cfg.workers <= 0) return 0;
    repl_rule_t rule;
    pthread_mutex_lock(&r->mu);
    rb_t *b = find_name(r, bucket, strlen(bucket));
    int have = b && !strncmp(key, b->rule.prefix, strlen(b->rule.prefix));
    if (have) rule = b->rule;
    pthread_mutex_unlock(&r->mu);
    if (!have) return 0;
    int rc = -1;
    s3c_t *c = client_for(r, &rule);
    memset(rule.secret_key, 0, sizeof(rule.secret_key));
    char tmp[4400];
    snprintf(tmp, sizeof(tmp), "%s/heal.XXXXXX", r->dir);
    int fd = c ? mkstemp(tmp) : -1;
    if (fd < 0) { snprintf(why, whycap, "cannot set up the fetch"); s3c_free(c); return -1; }
    unlink(tmp);
    s3c_resp_t resp;
    int g = s3c_get_object(c, rule.bucket, key, fd, size, &resp);
    if (g < 0) snprintf(why, whycap, "fetch from replica: %s", s3c_err(c));
    else if (resp.status != 200) snprintf(why, whycap, "fetch from replica: HTTP %d %s", resp.status, resp.code);
    else {
        s3_str_t bn = { bucket, strlen(bucket) }, kn = { key, strlen(key) };
        struct stat st;
        uint64_t got = fstat(fd, &st) == 0 ? (uint64_t)st.st_size : 0;
        s3_err_t e = store_repair_object(r->cfg.store, bn, kn, ino, fd, got, why, whycap);
        rc = e == S3_OK ? 1 : -1;
    }
    close(fd);
    s3c_free(c);
    return rc;
}

/* ===================================================================== */
/* Tick: rules of deleted buckets                                        */
/* ===================================================================== */

/* mu held. Marks dead; frees now if no worker holds it. */
static void rb_kill(repl_t *r, rb_t *b, int remove_state) {
    if (b->dead) return;
    b->dead = 1;
    __atomic_fetch_sub(&r->n_rules, 1, __ATOMIC_RELAXED);
    if (b->busy) return;                  /* the worker frees it */
    for (rb_t **pp = &r->head; *pp; pp = &(*pp)->next)
        if (*pp == b) { *pp = b->next; break; }
    if (r->rr == b) r->rr = NULL;
    if (remove_state) rm_rf_dir(b->dir);
    rb_free(b);
}

void repl_tick(repl_t *r, time_t now) {
    if (!r || r->cfg.workers <= 0 || now - r->last_gc < 10) return;
    r->last_gc = now;
    pthread_mutex_lock(&r->mu);
    for (rb_t *b = r->head, *nx; b; b = nx) {
        nx = b->next;
        if (b->dead) continue;
        s3_bucket_meta_t bm;
        s3_str_t bn = { b->name, strlen(b->name) };
        if (store_bucket_meta(r->cfg.store, bn, &bm) != S3_OK || strcmp(bm.id, b->id)) {
            LOG_I("replication: bucket %s is gone; dropping its rule and queue", b->name);
            rb_kill(r, b, 1);
        }
    }
    pthread_mutex_unlock(&r->mu);
}

/* ===================================================================== */
/* Admin API                                                             */
/* ===================================================================== */

static char *jerr(int *status, int code, const char *msg) {
    *status = code;
    char *o = malloc(600);
    if (!o) return NULL;
    size_t n = (size_t)snprintf(o, 600, "{\"error\":");
    json_put_str(o, 600, &n, msg);
    snprintf(o + n, 600 - n, "}\n");
    return o;
}

static size_t status_json(repl_t *r, rb_t *b, char *out, size_t cap) {
    time_t now = time(NULL);
    uint64_t q = b->next_seq - 1 - b->cursor_seq;
    uint64_t lag = q && b->oldest_ms ? (wall_ms() > b->oldest_ms ? (wall_ms() - b->oldest_ms) / 1000 : 0) : 0;
    size_t o = 0;
    o += (size_t)snprintf(out + o, cap - o, "{\"target\":");
    char tgt[400];
    snprintf(tgt, sizeof(tgt), "%s/%s", b->rule.endpoint, b->rule.bucket);
    json_put_str(out, cap, &o, tgt);
    o += (size_t)snprintf(out + o, cap - o,
        ",\"queue\":%llu,\"lag_seconds\":%llu,\"replicated\":%llu,\"deleted\":%llu,"
        "\"unchanged\":%llu,\"failed\":%llu,\"skipped_ssec\":%llu,\"bytes\":%llu,"
        "\"last_ok\":%lld,\"backoff_until\":%lld,\"journal_ok\":%s,\"recovery_pending\":%s,"
        "\"backfill\":{\"requested\":%s,\"running\":%s,\"scanned\":%llu,\"queued\":%llu,\"done\":%lld},"
        "\"last_error\":",
        (unsigned long long)q, (unsigned long long)lag, (unsigned long long)b->n_put,
        (unsigned long long)b->n_del, (unsigned long long)b->n_skip_same,
        (unsigned long long)b->n_fail, (unsigned long long)b->n_skip_ssec,
        (unsigned long long)b->bytes, (long long)b->last_ok,
        (long long)(b->backoff_until > now ? b->backoff_until : 0),
        b->journal_broken ? "false" : "true", b->need_recovery ? "true" : "false",
        b->backfill_req ? "true" : "false", b->backfill_running ? "true" : "false",
        (unsigned long long)b->bf_scanned, (unsigned long long)b->bf_queued, (long long)b->bf_done);
    json_put_str(out, cap, &o, b->last_error);
    o += (size_t)snprintf(out + o, cap - o, ",\"last_error_time\":%lld,\"errors\":[",
                          (long long)b->last_error_t);
    unsigned n = b->n_errs < REPL_ERR_RING ? b->n_errs : REPL_ERR_RING;
    for (unsigned i = 0; i < n && o + 600 < cap; i++) {
        const repl_err_t *e = &b->errs[(b->n_errs - 1 - i) % REPL_ERR_RING];
        o += (size_t)snprintf(out + o, cap - o, "%s{\"time\":%lld,\"key\":", i ? "," : "", (long long)e->t);
        json_put_str(out, cap, &o, e->key);
        o += (size_t)snprintf(out + o, cap - o, ",\"error\":");
        json_put_str(out, cap, &o, e->msg);
        o += (size_t)snprintf(out + o, cap - o, "}");
    }
    o += (size_t)snprintf(out + o, cap - o, "]}");
    (void)r;
    return o < cap ? o : cap - 1;
}

void repl_bucket_summary(repl_t *r, const char *bucket, char *out, size_t cap, size_t *o) {
    if (!r || r->cfg.workers <= 0) return;
    pthread_mutex_lock(&r->mu);
    rb_t *b = find_name(r, bucket, strlen(bucket));
    if (b && *o + 300 < cap) {
        char tgt[400];
        snprintf(tgt, sizeof(tgt), "%s/%s", b->rule.endpoint, b->rule.bucket);
        *o += (size_t)snprintf(out + *o, cap - *o, ",\"replication\":{\"target\":");
        json_put_str(out, cap, o, tgt);
        *o += (size_t)snprintf(out + *o, cap - *o, ",\"queue\":%llu,\"failed\":%llu,\"last_error\":",
                               (unsigned long long)(b->next_seq - 1 - b->cursor_seq),
                               (unsigned long long)b->n_fail);
        json_put_str(out, cap, o, b->last_error);
        if (*o + 2 < cap) { out[(*o)++] = '}'; out[*o] = 0; }
    }
    pthread_mutex_unlock(&r->mu);
}

static void audit_rule(const char *bucket, const char *what, const repl_rule_t *rule) {
    char ev[1000];
    if (rule)
        snprintf(ev, sizeof(ev), "bucket %s replication %s -> %s/%s key %s prefix \"%.100s\" deletes=%d",
                 bucket, what, rule->endpoint, rule->bucket, rule->access_key, rule->prefix, rule->deletes);
    else
        snprintf(ev, sizeof(ev), "bucket %s replication %s", bucket, what);
    LOG_I("admin: %s", ev);
    audit_event("admin-api", ev);
}

char *repl_admin(repl_t *r, const char *method, const char *bucket, const char *sub,
                 const char *body, size_t body_n, int *status) {
    if (!r || r->cfg.workers <= 0)
        return jerr(status, 501, "replication is disabled (--repl-workers 0)");
    s3_str_t bn = { bucket, strlen(bucket) };
    s3_bucket_meta_t bm;
    if (store_bucket_meta(r->cfg.store, bn, &bm) != S3_OK) return jerr(status, 404, "no such bucket");
    if (!bm.id[0]) return jerr(status, 409, "bucket has no id yet; set its owner first");

    if (!strcmp(sub, "status") || !strcmp(sub, "sync")) {
        int is_sync = !strcmp(sub, "sync");
        if (is_sync && strcmp(method, "POST")) return jerr(status, 405, "use POST");
        if (!is_sync && strcmp(method, "GET")) return jerr(status, 405, "use GET");
        pthread_mutex_lock(&r->mu);
        rb_t *b = find_name(r, bucket, strlen(bucket));
        if (!b) { pthread_mutex_unlock(&r->mu); return jerr(status, 404, "bucket has no replication rule"); }
        if (is_sync) {
            b->backfill_req = 1;
            b->backoff_until = 0;
            char p[4400];
            snprintf(p, sizeof(p), "%s/backfill", b->dir);
            int fd = open(p, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
            if (fd >= 0) close(fd);
            pthread_cond_broadcast(&r->work_cv);
        }
        size_t cap = 16384;
        char *out = malloc(cap);
        if (out) {
            size_t o = status_json(r, b, out, cap - 2);
            out[o++] = '\n';
            out[o] = 0;
        }
        pthread_mutex_unlock(&r->mu);
        if (is_sync) audit_rule(bucket, "backfill requested", NULL);
        *status = is_sync ? 202 : 200;
        return out;
    }
    if (*sub) return jerr(status, 404, "no such endpoint");

    if (!strcmp(method, "GET")) {
        repl_rule_t rule;
        int lr = load_rule(r, bucket, &rule);
        if (lr) return jerr(status, 404, lr > 0 ? "bucket has no replication rule" : "stored rule is invalid");
        char *out = malloc(4096);
        if (!out) return NULL;
        size_t o = rule_json(&rule, 0, out, 4094);
        memset(rule.secret_key, 0, sizeof(rule.secret_key));
        out[o++] = '\n';
        out[o] = 0;
        *status = 200;
        return out;
    }
    if (!strcmp(method, "DELETE")) {
        repl_rule_t gone;
        int had = load_rule(r, bucket, &gone) != 1;     /* present, even if invalid */
        memset(&gone, 0, sizeof(gone));
        s3_err_t e = had ? store_bucket_sidecar_delete(r->cfg.store, bn, "replication.json")
                         : S3_ERR_NO_SUCH_KEY;
        pthread_mutex_lock(&r->mu);
        rb_t *b = find_name(r, bucket, strlen(bucket));
        if (b) rb_kill(r, b, 1);
        pthread_mutex_unlock(&r->mu);
        if (e != S3_OK && !b) return jerr(status, 404, "bucket has no replication rule");
        audit_rule(bucket, "removed", NULL);
        *status = 200;
        char *out = strdup("{\"ok\":true}\n");
        return out;
    }
    if (strcmp(method, "PUT")) return jerr(status, 405, "use GET, PUT or DELETE");

    repl_rule_t old, rule;
    int have_old = load_rule(r, bucket, &old) == 0;
    char err[300];
    if (repl_rule_parse(body, body_n, have_old ? &old : NULL, tls_available(), &rule, err, sizeof(err)) < 0) {
        memset(&old, 0, sizeof(old));
        return jerr(status, 400, err);
    }
    memset(&old, 0, sizeof(old));
    char stored[4096];
    size_t sn = rule_json(&rule, 1, stored, sizeof(stored));
    s3_err_t e = store_bucket_sidecar_write(r->cfg.store, bn, "replication.json", stored, sn);
    memset(stored, 0, sizeof(stored));
    if (e != S3_OK) { memset(&rule, 0, sizeof(rule)); return jerr(status, 500, "cannot store the rule"); }

    pthread_mutex_lock(&r->mu);
    rb_t *b = find_name(r, bucket, strlen(bucket));
    if (b && !strcmp(b->id, bm.id)) {
        /* Same bucket: new settings apply to queued records too. */
        b->rule = rule;
        b->gen++;
        b->backoff_until = 0;
        b->backoff_s = 0;
    } else {
        if (b) rb_kill(r, b, 1);
        b = rb_load(r, bucket, &rule, bm.id);
        if (b) {
            b->next = r->head;
            r->head = b;
            __atomic_fetch_add(&r->n_rules, 1, __ATOMIC_RELAXED);
        }
    }
    pthread_cond_broadcast(&r->work_cv);
    pthread_mutex_unlock(&r->mu);
    audit_rule(bucket, "set", &rule);
    char *out = malloc(4096);
    if (out) {
        size_t o = rule_json(&rule, 0, out, 4094);
        out[o++] = '\n';
        out[o] = 0;
    }
    memset(&rule, 0, sizeof(rule));
    if (!b) return jerr(status, 500, "rule stored but replication state could not be created");
    *status = 200;
    return out;
}

/* ===================================================================== */
/* Metrics                                                               */
/* ===================================================================== */

int repl_render_text(repl_t *r, char *out, size_t cap) {
    if (!cap) return -1;
    out[0] = 0;
    if (!r || r->cfg.workers <= 0) return 0;
    size_t o = 0;
    uint64_t now = wall_ms();
    pthread_mutex_lock(&r->mu);
    for (rb_t *b = r->head; b; b = b->next) {
        if (b->dead) continue;
        uint64_t q = b->next_seq - 1 - b->cursor_seq;
        uint64_t lag = q && b->oldest_ms && now > b->oldest_ms ? (now - b->oldest_ms) / 1000 : 0;
        char err[200];
        size_t k = 0;
        for (const char *p = b->last_error; *p && k + 1 < sizeof(err); p++)
            err[k++] = ((unsigned char)*p < 0x20 || *p == 0x7f) ? ' ' : *p;
        err[k] = 0;
        int n = snprintf(out + o, cap - o, "%s %llu %llu %llu %s/%s %s\n", b->name,
                         (unsigned long long)q, (unsigned long long)b->n_fail,
                         (unsigned long long)lag, b->rule.endpoint, b->rule.bucket,
                         err[0] ? err : "-");
        if (n < 0 || (size_t)n >= cap - o) { pthread_mutex_unlock(&r->mu); return -1; }
        o += (size_t)n;
    }
    pthread_mutex_unlock(&r->mu);
    return (int)o;
}

int repl_metrics(repl_t *r, char *out, size_t cap) {
    if (!r || r->cfg.workers <= 0) return 0;
    size_t o = 0;
#define P(...) do { int _n = snprintf(out + o, cap - o, __VA_ARGS__); \
                    if (_n < 0 || (size_t)_n >= cap - o) { pthread_mutex_unlock(&r->mu); return -1; } \
                    o += (size_t)_n; } while (0)
    pthread_mutex_lock(&r->mu);
    P("# HELP fs3_repl_queue_depth Replication records not yet replicated.\n"
      "# TYPE fs3_repl_queue_depth gauge\n");
    for (rb_t *b = r->head; b; b = b->next) if (!b->dead)
        P("fs3_repl_queue_depth{bucket=\"%s\"} %llu\n", b->name,
          (unsigned long long)(b->next_seq - 1 - b->cursor_seq));
    P("# HELP fs3_repl_lag_seconds Age of the oldest unreplicated change.\n"
      "# TYPE fs3_repl_lag_seconds gauge\n");
    uint64_t now = wall_ms();
    for (rb_t *b = r->head; b; b = b->next) if (!b->dead) {
        uint64_t q = b->next_seq - 1 - b->cursor_seq;
        P("fs3_repl_lag_seconds{bucket=\"%s\"} %llu\n", b->name,
          (unsigned long long)(q && b->oldest_ms && now > b->oldest_ms ? (now - b->oldest_ms) / 1000 : 0));
    }
    P("# HELP fs3_repl_bytes_total Bytes uploaded to replicas.\n# TYPE fs3_repl_bytes_total counter\n");
    for (rb_t *b = r->head; b; b = b->next) if (!b->dead)
        P("fs3_repl_bytes_total{bucket=\"%s\"} %llu\n", b->name, (unsigned long long)b->bytes);
    P("# HELP fs3_repl_ops_total Replicated keys by operation and result.\n"
      "# TYPE fs3_repl_ops_total counter\n");
    for (rb_t *b = r->head; b; b = b->next) if (!b->dead) {
        P("fs3_repl_ops_total{bucket=\"%s\",op=\"put\",result=\"ok\"} %llu\n", b->name, (unsigned long long)b->n_put);
        P("fs3_repl_ops_total{bucket=\"%s\",op=\"delete\",result=\"ok\"} %llu\n", b->name, (unsigned long long)b->n_del);
        P("fs3_repl_ops_total{bucket=\"%s\",op=\"any\",result=\"unchanged\"} %llu\n", b->name, (unsigned long long)b->n_skip_same);
        P("fs3_repl_ops_total{bucket=\"%s\",op=\"any\",result=\"failed\"} %llu\n", b->name, (unsigned long long)b->n_fail);
        P("fs3_repl_ops_total{bucket=\"%s\",op=\"put\",result=\"skipped_ssec\"} %llu\n", b->name, (unsigned long long)b->n_skip_ssec);
    }
    P("# HELP fs3_repl_errors_total Replication errors (retried and permanent).\n"
      "# TYPE fs3_repl_errors_total counter\n");
    for (rb_t *b = r->head; b; b = b->next) if (!b->dead)
        P("fs3_repl_errors_total{bucket=\"%s\"} %u\n", b->name, b->n_errs);
    pthread_mutex_unlock(&r->mu);
#undef P
    return (int)o;
}
