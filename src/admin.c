/* src/admin.c — admin HTTP API (item 11). See include/admin.h. */

#include "admin.h"
#include "audit.h"
#include "json.h"
#include "log.h"
#include "scrub.h"
#include "repl.h"
#include "notify.h"
#include "sigv4.h"
#include "store.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

struct admin_ctx {
    admin_cfg_t cfg;
    char       *token;
    size_t      token_n;
    int         fails;
    time_t      blocked_until;
};

admin_ctx_t *admin_create(const admin_cfg_t *cfg) {
    admin_ctx_t *a = calloc(1, sizeof(*a));
    if (!a) return NULL;
    a->cfg = *cfg;
    if (cfg->token) {
        a->token = strdup(cfg->token);
        if (!a->token) { free(a); return NULL; }
        a->token_n = strlen(a->token);
    }
    return a;
}

void admin_destroy(admin_ctx_t *a) {
    if (!a) return;
    if (a->token) { OPENSSL_cleanse(a->token, a->token_n); free(a->token); }
    free(a);
}

/* ---- Response helpers ------------------------------------------------- */

static char *respond(int status, const char *reason, const char *body,
                     size_t *n_out) {
    size_t bn = strlen(body);
    size_t cap = bn + 256;
    char *r = malloc(cap);
    if (!r) return NULL;
    int n = snprintf(r, cap,
        "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\n"
        "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
        status, reason, bn, body);
    *n_out = (size_t)n;
    return r;
}

static char *err_json(int status, const char *reason, const char *msg,
                      size_t *n_out) {
    char b[512];
    size_t o = 0;
    o += (size_t)snprintf(b, sizeof(b), "{\"error\":");
    json_put_str(b, sizeof(b), &o, msg);
    snprintf(b + o, sizeof(b) - o, "}\n");
    return respond(status, reason, b, n_out);
}

/* ---- Request parsing ----------------------------------------------------- */

typedef struct {
    char        method[8];
    char        path[1024];
    const char *auth;   size_t auth_n;
    const char *origin;
    const char *host;   size_t host_n;
    const char *body;   size_t body_n;
} areq_t;

static int parse_req(const char *req, size_t n, areq_t *r) {
    memset(r, 0, sizeof(*r));
    const char *end = memmem(req, n, "\r\n\r\n", 4);
    if (!end) return -1;
    const char *sp1 = memchr(req, ' ', (size_t)(end - req));
    if (!sp1 || sp1 - req >= (long)sizeof(r->method)) return -1;
    memcpy(r->method, req, (size_t)(sp1 - req));
    const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(end - sp1 - 1));
    if (!sp2 || sp2 - sp1 - 1 >= (long)sizeof(r->path)) return -1;
    memcpy(r->path, sp1 + 1, (size_t)(sp2 - sp1 - 1));
    const char *line = memchr(req, '\n', (size_t)(end - req));
    while (line && line < end) {
        line++;
        const char *eol = memchr(line, '\r', (size_t)(end + 2 - line));
        if (!eol) break;
        const char *colon = memchr(line, ':', (size_t)(eol - line));
        if (colon) {
            size_t kn = (size_t)(colon - line);
            const char *v = colon + 1;
            while (v < eol && *v == ' ') v++;
            size_t vn = (size_t)(eol - v);
            if (kn == 13 && strncasecmp(line, "authorization", 13) == 0) {
                r->auth = v; r->auth_n = vn;
            } else if (kn == 6 && strncasecmp(line, "origin", 6) == 0) {
                r->origin = v;
            } else if (kn == 4 && strncasecmp(line, "host", 4) == 0) {
                r->host = v; r->host_n = vn;
            }
        }
        line = memchr(eol, '\n', (size_t)(end + 4 - eol));
        if (line >= end) break;
    }
    r->body = end + 4;
    r->body_n = n - (size_t)(end + 4 - req);
    return 0;
}

static int host_is_loopback(const areq_t *r) {
    if (!r->host) return 0;
    size_t n = r->host_n;
    const char *h = r->host;
    /* strip :port (not inside [::1]) */
    const char *colon = memrchr(h, ':', n);
    const char *rb = memchr(h, ']', n);
    if (colon && (!rb || colon > rb)) n = (size_t)(colon - h);
    return (n == 9 && !memcmp(h, "127.0.0.1", 9)) || (n == 9 && !strncasecmp(h, "localhost", 9))
        || (n == 5 && !memcmp(h, "[::1]", 5));
}

/* ---- Credentials file ---------------------------------------------------- */


static char *slurp(const char *path, size_t *n_out) {
    FILE *f = fopen(path, "re");
    if (!f) return NULL;
    size_t cap = 4096, n = 0;
    char *b = malloc(cap);
    while (b) {
        size_t got = fread(b + n, 1, cap - n - 1, f);
        n += got;
        if (got == 0) break;
        if (n + 1 >= cap) {
            if (cap > (1u << 20)) { free(b); b = NULL; break; }
            char *nb = realloc(b, cap * 2);
            if (!nb) { free(b); b = NULL; break; }
            b = nb; cap *= 2;
        }
    }
    fclose(f);
    if (b) { b[n] = '\0'; *n_out = n; }
    return b;
}

static int write_atomic(const char *path, const char *data, size_t n) {
    char tmp[4200];
    snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
    int fd = mkstemp(tmp);
    if (fd < 0) return -1;
    fchmod(fd, 0600);
    if (write(fd, data, n) != (ssize_t)n || fsync(fd) < 0) {
        close(fd); unlink(tmp); return -1;
    }
    close(fd);
    if (rename(tmp, path) < 0) { unlink(tmp); return -1; }
    char dir[4200];
    snprintf(dir, sizeof(dir), "%s", path);
    char *sl = strrchr(dir, '/');
    if (sl) { *sl = '\0'; } else { snprintf(dir, sizeof(dir), "."); }
    int dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) { fsync(dfd); close(dfd); }
    return 0;
}

static int json_u64_field(const json_t *obj, const char *key, uint64_t *out);

/* One credentials line: "ak:sk[:user[:attrs]]". */
typedef struct {
    char ak[129], sk[257], user[129], attrs[256];
    int  explicit_user;
} cred_line_t;

/* 1 credential, 0 comment/blank, -1 unparseable. */
static int cred_parse_line(const char *line, size_t n, cred_line_t *c) {
    memset(c, 0, sizeof(*c));
    while (n && (line[n-1] == ' ' || line[n-1] == '\t' || line[n-1] == '\r')) n--;
    if (n == 0 || line[0] == '#') return 0;
    const char *end = line + n;
    const char *c1 = memchr(line, ':', n);
    if (!c1 || c1 == line || (size_t)(c1 - line) > 128) return -1;
    memcpy(c->ak, line, (size_t)(c1 - line));
    const char *c2 = memchr(c1 + 1, ':', (size_t)(end - c1 - 1));
    const char *sk_end = c2 ? c2 : end;
    if ((size_t)(sk_end - c1 - 1) > 256) return -1;
    memcpy(c->sk, c1 + 1, (size_t)(sk_end - c1 - 1));
    if (c2) {
        const char *c3 = memchr(c2 + 1, ':', (size_t)(end - c2 - 1));
        const char *u_end = c3 ? c3 : end;
        if ((size_t)(u_end - c2 - 1) > 128) return -1;
        memcpy(c->user, c2 + 1, (size_t)(u_end - c2 - 1));
        if (c3) {
            if ((size_t)(end - c3 - 1) >= sizeof(c->attrs)) return -1;
            memcpy(c->attrs, c3 + 1, (size_t)(end - c3 - 1));
        }
    }
    c->explicit_user = c->user[0] != '\0';
    if (!c->user[0]) snprintf(c->user, sizeof(c->user), "%s", c->ak);
    return 1;
}

/* Lenient (display/edit) attribute parse; the server's loader is the
 * strict one and refuses the file on anything unknown. */
static void attrs_parse(const char *s, sigv4_cred_attrs_t *a) {
    memset(a, 0, sizeof(*a));
    for (const char *p = s; p && *p; ) {
        const char *e = strchr(p, ',');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n == 2 && !strncmp(p, "ro", 2)) a->read_only = 1;
        else if (n == 8 && !strncmp(p, "disabled", 8)) a->disabled = 1;
        else if (n > 8 && !strncmp(p, "created=", 8)) a->created = strtoll(p + 8, NULL, 10);
        else if (n > 8 && !strncmp(p, "expires=", 8)) a->expires = strtoll(p + 8, NULL, 10);
        p = e ? e + 1 : NULL;
    }
}

static void attrs_format(const sigv4_cred_attrs_t *a, char *out, size_t cap) {
    size_t o = 0;
    out[0] = '\0';
#define ADD(...) do { if (o) out[o++] = ','; o += (size_t)snprintf(out + o, cap - o, __VA_ARGS__); } while (0)
    if (a->created) ADD("created=%lld", (long long)a->created);
    if (a->expires) ADD("expires=%lld", (long long)a->expires);
    if (a->read_only) ADD("ro");
    if (a->disabled) ADD("disabled");
#undef ADD
}

/* "ak:sk[:user[:attrs]]\n" into out. */
static int cred_format_line(const cred_line_t *c, const sigv4_cred_attrs_t *a, char *out, size_t cap) {
    char at[256];
    attrs_format(a, at, sizeof(at));
    if (at[0])
        return snprintf(out, cap, "%s:%s:%s:%s\n", c->ak, c->sk, c->explicit_user ? c->user : "", at);
    if (c->explicit_user) return snprintf(out, cap, "%s:%s:%s\n", c->ak, c->sk, c->user);
    return snprintf(out, cap, "%s:%s\n", c->ak, c->sk);
}

typedef struct { const char *ak; int64_t last_used; } lu_probe_t;
static void lu_cb(void *ctx, const char *ak, const char *user, const sigv4_cred_attrs_t *a,
                  int64_t last_used) {
    (void)user; (void)a;
    lu_probe_t *p = ctx;
    if (!strcmp(ak, p->ak)) p->last_used = last_used;
}

static void key_json(admin_ctx_t *a, const cred_line_t *c, char *out, size_t cap, size_t *o) {
    sigv4_cred_attrs_t at;
    attrs_parse(c->attrs, &at);
    lu_probe_t lu = { c->ak, 0 };
    if (a->cfg.auth) sigv4_foreach_cred(a->cfg.auth, lu_cb, &lu);
    *o += (size_t)snprintf(out + *o, cap - *o, "{\"access_key\":");
    json_put_str(out, cap, o, c->ak);
    *o += (size_t)snprintf(out + *o, cap - *o, ",\"user\":");
    json_put_str(out, cap, o, c->user);
    *o += (size_t)snprintf(out + *o, cap - *o,
        ",\"created\":%lld,\"expires\":%lld,\"disabled\":%s,\"read_only\":%s,\"last_used\":%lld}",
        (long long)at.created, (long long)at.expires, at.disabled ? "true" : "false",
        at.read_only ? "true" : "false", (long long)lu.last_used);
}

static void random_chars(char *out, size_t n, const char *alphabet) {
    size_t an = strlen(alphabet);
    unsigned char rb[64];
    size_t o = 0;
    while (o < n) {
        if (RAND_bytes(rb, sizeof(rb)) != 1) abort();      /* no weak keys */
        for (size_t i = 0; i < sizeof(rb) && o < n; i++) {
            if (rb[i] >= 256 - (256 % an)) continue;       /* no modulo bias */
            out[o++] = alphabet[rb[i] % an];
        }
    }
    out[n] = '\0';
}

static char *keys_list(admin_ctx_t *a, size_t *rn) {
    size_t n;
    char *f = slurp(a->cfg.cred_file, &n);
    if (!f) return err_json(500, "Internal Server Error", "cannot read credentials file", rn);
    size_t cap = n * 2 + 1024, o = 0;
    char *out = malloc(cap);
    if (!out) { free(f); return NULL; }
    o += (size_t)snprintf(out, cap, "{\"keys\":[");
    int first = 1;
    for (char *l = f; *l; ) {
        char *e = strchr(l, '\n');
        size_t ln = e ? (size_t)(e - l) : strlen(l);
        cred_line_t c;
        if (cred_parse_line(l, ln, &c) == 1 && o + 600 < cap) {
            if (!first) out[o++] = ',';
            first = 0;
            key_json(a, &c, out, cap, &o);
        }
        OPENSSL_cleanse(c.sk, sizeof(c.sk));
        l = e ? e + 1 : l + ln;
    }
    snprintf(out + o, cap - o, "]}\n");
    OPENSSL_cleanse(f, n);
    free(f);
    char *r = respond(200, "OK", out, rn);
    free(out);
    return r;
}

static char *keys_create(admin_ctx_t *a, const areq_t *rq, size_t *rn) {
    char user[129] = "";
    int64_t new_expires = -1;
    int new_ro = 0;
    if (rq->body_n) {
        json_t *j = json_parse(rq->body, rq->body_n, 4, 64);
        if (!j || j->type != JSON_OBJ) { json_free(j); return err_json(400, "Bad Request", "invalid JSON", rn); }
        const char *u = json_str(json_get(j, "user"));
        if (json_get(j, "user") && !u) { json_free(j); return err_json(400, "Bad Request", "user must be a string", rn); }
        const json_t *je = json_get(j, "expires"), *jr = json_get(j, "read_only");
        if (je && je->type != JSON_NULL) {
            uint64_t ev;
            if (json_u64_field(j, "expires", &ev) < 0 || ev > 99999999999ULL) {
                json_free(j);
                return err_json(400, "Bad Request", "expires must be epoch seconds", rn);
            }
            new_expires = (int64_t)ev;
        }
        if (jr) {
            if (jr->type != JSON_BOOL) { json_free(j); return err_json(400, "Bad Request", "read_only must be a boolean", rn); }
            new_ro = jr->b;
        }
        if (u) {
            /* S3: strict charset at every write path into the file. */
            if (!s3_valid_ident_strict(u)) {
                json_free(j);
                return err_json(400, "Bad Request", "user must match [A-Za-z0-9._@-]{1,128}", rn);
            }
            snprintf(user, sizeof(user), "%s", u);
        }
        json_free(j);
    }
    char ak[21], sk[41];
    random_chars(ak + 3, 17, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    memcpy(ak, "FS3", 3);
    random_chars(sk, 40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    if (!user[0]) snprintf(user, sizeof(user), "%s", ak);

    size_t n = 0;
    char *f = slurp(a->cfg.cred_file, &n);
    if (!f) return err_json(500, "Internal Server Error", "cannot read credentials file", rn);
    size_t cap = n + 256;
    char *nf = malloc(cap);
    if (!nf) { free(f); return NULL; }
    sigv4_cred_attrs_t at;
    memset(&at, 0, sizeof(at));
    at.created = (int64_t)time(NULL);
    at.read_only = new_ro;
    if (new_expires > 0) at.expires = new_expires;
    else if (new_expires < 0 && a->cfg.key_max_age_days > 0)       /* --key-max-age-days */
        at.expires = at.created + (int64_t)a->cfg.key_max_age_days * 86400;
    char ats[256];
    attrs_format(&at, ats, sizeof(ats));
    int m = snprintf(nf, cap, "%s%s%s:%s:%s:%s\n", f, (n && f[n-1] != '\n') ? "\n" : "",
                     ak, sk, user, ats);
    char *resp;
    if (write_atomic(a->cfg.cred_file, nf, (size_t)m) < 0) {
        resp = err_json(500, "Internal Server Error", "cannot write credentials file", rn);
    } else if (a->cfg.reload && a->cfg.reload(a->cfg.reload_user) != 0) {
        write_atomic(a->cfg.cred_file, f, n);       /* roll back */
        resp = err_json(500, "Internal Server Error", "reload failed; change rolled back", rn);
    } else {
        char b[512];
        size_t o = 0;
        o += (size_t)snprintf(b, sizeof(b), "{\"access_key\":");
        json_put_str(b, sizeof(b), &o, ak);
        o += (size_t)snprintf(b + o, sizeof(b) - o, ",\"secret_key\":");
        json_put_str(b, sizeof(b), &o, sk);
        o += (size_t)snprintf(b + o, sizeof(b) - o, ",\"user\":");
        json_put_str(b, sizeof(b), &o, user);
        snprintf(b + o, sizeof(b) - o, ",\"created\":%lld,\"expires\":%lld,\"read_only\":%s}\n",
                 (long long)at.created, (long long)at.expires, at.read_only ? "true" : "false");
        resp = respond(201, "Created", b, rn);
        OPENSSL_cleanse(b, sizeof(b));
        LOG_I("admin: created access key %s for user %s", ak, user);
        { char ev[1400]; snprintf(ev, sizeof(ev), "create key %s for %s", ak, user); audit_event("admin-api", ev); }
    }
    OPENSSL_cleanse(sk, sizeof(sk));
    OPENSSL_cleanse(nf, cap);
    free(nf);
    OPENSSL_cleanse(f, n);
    free(f);
    return resp;
}

static char *keys_delete(admin_ctx_t *a, const char *ak_del, size_t *rn) {
    size_t n = 0;
    char *f = slurp(a->cfg.cred_file, &n);
    if (!f) return err_json(500, "Internal Server Error", "cannot read credentials file", rn);
    char *nf = malloc(n + 1);
    if (!nf) { free(f); return NULL; }
    size_t o = 0;
    int found = 0, kept = 0;
    for (char *l = f; *l; ) {
        char *e = strchr(l, '\n');
        size_t ln = e ? (size_t)(e - l) + 1 : strlen(l);
        cred_line_t cl;
        int r = cred_parse_line(l, e ? ln - 1 : ln, &cl);
        OPENSSL_cleanse(cl.sk, sizeof(cl.sk));
        if (r == 1 && strcmp(cl.ak, ak_del) == 0) {
            found = 1;
        } else {
            if (r == 1) kept++;
            memcpy(nf + o, l, ln);
            o += ln;
        }
        l += ln;
    }
    char *resp;
    if (!found) {
        resp = err_json(404, "Not Found", "no such access key", rn);
    } else if (kept == 0) {
        resp = err_json(409, "Conflict", "refusing to delete the last access key", rn);
    } else if (write_atomic(a->cfg.cred_file, nf, o) < 0) {
        resp = err_json(500, "Internal Server Error", "cannot write credentials file", rn);
    } else if (a->cfg.reload && a->cfg.reload(a->cfg.reload_user) != 0) {
        write_atomic(a->cfg.cred_file, f, n);
        resp = err_json(500, "Internal Server Error", "reload failed; change rolled back", rn);
    } else {
        LOG_I("admin: deleted access key %s", ak_del);
        { char ev[1400]; snprintf(ev, sizeof(ev), "delete key %s", ak_del); audit_event("admin-api", ev); }
        resp = respond(200, "OK", "{\"deleted\":true}\n", rn);
    }
    OPENSSL_cleanse(nf, n + 1);
    free(nf);
    OPENSSL_cleanse(f, n);
    free(f);
    return resp;
}

/* PATCH /v1/keys/<ak> {"disabled":bool,"read_only":bool,"expires":N|0|null}.
 * Takes effect at once (file rewrite + reload). Refuses to disable the
 * last enabled key. */
static char *keys_patch(admin_ctx_t *a, const char *ak_p, const areq_t *rq, size_t *rn) {
    json_t *j = json_parse(rq->body, rq->body_n, 4, 64);
    if (!j || j->type != JSON_OBJ) { json_free(j); return err_json(400, "Bad Request", "invalid JSON", rn); }
    const json_t *jd = json_get(j, "disabled"), *jr = json_get(j, "read_only"),
                 *je = json_get(j, "expires");
    int bad = (jd && jd->type != JSON_BOOL) || (jr && jr->type != JSON_BOOL);
    uint64_t ev = 0;
    if (je && je->type != JSON_NULL && (json_u64_field(j, "expires", &ev) < 0 || ev > 99999999999ULL))
        bad = 1;
    int set_d = jd ? jd->b : -1, set_r = jr ? jr->b : -1;
    json_free(j);
    if (bad) return err_json(400, "Bad Request",
                             "fields: disabled (bool), read_only (bool), expires (epoch seconds, 0/null = never)", rn);

    size_t n = 0;
    char *f = slurp(a->cfg.cred_file, &n);
    if (!f) return err_json(500, "Internal Server Error", "cannot read credentials file", rn);
    size_t cap = n + 512;
    char *nf = malloc(cap);
    if (!nf) { free(f); return NULL; }
    size_t o = 0;
    int found = 0, enabled_left = 0;
    cred_line_t hit;
    sigv4_cred_attrs_t hat;
    memset(&hit, 0, sizeof(hit));
    memset(&hat, 0, sizeof(hat));
    for (char *l = f; *l; ) {
        char *e = strchr(l, '\n');
        size_t ln = e ? (size_t)(e - l) + 1 : strlen(l);
        cred_line_t cl;
        int r = cred_parse_line(l, e ? ln - 1 : ln, &cl);
        if (r == 1 && !strcmp(cl.ak, ak_p)) {
            found = 1;
            sigv4_cred_attrs_t at;
            attrs_parse(cl.attrs, &at);
            if (set_d >= 0) at.disabled = set_d;
            if (set_r >= 0) at.read_only = set_r;
            if (je) at.expires = (int64_t)ev;
            if (!at.disabled) enabled_left++;
            int m = cred_format_line(&cl, &at, nf + o, cap - o);
            if (m > 0 && (size_t)m < cap - o) o += (size_t)m;
            hit = cl;
            hat = at;
            snprintf(hit.attrs, sizeof(hit.attrs), "%s", "");
            attrs_format(&at, hit.attrs, sizeof(hit.attrs));
        } else {
            if (r == 1) {
                sigv4_cred_attrs_t at;
                attrs_parse(cl.attrs, &at);
                if (!at.disabled) enabled_left++;
            }
            if (o + ln < cap) { memcpy(nf + o, l, ln); o += ln; }
        }
        OPENSSL_cleanse(cl.sk, sizeof(cl.sk));
        l += ln;
    }
    char *resp;
    if (!found) {
        resp = err_json(404, "Not Found", "no such access key", rn);
    } else if (enabled_left == 0) {
        resp = err_json(409, "Conflict", "refusing to disable the last enabled access key", rn);
    } else if (write_atomic(a->cfg.cred_file, nf, o) < 0) {
        resp = err_json(500, "Internal Server Error", "cannot write credentials file", rn);
    } else if (a->cfg.reload && a->cfg.reload(a->cfg.reload_user) != 0) {
        write_atomic(a->cfg.cred_file, f, n);
        resp = err_json(500, "Internal Server Error", "reload failed; change rolled back", rn);
    } else {
        char b[1024];
        size_t bo = 0;
        key_json(a, &hit, b, sizeof(b) - 2, &bo);
        b[bo++] = '\n';
        b[bo] = '\0';
        char ev2[1400];
        snprintf(ev2, sizeof(ev2), "patch key %s disabled=%d read_only=%d expires=%lld", ak_p,
                 hat.disabled, hat.read_only, (long long)hat.expires);
        LOG_I("admin: %s", ev2);
        audit_event("admin-api", ev2);
        resp = respond(200, "OK", b, rn);
    }
    OPENSSL_cleanse(hit.sk, sizeof(hit.sk));
    OPENSSL_cleanse(nf, cap);
    free(nf);
    OPENSSL_cleanse(f, n);
    free(f);
    return resp;
}

/* ---- Buckets ------------------------------------------------------------- */

static void perms_str(int p, char out[4]) {
    size_t o = 0;
    if (p & S3_GRANT_R) out[o++] = 'r';
    if (p & S3_GRANT_W) out[o++] = 'w';
    if (p & S3_GRANT_O) out[o++] = 'o';
    out[o] = '\0';
}

static int has_sidecar(admin_ctx_t *a, s3_str_t b, const char *name) {
    char *d = NULL;
    size_t n;
    if (store_bucket_sidecar_read(a->cfg.store, b, name, 1 << 20, &d, &n) != S3_OK)
        return 0;
    free(d);
    return 1;
}

/* ---- Quotas (round 2, item 2) ------------------------------------------- */

/* Non-negative integer field; absent → 0. -1 if present but not one. */
static int json_u64_field(const json_t *obj, const char *key, uint64_t *out) {
    const json_t *j = json_get(obj, key);
    *out = 0;
    if (!j || j->type == JSON_NULL) return 0;
    if (j->type != JSON_NUM || !j->str || !j->str[0] || strlen(j->str) > 19) return -1;
    for (const char *c = j->str; *c; c++) if (*c < '0' || *c > '9') return -1;
    *out = strtoull(j->str, NULL, 10);
    return 0;
}

static void quota_json(const s3_quota_usage_t *u, char *out, size_t cap, size_t *o) {
    *o += (size_t)snprintf(out + *o, cap - *o,
        "\"usage\":{\"bytes\":%llu,\"objects\":%llu,\"reserved\":%llu},"
        "\"quota\":{\"max_bytes\":%llu,\"max_objects\":%llu,\"explicit\":%s}",
        (unsigned long long)u->bytes, (unsigned long long)u->objects,
        (unsigned long long)u->reserved, (unsigned long long)u->max_bytes,
        (unsigned long long)u->max_objects, u->has_cfg ? "true" : "false");
}

/* GET / PUT {"max_bytes":N,"max_objects":N} / DELETE on a bucket's or
 * user's quota (user == NULL: bucket b). */
static char *quota_route(admin_ctx_t *a, const areq_t *rq, s3_str_t b, const char *user,
                         size_t *rn) {
    s3_err_t e = S3_OK;
    char what[200];
    if (user) snprintf(what, sizeof(what), "user %s", user);
    else      snprintf(what, sizeof(what), "bucket %.*s", (int)b.n, b.p);
    if (!strcmp(rq->method, "PUT")) {
        json_t *j = json_parse(rq->body, rq->body_n, 4, 64);
        uint64_t mb = 0, mo = 0;
        int bad = !j || json_u64_field(j, "max_bytes", &mb) < 0
               || json_u64_field(j, "max_objects", &mo) < 0;
        json_free(j);
        if (bad) return err_json(400, "Bad Request",
                                 "body must be {\"max_bytes\":N,\"max_objects\":N} (0 = unlimited)", rn);
        e = user ? store_user_quota_set(a->cfg.store, user, mb, mo)
                 : store_bucket_quota_set(a->cfg.store, b, mb, mo);
        if (e == S3_OK) {
            char ev[400];
            snprintf(ev, sizeof(ev), "quota %s max_bytes=%llu max_objects=%llu", what,
                     (unsigned long long)mb, (unsigned long long)mo);
            LOG_I("admin: %s", ev);
            audit_event("admin-api", ev);
        }
    } else if (!strcmp(rq->method, "DELETE")) {
        e = user ? store_user_quota_clear(a->cfg.store, user)
                 : store_bucket_quota_clear(a->cfg.store, b);
        if (e == S3_OK) {
            char ev[300];
            snprintf(ev, sizeof(ev), "quota %s cleared", what);
            audit_event("admin-api", ev);
        }
    } else if (strcmp(rq->method, "GET") != 0) {
        return err_json(405, "Method Not Allowed", "use GET, PUT or DELETE", rn);
    }
    if (e != S3_OK) return err_json(500, "Internal Server Error", "cannot write quota", rn);
    s3_quota_usage_t u;
    e = user ? store_user_usage(a->cfg.store, user, &u) : store_bucket_usage(a->cfg.store, b, &u);
    if (e != S3_OK) return err_json(404, "Not Found", "no such bucket", rn);
    char out[1024];
    size_t o = (size_t)snprintf(out, sizeof(out), "{");
    quota_json(&u, out, sizeof(out), &o);
    snprintf(out + o, sizeof(out) - o, "}\n");
    return respond(200, "OK", out, rn);
}

static char *bucket_json(admin_ctx_t *a, const char *name, int detail,
                         char *out, size_t cap, size_t *o) {
    s3_str_t b = { name, strlen(name) };
    s3_bucket_meta_t m;
    if (store_bucket_meta(a->cfg.store, b, &m) != S3_OK) return NULL;
    s3_bucket_stats_t st = {0};
    store_bucket_stats(a->cfg.store, b, &st);
    *o += (size_t)snprintf(out + *o, cap - *o, "{\"name\":");
    json_put_str(out, cap, o, name);
    *o += (size_t)snprintf(out + *o, cap - *o, ",\"owner\":");
    json_put_str(out, cap, o, m.owner);
    *o += (size_t)snprintf(out + *o, cap - *o, ",\"objects\":%llu,\"bytes\":%llu",
                           (unsigned long long)st.objects, (unsigned long long)st.bytes);
    s3_quota_usage_t qu;
    if (store_bucket_usage(a->cfg.store, b, &qu) == S3_OK && *o + 300 < cap) {
        out[(*o)++] = ',';
        quota_json(&qu, out, cap, o);
    }
    if (detail) {
        *o += (size_t)snprintf(out + *o, cap - *o, ",\"id\":");
        json_put_str(out, cap, o, m.id);
        s3_grant_t *g = NULL;
        size_t ng = 0;
        store_bucket_grants_get(a->cfg.store, b, &g, &ng);
        *o += (size_t)snprintf(out + *o, cap - *o, ",\"grants\":{");
        for (size_t i = 0; i < ng && *o + 300 < cap; i++) {
            char p[4];
            perms_str(g[i].perms, p);
            if (i) out[(*o)++] = ',';
            json_put_str(out, cap, o, g[i].user);
            out[(*o)++] = ':';
            json_put_str(out, cap, o, p);
        }
        free(g);
        *o += (size_t)snprintf(out + *o, cap - *o,
            "},\"versioning\":\"%s\",\"object_lock\":%s,\"cors\":%s,"
            "\"lifecycle\":%s,\"website\":%s,\"policy\":%s",
            store_bucket_versioning(a->cfg.store, b),
            store_bucket_object_lock(a->cfg.store, b) ? "true" : "false",
            has_sidecar(a, b, "cors.xml") ? "true" : "false",
            has_sidecar(a, b, "lifecycle.xml") ? "true" : "false",
            has_sidecar(a, b, "website.xml") ? "true" : "false",
            has_sidecar(a, b, "policy.json") ? "true" : "false");
    }
    repl_bucket_summary(a->cfg.repl, name, out, cap - 2, o);
    if (*o + 2 < cap) out[(*o)++] = '}';
    out[*o] = '\0';
    return out;
}

static char *buckets_list(admin_ctx_t *a, size_t *rn) {
    s3_bucket_info_t *bl = NULL;
    size_t nb = 0;
    if (store_list_buckets(a->cfg.store, &bl, &nb) != S3_OK)
        return err_json(500, "Internal Server Error", "cannot list buckets", rn);
    size_t cap = 512 + nb * 768, o = 0;
    char *out = malloc(cap);
    if (!out) { store_buckets_free(bl, nb); return NULL; }
    o += (size_t)snprintf(out, cap, "{\"buckets\":[");
    int first = 1;
    for (size_t i = 0; i < nb; i++) {
        size_t save = o;
        if (!first) out[o++] = ',';
        if (!bucket_json(a, bl[i].name, 0, out, cap, &o)) { o = save; continue; }
        first = 0;
    }
    snprintf(out + o, cap - o, "]}\n");
    store_buckets_free(bl, nb);
    char *r = respond(200, "OK", out, rn);
    free(out);
    return r;
}

/* ---- Object browser support: listing and presigned URLs ---------------- */

/* URI-encode for an S3 path: unreserved and '/' stay, the rest is %XX. */
static size_t pct_enc(const char *p, size_t n, char *out, size_t cap) {
    static const char H[] = "0123456789ABCDEF";
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        int raw = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
               || c == '-' || c == '.' || c == '_' || c == '~' || c == '/';
        if (o + (raw ? 1 : 3) >= cap) return (size_t)-1;
        if (raw) out[o++] = (char)c;
        else { out[o++] = '%'; out[o++] = H[c >> 4]; out[o++] = H[c & 15]; }
    }
    out[o] = 0;
    return o;
}

static int hexv(char c) {
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10
         : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

/* Query parameter `name` of "a=b&c=d", form-decoded. Length, -1 if
 * absent, -2 if malformed, too long or containing NUL. */
static long qparam(const char *q, const char *name, char *out, size_t cap) {
    size_t nl = strlen(name);
    for (const char *p = q; p && *p; ) {
        const char *amp = strchr(p, '&');
        size_t seg = amp ? (size_t)(amp - p) : strlen(p);
        if (seg > nl && p[nl] == '=' && !strncmp(p, name, nl)) {
            size_t o = 0;
            for (size_t i = nl + 1; i < seg; i++) {
                char c = p[i];
                if (c == '+') c = ' ';
                else if (c == '%') {
                    if (i + 2 >= seg) return -2;
                    int hi = hexv(p[i + 1]), lo = hexv(p[i + 2]);
                    if (hi < 0 || lo < 0) return -2;
                    c = (char)(hi * 16 + lo);
                    i += 2;
                }
                if (!c || o + 1 >= cap) return -2;
                out[o++] = c;
            }
            out[o] = 0;
            return (long)o;
        }
        if (seg == nl && !strncmp(p, name, nl)) { out[0] = 0; return 0; }
        p = amp ? amp + 1 : NULL;
    }
    return -1;
}

typedef struct { char *p; size_t n, cap; int oom; } abuf_t;
static void ab_put(abuf_t *b, const char *s, size_t n) {
    if (b->oom) return;
    if (b->n + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (nc < b->n + n + 1) nc *= 2;
        char *np = realloc(b->p, nc);
        if (!np) { b->oom = 1; return; }
        b->p = np; b->cap = nc;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
}
static void ab_fmt(abuf_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void ab_fmt(abuf_t *b, const char *fmt, ...) {
    char t[512];
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(t, sizeof(t), fmt, ap);
    va_end(ap);
    if (k > 0) ab_put(b, t, (size_t)k < sizeof(t) ? (size_t)k : sizeof(t) - 1);
}
static void ab_jstr(abuf_t *b, const char *s, size_t n) {
    char *t = malloc(n * 6 + 3);
    if (!t) { b->oom = 1; return; }
    char *z = malloc(n + 1);
    if (!z) { free(t); b->oom = 1; return; }
    memcpy(z, s, n);
    z[n] = 0;
    size_t o = 0;
    json_put_str(t, n * 6 + 3, &o, z);
    ab_put(b, t, o);
    free(t);
    free(z);
}

/* GET /v1/buckets/<b>/objects?prefix=&after=&delimiter=/&max=200&format=json|tsv
 * TSV (for the DSM tile's shell CGI): keys and prefixes URI-encoded, so
 * no field can hold a tab, newline or markup:
 *   T <truncated 0|1> <next marker, encoded or "-">
 *   P <prefix>
 *   O <size> <mtime_ms> <etag> <key> */
static char *objects_route(admin_ctx_t *a, const areq_t *rq, const char *name, const char *query,
                           size_t *rn) {
    if (strcmp(rq->method, "GET")) return err_json(405, "Method Not Allowed", "use GET", rn);
    char prefix[1025] = "", after[1025] = "", delim[8] = "/", maxs[8] = "", fmt[8] = "json";
    if (qparam(query, "prefix", prefix, sizeof(prefix)) < -1 || qparam(query, "after", after, sizeof(after)) < -1
        || qparam(query, "delimiter", delim, sizeof(delim)) < -1 || qparam(query, "max", maxs, sizeof(maxs)) < -1
        || qparam(query, "format", fmt, sizeof(fmt)) < -1)
        return err_json(400, "Bad Request", "malformed query", rn);
    if (*delim && strcmp(delim, "/")) return err_json(400, "Bad Request", "delimiter must be \"/\" or empty", rn);
    int tsv = !strcmp(fmt, "tsv");
    if (!tsv && strcmp(fmt, "json")) return err_json(400, "Bad Request", "format must be json or tsv", rn);
    long max = 200;
    if (*maxs) {
        char *end;
        max = strtol(maxs, &end, 10);
        if (*end || max < 1 || max > 1000) return err_json(400, "Bad Request", "max must be 1..1000", rn);
    }
    s3_str_t b = { name, strlen(name) };
    s3_list_opts_t lo = { { prefix, strlen(prefix) }, { after, strlen(after) },
                          { delim, strlen(delim) }, (int)max };
    s3_lister_t *l = NULL;
    if (store_list_begin(a->cfg.store, b, &lo, &l) != S3_OK)
        return err_json(500, "Internal Server Error", "cannot list the bucket", rn);
    abuf_t pre = { 0 }, obj = { 0 };
    char *last = NULL;
    size_t last_n = 0;
    int np = 0, no = 0;
    char *enc = malloc(3 * 1024 * 3 + 4);
    s3_str_t k;
    s3_obj_meta_t m;
    int isp;
    while (enc && store_list_next(l, &k, &m, &isp) == S3_OK) {
        free(last);
        last = malloc(k.n + 1);
        if (!last) break;
        memcpy(last, k.p, k.n);
        last[k.n] = 0;
        last_n = k.n;
        if (tsv) {
            if (pct_enc(k.p, k.n, enc, 3 * 1024 * 3 + 4) == (size_t)-1) continue;
            if (isp) { ab_fmt(&pre, "P\t"); ab_put(&pre, enc, strlen(enc)); ab_put(&pre, "\n", 1); }
            else {
                char et[48];
                for (int i = 0; i < 16; i++) snprintf(et + 2 * i, 3, "%02x", m.etag[i]);
                if (m.part_count) snprintf(et + 32, 16, "-%u", m.part_count);
                ab_fmt(&obj, "O\t%llu\t%llu\t%s\t", (unsigned long long)m.size,
                       (unsigned long long)m.mtime_ms, et);
                ab_put(&obj, enc, strlen(enc));
                ab_put(&obj, "\n", 1);
            }
        } else if (isp) {
            if (np++) ab_put(&pre, ",", 1);
            ab_jstr(&pre, k.p, k.n);
        } else {
            char et[48];
            for (int i = 0; i < 16; i++) snprintf(et + 2 * i, 3, "%02x", m.etag[i]);
            if (m.part_count) snprintf(et + 32, 16, "-%u", m.part_count);
            if (no++) ab_put(&obj, ",", 1);
            ab_put(&obj, "{\"key\":", 7);
            ab_jstr(&obj, k.p, k.n);
            ab_fmt(&obj, ",\"size\":%llu,\"mtime_ms\":%llu,\"etag\":\"%s\"}",
                   (unsigned long long)m.size, (unsigned long long)m.mtime_ms, et);
        }
    }
    int trunc = store_list_truncated(l);
    store_list_close(l);
    abuf_t out = { 0 };
    if (tsv) {
        ab_fmt(&out, "T\t%d\t", trunc);
        if (trunc && last && enc && pct_enc(last, last_n, enc, 3 * 1024 * 3 + 4) != (size_t)-1)
            ab_put(&out, enc, strlen(enc));
        else ab_put(&out, "-", 1);
        ab_put(&out, "\n", 1);
        if (pre.p) ab_put(&out, pre.p, pre.n);
        if (obj.p) ab_put(&out, obj.p, obj.n);
    } else {
        ab_put(&out, "{\"prefixes\":[", 13);
        if (pre.p) ab_put(&out, pre.p, pre.n);
        ab_put(&out, "],\"objects\":[", 13);
        if (obj.p) ab_put(&out, obj.p, obj.n);
        ab_fmt(&out, "],\"truncated\":%s,\"next\":", trunc ? "true" : "false");
        if (trunc && last) ab_jstr(&out, last, last_n); else ab_put(&out, "null", 4);
        ab_put(&out, "}\n", 2);
    }
    int oom = !enc || pre.oom || obj.oom || out.oom;
    free(enc); free(last); free(pre.p); free(obj.p);
    if (oom) { free(out.p); return err_json(500, "Internal Server Error", "out of memory", rn); }
    char *r = respond(200, "OK", out.p, rn);
    free(out.p);
    return r;
}

/* POST /v1/buckets/<b>/presign {"key","method","expires","host","scheme"}
 * → {"url","access_key","expires"}: a presigned URL made with a key of
 * the bucket's owner (or, failing that, of an admin). */
static char *presign_route(admin_ctx_t *a, const areq_t *rq, const char *name, size_t *rn) {
    if (strcmp(rq->method, "POST")) return err_json(405, "Method Not Allowed", "use POST", rn);
    json_t *j = json_parse(rq->body, rq->body_n, 4, 32);
    if (!j || j->type != JSON_OBJ) { json_free(j); return err_json(400, "Bad Request", "body must be a JSON object", rn); }
    /* "key_enc": the key URI-encoded (what the objects listing's TSV
     * gives), so a shell client never has to decode or JSON-escape it. */
    const json_t *jke = json_get(j, "key_enc");
    char kdec[1025];
    json_t kfake;
    if (jke && !json_get(j, "key")) {
        size_t o = 0;
        int ok = jke->type == JSON_STR && jke->str_n <= 3 * 1024;
        for (size_t i = 0; ok && i < jke->str_n; i++) {
            char c = jke->str[i];
            if (c == '%') {
                int hi = i + 2 < jke->str_n ? hexv(jke->str[i + 1]) : -1;
                int lo = i + 2 < jke->str_n ? hexv(jke->str[i + 2]) : -1;
                if (hi < 0 || lo < 0) { ok = 0; break; }
                c = (char)(hi * 16 + lo);
                i += 2;
            } else if (!(isalnum((unsigned char)c) || c == '-' || c == '.' || c == '_' || c == '~' || c == '/')) {
                ok = 0; break;
            }
            if (!c || o >= 1024) { ok = 0; break; }
            kdec[o++] = c;
        }
        kdec[o] = 0;
        memset(&kfake, 0, sizeof(kfake));
        kfake.type = ok ? JSON_STR : JSON_NULL;
        kfake.str = kdec;
        kfake.str_n = o;
    }
    const json_t *jk = jke && !json_get(j, "key") ? &kfake : json_get(j, "key"), *jm = json_get(j, "method"), *je = json_get(j, "expires"),
                 *jh = json_get(j, "host"), *js = json_get(j, "scheme");
    char key[1025], method[8] = "GET", host[300], scheme[8] = "http";
    int bad = !jk || jk->type != JSON_STR || !jk->str_n || jk->str_n > 1024 || memchr(jk->str, 0, jk->str_n)
           || !jh || jh->type != JSON_STR || !jh->str_n || jh->str_n >= sizeof(host)
           || (jm && (jm->type != JSON_STR || jm->str_n >= sizeof(method)))
           || (js && (js->type != JSON_STR || js->str_n >= sizeof(scheme)))
           || (je && je->type != JSON_NUM);
    long long expires = 3600;
    if (!bad) {
        memcpy(key, jk->str, jk->str_n); key[jk->str_n] = 0;
        memcpy(host, jh->str, jh->str_n); host[jh->str_n] = 0;
        if (jm) { memcpy(method, jm->str, jm->str_n); method[jm->str_n] = 0; }
        if (js) { memcpy(scheme, js->str, js->str_n); scheme[js->str_n] = 0; }
        if (je) {
            char t[24]; size_t l = je->str_n < 23 ? je->str_n : 23;
            memcpy(t, je->str, l); t[l] = 0;
            char *end; expires = strtoll(t, &end, 10);
            if (*end || expires < 1 || expires > 604800) bad = 1;
        }
    }
    json_free(j);
    if (bad) return err_json(400, "Bad Request", "need key (1..1024 bytes), host, and optional method, expires (1..604800 s), scheme", rn);
    for (const char *p = host; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '.' || *p == ':' || *p == '-' || *p == '[' || *p == ']'))
            return err_json(400, "Bad Request", "invalid host", rn);
    if (strcmp(scheme, "http") && strcmp(scheme, "https")) return err_json(400, "Bad Request", "scheme must be http or https", rn);
    int need_write = !strcmp(method, "PUT") || !strcmp(method, "DELETE");
    if (!need_write && strcmp(method, "GET") && strcmp(method, "HEAD"))
        return err_json(400, "Bad Request", "method must be GET, HEAD, PUT or DELETE", rn);
    char path[64 + 3 * 1024 + 4];
    int po = snprintf(path, sizeof(path), "/%s/", name);
    if (pct_enc(key, strlen(key), path + po, sizeof(path) - (size_t)po) == (size_t)-1)
        return err_json(400, "Bad Request", "key too long", rn);
    s3_bucket_meta_t bm;
    s3_str_t b = { name, strlen(name) };
    if (store_bucket_meta(a->cfg.store, b, &bm) != S3_OK) return err_json(404, "Not Found", "no such bucket", rn);
    char q[1400] = "", ak[160] = "";
    int signed_url = a->cfg.auth != NULL;
    if (signed_url) {
        sigv4_presign_req_t pr = { .method = method, .host = host, .path = path, .user = bm.owner,
                                   .expires = expires, .need_write = need_write, .allow_admin = 1 };
        int rc = sigv4_presign(a->cfg.auth, &pr, q, sizeof(q), ak, sizeof(ak));
        if (rc == SIGV4_PRESIGN_NO_KEY)
            return err_json(409, "Conflict", "no usable key: the bucket owner (or an admin) needs an enabled key "
                                 "that is not read-only for writes and does not expire first", rn);
        if (rc == SIGV4_PRESIGN_TOO_LONG) return err_json(400, "Bad Request", "expires is over --presign-max-expires", rn);
        if (rc) return err_json(500, "Internal Server Error", "cannot sign", rn);
    }
    abuf_t out = { 0 };
    ab_fmt(&out, "{\"url\":\"%s://%s", scheme, host);
    ab_put(&out, path, strlen(path));
    if (*q) { ab_put(&out, "?", 1); ab_put(&out, q, strlen(q)); }
    ab_fmt(&out, "\",\"method\":\"%s\",\"access_key\":", method);
    ab_jstr(&out, ak, strlen(ak));
    ab_fmt(&out, ",\"signed\":%s,\"expires\":%lld}\n", signed_url ? "true" : "false", expires);
    if (out.oom) { free(out.p); return err_json(500, "Internal Server Error", "out of memory", rn); }
    char ev[1400];
    snprintf(ev, sizeof(ev), "presign %s bucket %s key %.1024s by %s for %llds", method, name, path + po,
             *ak ? ak : "(no auth)", expires);
    LOG_I("admin: %s", ev);
    audit_event("admin-api", ev);
    char *r = respond(200, "OK", out.p, rn);
    free(out.p);
    return r;
}

static char *bucket_route(admin_ctx_t *a, const areq_t *rq, const char *rest,
                          size_t *rn) {
    /* rest: "<b>" | "<b>/owner" | "<b>/grants/<user>" */
    char name[64];
    const char *sl = strchr(rest, '/');
    size_t bn = sl ? (size_t)(sl - rest) : strlen(rest);
    if (bn == 0 || bn > 63) return err_json(404, "Not Found", "no such bucket", rn);
    memcpy(name, rest, bn);
    name[bn] = '\0';
    s3_str_t b = { name, bn };
    if (!store_valid_bucket_name(b) || !store_bucket_exists(a->cfg.store, b))
        return err_json(404, "Not Found", "no such bucket", rn);
    const char *sub = sl ? sl + 1 : "";
    if (!strncmp(sub, "objects", 7) && (!sub[7] || sub[7] == '?'))
        return objects_route(a, rq, name, sub[7] ? sub + 8 : "", rn);
    if (!strcmp(sub, "presign")) return presign_route(a, rq, name, rn);

    if (!*sub && !strcmp(rq->method, "GET")) {
        char out[8192];
        size_t o = 0;
        if (!bucket_json(a, name, 1, out, sizeof(out) - 2, &o))
            return err_json(404, "Not Found", "no such bucket", rn);
        out[o++] = '\n';
        out[o] = '\0';
        return respond(200, "OK", out, rn);
    }
    if (!strcmp(sub, "owner") && !strcmp(rq->method, "PUT")) {
        json_t *j = json_parse(rq->body, rq->body_n, 4, 64);
        const char *ow = json_str(json_get(j, "owner"));
        char owner[129] = "";
        if (ow) snprintf(owner, sizeof(owner), "%s", ow);
        json_free(j);
        if (!s3_valid_ident_strict(owner))
            return err_json(400, "Bad Request", "owner must match [A-Za-z0-9._@-]{1,128}", rn);
        if (store_bucket_set_owner(a->cfg.store, b, owner) != S3_OK)
            return err_json(500, "Internal Server Error", "cannot set owner", rn);
        LOG_I("admin: bucket %s owner set to %s", name, owner);
        { char ev[1400]; snprintf(ev, sizeof(ev), "bucket %s owner %s", name, owner); audit_event("admin-api", ev); }
        return respond(200, "OK", "{\"ok\":true}\n", rn);
    }
    if (!strcmp(sub, "quota")) return quota_route(a, rq, b, NULL, rn);
    if (!strcmp(sub, "replication") || !strncmp(sub, "replication/", 12)) {
        int st = 500;
        char *body = repl_admin(a->cfg.repl, rq->method, name, sub[11] ? sub + 12 : "",
                                rq->body, rq->body_n, &st);
        if (!body) return err_json(500, "Internal Server Error", "out of memory", rn);
        const char *reason = st == 200 ? "OK" : st == 202 ? "Accepted" : st == 400 ? "Bad Request"
                           : st == 404 ? "Not Found" : st == 405 ? "Method Not Allowed"
                           : st == 409 ? "Conflict" : st == 501 ? "Not Implemented" : "Internal Server Error";
        char *resp = respond(st, reason, body, rn);
        free(body);
        return resp;
    }
    if (!strcmp(sub, "notification") || !strncmp(sub, "notification/", 13)) {
        int st = 500;
        char *body = notify_admin(a->cfg.notify, rq->method, name, sub[12] ? sub + 13 : "",
                                  rq->body, rq->body_n, &st);
        if (!body) return err_json(500, "Internal Server Error", "out of memory", rn);
        const char *reason = st == 200 ? "OK" : st == 202 ? "Accepted" : st == 400 ? "Bad Request"
                           : st == 404 ? "Not Found" : st == 405 ? "Method Not Allowed"
                           : st == 409 ? "Conflict" : st == 501 ? "Not Implemented" : "Internal Server Error";
        char *resp = respond(st, reason, body, rn);
        free(body);
        return resp;
    }
    if (!strncmp(sub, "grants/", 7)) {
        const char *user = sub + 7;
        if (!s3_valid_ident_strict(user))
            return err_json(400, "Bad Request", "user must match [A-Za-z0-9._@-]{1,128}", rn);
        int perms = 0;
        if (!strcmp(rq->method, "PUT")) {
            json_t *j = json_parse(rq->body, rq->body_n, 4, 64);
            const char *p = json_str(json_get(j, "perms"));
            perms = p ? store_grant_parse_perms(p, strlen(p)) : -1;
            json_free(j);
            if (perms <= 0)
                return err_json(400, "Bad Request", "perms must be a non-empty subset of \"rwo\"", rn);
        } else if (strcmp(rq->method, "DELETE") != 0) {
            return err_json(405, "Method Not Allowed", "use PUT or DELETE", rn);
        }
        if (store_bucket_grant_set(a->cfg.store, b, user, perms) != S3_OK)
            return err_json(500, "Internal Server Error", "cannot write grants", rn);
        LOG_I("admin: bucket %s grant %s = %d", name, user, perms);
        { char ev[1400]; snprintf(ev, sizeof(ev), "bucket %s grant %s=%d", name, user, perms); audit_event("admin-api", ev); }
        return respond(200, "OK", "{\"ok\":true}\n", rn);
    }
    return err_json(404, "Not Found", "no such endpoint", rn);
}

/* ---- Entry point --------------------------------------------------------- */

char *admin_handle_v1(admin_ctx_t *a, const char *req, size_t n, int via_uds,
                      size_t *rn) {
    areq_t rq;
    if (parse_req(req, n, &rq) < 0)
        return err_json(400, "Bad Request", "malformed request", rn);
    if (!via_uds) {
        /* S10: browsers attach Origin; a page on any site could otherwise
         * reach loopback via DNS rebinding. */
        if (rq.origin) return err_json(403, "Forbidden", "cross-origin requests refused", rn);
        if (!host_is_loopback(&rq)) return err_json(403, "Forbidden", "Host must be loopback", rn);
        if (!a->token) return err_json(403, "Forbidden", "admin API needs --admin-token-file or --admin-socket", rn);
        time_t now = time(NULL);
        if (now < a->blocked_until)
            return err_json(429, "Too Many Requests", "too many failed attempts", rn);
        int ok = rq.auth && rq.auth_n == 7 + a->token_n
                 && strncmp(rq.auth, "Bearer ", 7) == 0
                 && CRYPTO_memcmp(rq.auth + 7, a->token, a->token_n) == 0;
        if (!ok) {
            if (a->fails < 5) a->fails++;
            a->blocked_until = now + (1 << a->fails) / 2;
            LOG_W("admin: rejected request with bad or missing token");
            return err_json(401, "Unauthorized", "bad or missing bearer token", rn);
        }
        a->fails = 0;
    }

    const char *p = rq.path;
    if (!strcmp(p, "/v1/keys") || !strncmp(p, "/v1/keys/", 9)) {
        if (!a->cfg.cred_file)
            return err_json(501, "Not Implemented", "key management needs --credentials-file", rn);
        if (!strcmp(p, "/v1/keys")) {
            if (!strcmp(rq.method, "GET")) return keys_list(a, rn);
            if (!strcmp(rq.method, "POST")) return keys_create(a, &rq, rn);
            return err_json(405, "Method Not Allowed", "use GET or POST", rn);
        }
        const char *ak = p + 9;
        if (!s3_valid_ident_strict(ak)) return err_json(404, "Not Found", "no such access key", rn);
        if (!strcmp(rq.method, "PATCH")) return keys_patch(a, ak, &rq, rn);
        if (strcmp(rq.method, "DELETE") != 0)
            return err_json(405, "Method Not Allowed", "use PATCH or DELETE", rn);
        return keys_delete(a, ak, rn);
    }
    if (!strcmp(p, "/v1/buckets")) {
        if (strcmp(rq.method, "GET") != 0) return err_json(405, "Method Not Allowed", "use GET", rn);
        return buckets_list(a, rn);
    }
    if (!strncmp(p, "/v1/buckets/", 12)) return bucket_route(a, &rq, p + 12, rn);
    if (!strcmp(p, "/v1/scrub")) {
        if (!a->cfg.scrub) return err_json(501, "Not Implemented", "scrub not configured", rn);
        if (!strcmp(rq.method, "POST")) {
            int r = scrub_request(a->cfg.scrub);
            if (r < 0) return err_json(503, "Service Unavailable", "scrub needs --io-threads > 0", rn);
            audit_event("admin-api", r == 0 ? "scrub started" : "scrub start requested (already running)");
        } else if (strcmp(rq.method, "GET") != 0) {
            return err_json(405, "Method Not Allowed", "use GET or POST", rn);
        }
        char out[1024];
        size_t o = scrub_status_json(a->cfg.scrub, out, sizeof(out) - 2);
        out[o++] = '\n';
        out[o] = '\0';
        return respond(200, "OK", out, rn);
    }
    if (!strncmp(p, "/v1/users/", 10)) {
        /* /v1/users/<u>/quota */
        const char *u = p + 10, *sl = strchr(u, '/');
        char user[129];
        size_t un = sl ? (size_t)(sl - u) : 0;
        if (!sl || strcmp(sl, "/quota") || un == 0 || un >= sizeof(user))
            return err_json(404, "Not Found", "no such endpoint", rn);
        memcpy(user, u, un);
        user[un] = '\0';
        if (!s3_valid_ident_strict(user))
            return err_json(400, "Bad Request", "user must match [A-Za-z0-9._@-]{1,128}", rn);
        return quota_route(a, &rq, S3_STR_NULL, user, rn);
    }
    return err_json(404, "Not Found", "no such endpoint", rn);
}
