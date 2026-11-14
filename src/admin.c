/* src/admin.c — admin HTTP API (item 11). See include/admin.h. */

#include "admin.h"
#include "audit.h"
#include "json.h"
#include "log.h"
#include "store.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <errno.h>
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

typedef struct { char ak[129]; char user[129]; char *line; } cred_line_t;

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

/* Fields of an "ak:sk[:user]" line (comments/blank → 0). */
static int cred_fields(const char *line, size_t n, char ak[129], char user[129]) {
    while (n && (line[n-1] == ' ' || line[n-1] == '\t' || line[n-1] == '\r')) n--;
    if (n == 0 || line[0] == '#') return 0;
    const char *c1 = memchr(line, ':', n);
    if (!c1 || c1 == line || (size_t)(c1 - line) > 128) return -1;
    memcpy(ak, line, (size_t)(c1 - line));
    ak[c1 - line] = '\0';
    const char *rest = c1 + 1;
    size_t rn = n - (size_t)(rest - line);
    const char *c2 = memchr(rest, ':', rn);
    if (c2 && (size_t)(rest + rn - c2 - 1) <= 128 && rest + rn > c2 + 1) {
        memcpy(user, c2 + 1, (size_t)(rest + rn - c2 - 1));
        user[rest + rn - c2 - 1] = '\0';
    } else {
        snprintf(user, 129, "%s", ak);
    }
    return 1;
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
    size_t cap = n * 2 + 64, o = 0;
    char *out = malloc(cap);
    if (!out) { free(f); return NULL; }
    o += (size_t)snprintf(out, cap, "{\"keys\":[");
    int first = 1;
    for (char *l = f; *l; ) {
        char *e = strchr(l, '\n');
        size_t ln = e ? (size_t)(e - l) : strlen(l);
        char ak[129], user[129];
        if (cred_fields(l, ln, ak, user) == 1) {
            if (!first) out[o++] = ',';
            first = 0;
            o += (size_t)snprintf(out + o, cap - o, "{\"access_key\":");
            json_put_str(out, cap, &o, ak);
            o += (size_t)snprintf(out + o, cap - o, ",\"user\":");
            json_put_str(out, cap, &o, user);
            out[o++] = '}';
        }
        l = e ? e + 1 : l + ln;
    }
    snprintf(out + o, cap - o, "]}\n");
    free(f);
    char *r = respond(200, "OK", out, rn);
    free(out);
    return r;
}

static char *keys_create(admin_ctx_t *a, const areq_t *rq, size_t *rn) {
    char user[129] = "";
    if (rq->body_n) {
        json_t *j = json_parse(rq->body, rq->body_n, 4, 64);
        if (!j || j->type != JSON_OBJ) { json_free(j); return err_json(400, "Bad Request", "invalid JSON", rn); }
        const char *u = json_str(json_get(j, "user"));
        if (json_get(j, "user") && !u) { json_free(j); return err_json(400, "Bad Request", "user must be a string", rn); }
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
    int m = snprintf(nf, cap, "%s%s%s:%s:%s\n", f, (n && f[n-1] != '\n') ? "\n" : "",
                     ak, sk, user);
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
        snprintf(b + o, sizeof(b) - o, "}\n");
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
        char ak[129], user[129];
        int r = cred_fields(l, e ? ln - 1 : ln, ak, user);
        if (r == 1 && strcmp(ak, ak_del) == 0) {
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
    if (*o + 2 < cap) out[(*o)++] = '}';
    out[*o] = '\0';
    return out;
}

static char *buckets_list(admin_ctx_t *a, size_t *rn) {
    s3_bucket_info_t *bl = NULL;
    size_t nb = 0;
    if (store_list_buckets(a->cfg.store, &bl, &nb) != S3_OK)
        return err_json(500, "Internal Server Error", "cannot list buckets", rn);
    size_t cap = 512 + nb * 512, o = 0;
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
        if (strcmp(rq.method, "DELETE") != 0)
            return err_json(405, "Method Not Allowed", "use DELETE", rn);
        const char *ak = p + 9;
        if (!s3_valid_ident_strict(ak)) return err_json(404, "Not Found", "no such access key", rn);
        return keys_delete(a, ak, rn);
    }
    if (!strcmp(p, "/v1/buckets")) {
        if (strcmp(rq.method, "GET") != 0) return err_json(405, "Method Not Allowed", "use GET", rn);
        return buckets_list(a, rn);
    }
    if (!strncmp(p, "/v1/buckets/", 12)) return bucket_route(a, &rq, p + 12, rn);
    return err_json(404, "Not Found", "no such endpoint", rn);
}
