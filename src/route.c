/* src/route.c — request dispatcher and per-method handlers
 *
 * Path shape determines handler family:
 *   /                                 → service ops (list buckets — TODO)
 *   /<bucket>                         → bucket ops (create/delete/list)
 *   /<bucket>/<key...>                → object ops (PUT/GET/HEAD/DELETE)
 *
 * Query string matters for some bucket ops:
 *   GET /<bucket>?location            → location subresource (TODO)
 *   GET /<bucket>?list-type=2&...     → ListObjectsV2 (treated as list)
 *   GET /<bucket>?prefix=&delimiter=  → ListObjectsV1
 *
 * For simplicity right now we treat any GET on /<bucket> (with or
 * without query) as a list. Full subresource handling lands in 3.1.
 */

#include "route.h"
#include "action.h"
#include "checksum.h"
#include "cors.h"
#include "lifecycle.h"
#include "website.h"
#include "policy.h"
#include "objlock.h"
#include "xml_parser.h"
#include "conn.h"
#include "iopool.h"
#include "log.h"
#include "response.h"
#include "store.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <time.h>
#include <unistd.h>

/* ===================================================================== */
/* URL parsing                                                            */
/* ===================================================================== */

/* Decode a percent-encoded substring in place. Returns the new length.
 * Stops at NUL or end of `n`. Treats `+` as literal `+` (S3 keys can
 * contain '+', and '+' meaning space is form-encoding, not URI). */
static size_t pct_decode(char *s, size_t n) {
    size_t r = 0, w = 0;
    while (r < n) {
        if (s[r] == '%' && r + 2 < n) {
            int hi = -1, lo = -1;
            char c1 = s[r+1], c2 = s[r+2];
            if      (c1 >= '0' && c1 <= '9') hi = c1 - '0';
            else if (c1 >= 'a' && c1 <= 'f') hi = c1 - 'a' + 10;
            else if (c1 >= 'A' && c1 <= 'F') hi = c1 - 'A' + 10;
            if      (c2 >= '0' && c2 <= '9') lo = c2 - '0';
            else if (c2 >= 'a' && c2 <= 'f') lo = c2 - 'a' + 10;
            else if (c2 >= 'A' && c2 <= 'F') lo = c2 - 'A' + 10;
            if (hi >= 0 && lo >= 0) {
                s[w++] = (char)((hi << 4) | lo);
                r += 3;
                continue;
            }
        }
        s[w++] = s[r++];
    }
    return w;
}

/* Parse the request path into bucket and key spans.
 *
 * Path always begins with '/'. Forms:
 *   "/"                    → bucket = empty, key = empty (service)
 *   "/bucket"              → bucket = "bucket", key = empty
 *   "/bucket/"             → bucket = "bucket", key = empty
 *   "/bucket/key/with/slashes" → bucket = "bucket", key = "key/with/slashes"
 *
 * Both spans are decoded in place into the caller-provided scratch
 * buffer (which must have room for path.n bytes). The returned spans
 * point into the scratch buffer. */
static int parse_path(s3_str_t path, char *scratch, size_t cap,
                      s3_str_t *bucket, s3_str_t *key) {
    if (path.n == 0 || path.p[0] != '/') return -1;
    if (path.n > cap) return -1;
    memcpy(scratch, path.p, path.n);

    /* Skip leading '/' */
    char *p   = scratch + 1;
    size_t pn = path.n - 1;

    /* Find first '/' separating bucket from key */
    char *slash = memchr(p, '/', pn);
    if (!slash) {
        /* "/bucket" — bucket only */
        size_t bn = pct_decode(p, pn);
        *bucket = (s3_str_t){ p, bn };
        *key    = S3_STR_NULL;
        return 0;
    }
    size_t bn = (size_t)(slash - p);
    size_t kn = pn - bn - 1;
    bn = pct_decode(p, bn);
    if (kn > 0) {
        kn = pct_decode(slash + 1, kn);
        *key = (s3_str_t){ slash + 1, kn };
    } else {
        *key = S3_STR_NULL;
    }
    *bucket = (s3_str_t){ p, bn };
    return 0;
}

/* Query helpers over the parsed, decoded parameters (conn_parse_query). */
static int q_has(const conn_t *c, const char *name) {
    return conn_query_get(c, name) != NULL;
}

/* Decoded value of `name`, or S3_STR_NULL. */
static s3_str_t q_val(const conn_t *c, const char *name) {
    const conn_qparam_t *p = conn_query_get(c, name);
    return p ? p->v : S3_STR_NULL;
}

/* Find a header by lowercase name. */
static const s3_str_t *hdr_get(const conn_t *c, const char *lc_name) {
    for (size_t i = 0; i < c->req.n_headers; i++) {
        if (s3_str_eq_lit(c->req.headers[i].k, lc_name)) {
            return &c->req.headers[i].v;
        }
    }
    return NULL;
}

static int bucket_versioning_state(conn_t *c, s3_str_t bucket) {
    s3_bucket_meta_t m;
    return store_bucket_meta(c->store, bucket, &m) == S3_OK ? m.versioning : 0;
}

/* Queue x-amz-checksum-<algo> (+ type) response headers for m. */
static void add_checksum_headers(conn_t *c, const s3_obj_meta_t *m) {
    if (!m->cksum_algo) return;
    char v[64];
    rsp_format_checksum(m, v);
    conn_add_header(c, cksum_header_name(m->cksum_algo), v);
    conn_add_header(c, "x-amz-checksum-type",
                    m->cksum_type == S3_CKSUM_TYPE_COMPOSITE ? "COMPOSITE"
                                                             : "FULL_OBJECT");
}

/* Echo the request's verified additional checksum (PUT, UploadPart). */
static void echo_request_checksum(conn_t *c) {
    if (!c->cksum_algo) return;
    s3_obj_meta_t m;
    memset(&m, 0, sizeof(m));
    m.cksum_algo = (uint8_t)c->cksum_algo;
    memcpy(m.cksum, c->cksum_expect, sizeof(m.cksum));
    char v[64];
    rsp_format_checksum(&m, v);
    conn_add_header(c, cksum_header_name(m.cksum_algo), v);
}

static int ieq_lit(s3_str_t a, const char *b) {
    size_t n = strlen(b);
    if (a.n != n) return 0;
    for (size_t i = 0; i < n; i++) {
        char x = a.p[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        char y = b[i];
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return 0;
    }
    return 1;
}

/* x-amz-version-id for a versioned response. vid all-zero: "null", but
 * only if the bucket has (ever had) versioning. */
static void add_version_header(conn_t *c, s3_str_t bucket, const uint8_t vid[16]) {
    char vs[33];
    store_vid_format(vid, vs);
    if (!strcmp(vs, "null") && bucket_versioning_state(c, bucket) == S3_VERSIONING_UNSET)
        return;
    conn_add_header(c, "x-amz-version-id", vs);
}

/* ?versionId → *vid (returns 1), absent → 0, malformed → -1 (S5:
 * validated before any path is built). */
static int version_param(const conn_t *c, uint8_t vid[16]) {
    const conn_qparam_t *p = conn_query_get(c, "versionId");
    if (!p) return 0;
    return store_vid_parse(p->v, vid) == 0 ? 1 : -1;
}

/* Method comparison. */
static int method_is(const conn_t *c, const char *m) {
    return s3_str_eq_lit(c->req.method, m);
}

/* ===================================================================== */
/* Per-request scratch                                                   */
/* ===================================================================== */

/* Per-request bump arena lives on conn_t. Reset at the start of each
 * request via scratch_reset(c). Used to hold decoded path/query bytes. */

static char *scratch_alloc(conn_t *c, size_t n) {
    if (c->req_scratch_used + n > sizeof(c->req_scratch)) return NULL;
    char *p = c->req_scratch + c->req_scratch_used;
    c->req_scratch_used += n;
    return p;
}

static void scratch_reset(conn_t *c) { c->req_scratch_used = 0; }

/* ===================================================================== */
/* Service-level (PATH = "/")                                            */
/* ===================================================================== */

/* ===================================================================== */
/* Bucket ownership                                                       */
/* ===================================================================== */
/*
 * With auth configured, every bucket belongs to the identity that
 * created it (the credential's user, or its access key), and only that
 * identity — or an --admin user — may see or act on it or its objects.
 * Ownerless buckets (from before isolation, or created in no-auth mode)
 * are admin-only until --legacy-owner assigns them. Anonymous requests
 * (auth configured without --require-auth) own nothing and get 403.
 * Without auth there are no identities and no checks: open mode is
 * unchanged.
 */

/* Authorization decision for `act` on bucket/key (key may be empty for
 * bucket-level actions). S3_OK = allowed. S3_ERR_NO_SUCH_BUCKET is passed
 * through for the handler to report its own way; anything else is a
 * denial. Unclassified actions (no table entry) are always denied.
 *
 * Evaluation order (later items plug in here):
 *   policy actions                        → owner/admin only (lockout rule)
 *   bucket policy explicit Deny           → deny    (item 9)
 *   owner or admin                        → allow
 *   per-user grant covering the action    → allow   (item 3)
 *   bucket policy Allow                   → allow   (anonymous via "*")
 *   otherwise                             → deny
 */
static int is_policy_action(s3_action_t a) {
    return a == ACT_GET_BUCKET_POLICY || a == ACT_PUT_BUCKET_POLICY
        || a == ACT_DELETE_BUCKET_POLICY;
}

s3_err_t authz(conn_t *c, s3_str_t bucket, s3_str_t key, s3_action_t act) {
    const s3_action_info_t *ai = action_info(act);
    if (!ai) return S3_ERR_ACCESS_DENIED;          /* default deny */
    if (!c->auth) return S3_OK;                    /* open mode */
    int anon = !c->id.user[0];
    if (act == ACT_LIST_BUCKETS || act == ACT_CREATE_BUCKET)
        return anon ? S3_ERR_ACCESS_DENIED : S3_OK;
    s3_bucket_meta_t m;
    s3_err_t e = store_bucket_meta(c->store, bucket, &m);
    if (e != S3_OK) {
        /* Anonymous callers learn nothing about which buckets exist. */
        return anon ? S3_ERR_ACCESS_DENIED : e;
    }
    int owner = !anon && (c->id.is_admin
                          || (m.owner[0] && strcmp(m.owner, c->id.user) == 0));

    /* Policy lockout rule (S6): the owner and admins can always read,
     * replace or delete the policy, whatever it says; nobody else can. */
    if (is_policy_action(act)) return owner ? S3_OK : S3_ERR_ACCESS_DENIED;

    /* Bucket policy: an explicit Deny wins over everything, owner and
     * admin included (admins can still edit the policy). */
    policy_effect_t pe = POLICY_NONE;
    store_cfg_ref_t *pref = store_sidecar_get(c->store, bucket, "policy.json",
                                              POLICY_MAX_BYTES, policy_parse_cb,
                                              policy_free_cb);
    if (pref) {
        const conn_qparam_t *qp = act == ACT_LIST_OBJECTS ? conn_query_get(c, "prefix") : NULL;
        policy_req_t pr = {
            .user = c->id.user, .action = ai->iam_name, .bucket = bucket,
            .key = ai->bucket_level ? S3_STR_NULL : key,
            .source_ip = c->client_ip[0] ? c->client_ip : NULL,
            .secure = c->secure,
            .prefix = qp ? qp->v : S3_STR_NULL, .has_prefix = qp != NULL,
        };
        pe = policy_eval(store_cfg_obj(pref), &pr);
        store_sidecar_put(c->store, pref);
    }
    if (pe == POLICY_DENY) return S3_ERR_POLICY_DENIED;
    if (owner) return S3_OK;
    /* Grants: r → list/get, w → put/delete/MPU, o → config. Bucket
     * delete and create are never grantable. */
    if (!anon && act != ACT_DELETE_BUCKET) {
        int g = store_bucket_grant_perms(c->store, bucket, c->id.user);
        int need = ai->perm == PERM_R ? S3_GRANT_R
                 : ai->perm == PERM_W ? S3_GRANT_W : S3_GRANT_O;
        if (g & need) return S3_OK;
    }
    /* A policy Allow (including Principal "*" for anonymous callers) —
     * never for bucket deletion. */
    if (pe == POLICY_ALLOW && act != ACT_DELETE_BUCKET) return S3_OK;
    return S3_ERR_ACCESS_DENIED;
}

static int handle_service(conn_t *c) {
    /* Only GET is meaningful; everything else is method-not-allowed. */
    if (!method_is(c, "GET")) {
        return rsp_build_s3_error(c, S3_ERR_METHOD_NOT_ALLOWED,
                                  S3_STR_LIT("/"), NULL);
    }
    /* GET / → ListAllMyBuckets */
    s3_bucket_info_t *buckets = NULL;
    size_t n_buckets = 0;
    if (c->auth && !c->id.user[0]) {
        return rsp_build_s3_error(c, S3_ERR_ACCESS_DENIED,
                                  S3_STR_LIT("/"), NULL);
    }
    s3_err_t e = store_list_buckets(c->store, &buckets, &n_buckets);
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, S3_STR_LIT("/"), NULL);
    }
    /* Each user sees their own buckets and those they hold any grant
     * on; admins see all. */
    if (c->auth && !c->id.is_admin) {
        size_t kept = 0;
        for (size_t i = 0; i < n_buckets; i++) {
            s3_str_t bn = { buckets[i].name, strlen(buckets[i].name) };
            if ((buckets[i].owner[0]
                 && strcmp(buckets[i].owner, c->id.user) == 0)
                || store_bucket_grant_perms(c->store, bn, c->id.user)) {
                buckets[kept++] = buckets[i];
            } else {
                free(buckets[i].name);
            }
        }
        n_buckets = kept;
    }
    int rc = rsp_build_list_all_my_buckets(c, buckets, n_buckets);
    store_buckets_free(buckets, n_buckets);
    return rc;
}

/* ===================================================================== */
/* Bulk-delete handler (POST /<bucket>?delete)                            */
/* ===================================================================== */

#define BULK_DELETE_BODY_CAP (1024 * 1024)

static int handle_bulk_delete_begin(conn_t *c, s3_str_t bucket) {
    if (!store_bucket_exists(c->store, bucket)) {
        return rsp_build_s3_error(c, S3_ERR_NO_SUCH_BUCKET, c->req.path, NULL);
    }
    free(c->req_body_buf);
    c->req_body_buf = malloc(BULK_DELETE_BODY_CAP);
    if (!c->req_body_buf) {
        return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    }
    c->req_body_len = 0;
    c->req_body_cap = BULK_DELETE_BODY_CAP;
    c->delete_pending = 1;
    c->delete_bucket  = bucket;
    return 0;
}

/* Parse <Delete>...<Object><Key>k</Key></Object>...</Delete>.
 * Fills keys_out with a heap-allocated array of NUL-terminated strings.
 * Sets quiet_out to 1 if <Quiet>true</Quiet> is present. Returns 0 ok,
 * -1 on OOM. Caller frees each key and the array. */
static int parse_delete_body(const char *body, size_t body_len,
                              char ***keys_out, char ***vids_out,
                              size_t *n_out, int *quiet_out) {
    *quiet_out = 0;
    static const char qt_open[]  = "<Quiet>";
    static const char qt_close[] = "</Quiet>";
    const char *qp = memmem(body, body_len, qt_open, sizeof(qt_open) - 1);
    if (qp) {
        size_t qv0 = (size_t)(qp - body) + sizeof(qt_open) - 1;
        const char *qq = memmem(body + qv0, body_len - qv0,
                                qt_close, sizeof(qt_close) - 1);
        if (qq && (size_t)(qq - body) - qv0 == 4
            && memcmp(body + qv0, "true", 4) == 0) {
            *quiet_out = 1;
        }
    }

    static const char obj_open[]  = "<Object>";
    static const char obj_close[] = "</Object>";
    static const char key_open[]  = "<Key>";
    static const char key_close[] = "</Key>";

    char **keys = NULL, **vids = NULL;
    size_t n_keys = 0, cap = 0;
    size_t pos = 0;

    while (pos < body_len) {
        const char *op = memmem(body + pos, body_len - pos,
                                obj_open, sizeof(obj_open) - 1);
        if (!op) break;
        size_t obj_start = (size_t)(op - body) + sizeof(obj_open) - 1;
        const char *oq = memmem(body + obj_start, body_len - obj_start,
                                obj_close, sizeof(obj_close) - 1);
        if (!oq) break;
        size_t obj_end = (size_t)(oq - body);

        const char *kp = memmem(body + obj_start, obj_end - obj_start,
                                key_open, sizeof(key_open) - 1);
        if (kp) {
            size_t kv0 = (size_t)(kp - body) + sizeof(key_open) - 1;
            const char *kq = memmem(body + kv0, obj_end - kv0,
                                    key_close, sizeof(key_close) - 1);
            if (kq) {
                size_t klen = (size_t)(kq - body) - kv0;
                char *k = malloc(klen + 1);
                if (!k) goto oom;
                memcpy(k, body + kv0, klen);
                k[klen] = '\0';
                if (n_keys == cap) {
                    size_t nc = cap ? cap * 2 : 16;
                    char **nk = realloc(keys, nc * sizeof(*nk));
                    if (!nk) { free(k); goto oom; }
                    keys = nk;
                    char **nv = realloc(vids, nc * sizeof(*nv));
                    if (!nv) { free(k); goto oom; }
                    vids = nv;
                    cap = nc;
                }
                char *vid = NULL;
                static const char vo[] = "<VersionId>", vc[] = "</VersionId>";
                const char *vp = memmem(body + obj_start, obj_end - obj_start, vo, sizeof(vo) - 1);
                if (vp) {
                    size_t v0 = (size_t)(vp - body) + sizeof(vo) - 1;
                    const char *vq = memmem(body + v0, obj_end - v0, vc, sizeof(vc) - 1);
                    if (vq) vid = strndup(body + v0, (size_t)(vq - body) - v0);
                }
                vids[n_keys] = vid;
                keys[n_keys++] = k;
            }
        }
        pos = obj_end + sizeof(obj_close) - 1;
    }

    *keys_out = keys;
    *vids_out = vids;
    *n_out    = n_keys;
    return 0;
oom:
    for (size_t i = 0; i < n_keys; i++) { free(keys[i]); if (vids) free(vids[i]); }
    free(keys);
    free(vids);
    return -1;
}

static int handle_bulk_delete_finish(conn_t *c, s3_str_t bucket) {
    if (c->req_body_len > c->req_body_cap) {
        return rsp_build_s3_error(c, S3_ERR_ENTITY_TOO_LARGE, c->req.path, NULL);
    }
    char **keys = NULL, **vids = NULL;
    size_t n_keys = 0;
    int quiet = 0;
    if (parse_delete_body(c->req_body_buf, c->req_body_len,
                          &keys, &vids, &n_keys, &quiet) < 0) {
        return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    }
    if (n_keys == 0) {
        return rsp_build_s3_error(c, S3_ERR_MALFORMED_XML, c->req.path, NULL);
    }
    const char **deleted_keys = malloc(n_keys * sizeof(*deleted_keys));
    const char **error_keys   = malloc(n_keys * sizeof(*error_keys));
    size_t n_deleted = 0, n_errors = 0;
    if (!deleted_keys || !error_keys) {
        for (size_t i = 0; i < n_keys; i++) { free(keys[i]); free(vids[i]); }
        free(keys); free(vids); free(deleted_keys); free(error_keys);
        return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    }
    for (size_t i = 0; i < n_keys; i++) {
        s3_str_t k = { keys[i], strlen(keys[i]) };
        /* Each key is its own delete: it needs w on the bucket (checked at
         * dispatch) and, with versions, a valid id (S5). */
        uint8_t vid[16];
        s3_err_t e;
        if (vids[i] && store_vid_parse((s3_str_t){ vids[i], strlen(vids[i]) }, vid) < 0)
            e = S3_ERR_INVALID_ARGUMENT;
        else if ((e = authz(c, bucket, k, ACT_DELETE_OBJECT)) != S3_OK)
            ;   /* per-key policy decision (prefix-scoped Deny etc.) */
        else
            e = store_delete_ex(c->store, bucket, k, vids[i] ? vid : NULL, NULL);
        if (e == S3_OK) {
            if (!quiet) deleted_keys[n_deleted++] = keys[i];
        } else {
            error_keys[n_errors++] = keys[i];
        }
    }
    int rc = rsp_build_delete_objects(c, deleted_keys, n_deleted,
                                       error_keys, n_errors);
    for (size_t i = 0; i < n_keys; i++) { free(keys[i]); free(vids[i]); }
    free(keys); free(vids); free(deleted_keys); free(error_keys);
    return rc;
}

/* ===================================================================== */
/* Bucket-level (PATH = "/bucket" or "/bucket/")                          */
/* ===================================================================== */

/* ===================================================================== */
/* Bucket configuration subresources (?cors, ?lifecycle, ?website, ...)   */
/* ===================================================================== */

#define CFG_BODY_CAP (64 * 1024)

typedef struct {
    s3_action_t get, put, del;
    const char *sidecar;
    s3_err_t    missing;
    const char *content_type;
} cfg_kind_t;

static const cfg_kind_t CFG_KINDS[] = {
    { ACT_GET_BUCKET_CORS, ACT_PUT_BUCKET_CORS, ACT_DELETE_BUCKET_CORS,
      "cors.xml", S3_ERR_NO_SUCH_CORS, "application/xml" },
    { ACT_GET_BUCKET_LIFECYCLE, ACT_PUT_BUCKET_LIFECYCLE, ACT_DELETE_BUCKET_LIFECYCLE,
      "lifecycle.xml", S3_ERR_NO_SUCH_LIFECYCLE, "application/xml" },
    { ACT_GET_BUCKET_WEBSITE, ACT_PUT_BUCKET_WEBSITE, ACT_DELETE_BUCKET_WEBSITE,
      "website.xml", S3_ERR_NO_SUCH_WEBSITE, "application/xml" },
    { ACT_GET_BUCKET_POLICY, ACT_PUT_BUCKET_POLICY, ACT_DELETE_BUCKET_POLICY,
      "policy.json", S3_ERR_NO_SUCH_POLICY, "application/json" },
    { ACT_GET_BUCKET_OBJECT_LOCK, ACT_PUT_BUCKET_OBJECT_LOCK, ACT_NONE,
      "object-lock.xml", S3_ERR_NO_SUCH_OBJECT_LOCK, "application/xml" },
};

static const cfg_kind_t *cfg_kind_for(s3_action_t act) {
    for (size_t i = 0; i < sizeof(CFG_KINDS) / sizeof(*CFG_KINDS); i++)
        if (CFG_KINDS[i].get == act || CFG_KINDS[i].put == act
            || (CFG_KINDS[i].del != ACT_NONE && CFG_KINDS[i].del == act))
            return &CFG_KINDS[i];
    return NULL;
}

/* Validate a config document before it is stored. */
static s3_err_t cfg_validate(conn_t *c, s3_action_t act, const char *body,
                             size_t n) {
    switch (act) {
    case ACT_PUT_BUCKET_LIFECYCLE: {
        s3_err_t e;
        lc_config_t *lc = lc_parse(body, n, &e);
        if (!lc) return e;
        /* S9: an Expiration/Date already in the past deletes everything
         * the rule matches at the next sweep. Demand an explicit opt-in. */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        int imm = lc_has_immediate_rule(lc, (int64_t)ts.tv_sec * 1000);
        lc_free(lc);
        const s3_str_t *ok = hdr_get(c, "x-fs3-confirm-immediate-expiry");
        if (imm && !(ok && s3_str_eq_lit(*ok, "true"))) {
            LOG_W("refusing lifecycle rule with a past Expiration/Date on "
                  S3_STR_FMT " (send x-fs3-confirm-immediate-expiry: true)",
                  S3_STR_ARG(c->cfg_bucket));
            return S3_ERR_INVALID_ARGUMENT;
        }
        LOG_W("lifecycle configuration installed on " S3_STR_FMT
              "%s: matching objects will be deleted by the sweeper",
              S3_STR_ARG(c->cfg_bucket), imm ? " (immediate expiry confirmed)" : "");
        return S3_OK;
    }
    case ACT_PUT_BUCKET_OBJECT_LOCK: {
        if (!store_bucket_object_lock(c->store, c->cfg_bucket)) return S3_ERR_INVALID_REQUEST;
        s3_err_t e;
        olock_cfg_t *oc = olock_cfg_parse(body, n, &e);
        if (!oc) return e;
        uint64_t span = (uint64_t)oc->days * 86400000ULL;
        free(oc);
        if (c->max_retention_ms && span > c->max_retention_ms) return S3_ERR_INVALID_ARGUMENT;
        return S3_OK;
    }
    case ACT_PUT_BUCKET_POLICY: {
        policy_check_t chk;
        policy_t *pol = policy_compile(body, n, c->cfg_bucket, &chk);
        if (!pol) {
            LOG_D("policy rejected: %s", chk.msg ? chk.msg : "?");
            return S3_ERR_MALFORMED_POLICY;
        }
        policy_free(pol);
        /* S6: public grants need --allow-public, public writes need
         * --allow-public-write as well. */
        if ((chk.public_read && !c->allow_public)
            || (chk.public_write && !c->allow_public_write)) {
            LOG_W("refusing public bucket policy on " S3_STR_FMT
                  " (--allow-public%s not set)", S3_STR_ARG(c->cfg_bucket),
                  chk.public_write ? "-write" : "");
            return S3_ERR_ACCESS_DENIED;
        }
        return S3_OK;
    }
    case ACT_PUT_BUCKET_WEBSITE: {
        /* S6: block-public-access is on unless --allow-public: a website
         * config makes the bucket anonymously readable (on the website
         * listener). */
        if (!c->allow_public) return S3_ERR_ACCESS_DENIED;
        s3_err_t e;
        web_config_t *w = web_parse(body, n, &e);
        if (!w) return e;
        web_free(w);
        return S3_OK;
    }
    case ACT_PUT_BUCKET_CORS: {
        s3_err_t e;
        cors_config_t *cc = cors_parse(body, n, &e);
        if (!cc) return e;
        cors_free(cc);
        return S3_OK;
    }
    default:
        return S3_ERR_NOT_IMPLEMENTED;
    }
}

static int cfg_put_begin(conn_t *c, s3_str_t bucket, s3_action_t act) {
    if (!store_bucket_exists(c->store, bucket))
        return rsp_build_s3_error(c, S3_ERR_NO_SUCH_BUCKET, c->req.path, NULL);
    free(c->req_body_buf);
    c->req_body_buf = malloc(CFG_BODY_CAP);
    if (!c->req_body_buf)
        return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    c->req_body_len = 0;
    c->req_body_cap = CFG_BODY_CAP;
    c->cfg_act = (int)act;
    c->cfg_bucket = bucket;
    return 0;
}

static int lock_put_finish(conn_t *c, int legal);

static int put_versioning_finish(conn_t *c) {
    if (c->req_body_len > c->req_body_cap)
        return rsp_build_s3_error(c, S3_ERR_ENTITY_TOO_LARGE, c->req.path, NULL);
    xml_parse_opts_t po = { .max_depth = 4, .max_nodes = 16 };
    XMLNode *root = parse_xml(c->req_body_buf, c->req_body_len, &po, NULL);
    if (!root || strcmp(root->local_name, "VersioningConfiguration") != 0) {
        free_tree(root);
        return rsp_build_s3_error(c, S3_ERR_MALFORMED_XML, c->req.path, NULL);
    }
    XMLNode *st = find_child(root, "Status");
    XMLNode *mfa = find_child(root, "MfaDelete");
    int state = -1;
    if (st && st->content && !strcmp(st->content, "Enabled")) state = S3_VERSIONING_ENABLED;
    else if (st && st->content && !strcmp(st->content, "Suspended")) state = S3_VERSIONING_SUSPENDED;
    int mfa_on = mfa && mfa->content && !strcmp(mfa->content, "Enabled");
    free_tree(root);
    if (mfa_on) return rsp_build_s3_error(c, S3_ERR_NOT_IMPLEMENTED, c->req.path, NULL);
    if (state < 0) return rsp_build_s3_error(c, S3_ERR_MALFORMED_XML, c->req.path, NULL);
    s3_err_t e = store_bucket_set_versioning(c->store, c->cfg_bucket, state);
    if (e != S3_OK) return rsp_build_s3_error(c, e, c->req.path, NULL);
    return rsp_build_status(c, 200, "OK");
}

static int cfg_put_finish(conn_t *c) {
    s3_action_t act = (s3_action_t)c->cfg_act;
    c->cfg_act = 0;
    if (act == ACT_PUT_BUCKET_VERSIONING) return put_versioning_finish(c);
    if (act == ACT_PUT_OBJECT_RETENTION) return lock_put_finish(c, 0);
    if (act == ACT_PUT_OBJECT_LEGAL_HOLD) return lock_put_finish(c, 1);
    const cfg_kind_t *k = cfg_kind_for(act);
    if (!k) return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    if (c->req_body_len > c->req_body_cap)
        return rsp_build_s3_error(c, S3_ERR_ENTITY_TOO_LARGE, c->req.path, NULL);
    s3_err_t e = cfg_validate(c, act, c->req_body_buf, c->req_body_len);
    if (e == S3_OK)
        e = store_bucket_sidecar_write(c->store, c->cfg_bucket, k->sidecar,
                                       c->req_body_buf, c->req_body_len);
    if (e != S3_OK) return rsp_build_s3_error(c, e, c->req.path, NULL);
    return rsp_build_status(c, 200, "OK");
}

static int cfg_get(conn_t *c, s3_str_t bucket, const cfg_kind_t *k) {
    char *data = NULL;
    size_t n = 0;
    s3_err_t e = store_bucket_sidecar_read(c->store, bucket, k->sidecar,
                                           CFG_BODY_CAP, &data, &n);
    if (k->get == ACT_GET_BUCKET_OBJECT_LOCK) {
        if (!store_bucket_object_lock(c->store, bucket)) {
            free(data);
            return rsp_build_s3_error(c, S3_ERR_NO_SUCH_OBJECT_LOCK, c->req.path, NULL);
        }
        if (e == S3_ERR_NO_SUCH_KEY) {
            static const char x[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                "<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                "<ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>";
            data = strdup(x);
            if (!data) return -1;
            return rsp_build_raw(c, 200, "OK", "application/xml", data, sizeof(x) - 1);
        }
    }
    if (e == S3_ERR_NO_SUCH_KEY) e = k->missing;
    if (e != S3_OK) return rsp_build_s3_error(c, e, c->req.path, NULL);
    return rsp_build_raw(c, 200, "OK", k->content_type, data, n);
}

static int cfg_delete(conn_t *c, s3_str_t bucket, const cfg_kind_t *k) {
    s3_err_t e = store_bucket_sidecar_delete(c->store, bucket, k->sidecar);
    if (e != S3_OK) return rsp_build_s3_error(c, e, c->req.path, NULL);
    return rsp_build_status(c, 204, "No Content");
}

/* ===================================================================== */
/* CORS (item 4)                                                          */
/* ===================================================================== */

/* Unauthenticated paths read CORS config through a 1 s TTL cache, so a
 * flood of preflights causes no per-request disk I/O and a missing
 * bucket looks exactly like a bucket without a matching rule (S7). */
#define CORS_CACHE_TTL_MS 1000

static store_cfg_ref_t *cors_ref(conn_t *c, s3_str_t bucket) {
    return store_sidecar_get_ttl(c->store, bucket, "cors.xml", CORS_MAX_BYTES,
                                 cors_parse_cb, cors_free_cb, CORS_CACHE_TTL_MS);
}

static void cors_methods_str(int m, char *out, size_t cap) {
    snprintf(out, cap, "%s%s%s%s%s",
             m & CORS_GET ? "GET, " : "", m & CORS_PUT ? "PUT, " : "",
             m & CORS_POST ? "POST, " : "", m & CORS_DELETE ? "DELETE, " : "",
             m & CORS_HEAD ? "HEAD, " : "");
    size_t n = strlen(out);
    if (n >= 2) out[n - 2] = '\0';
}

/* Allow-Origin value: "*" only if the matching rule's origin is exactly
 * "*" (credentials are never allowed, so this is safe); otherwise echo. */
static void cors_allow_origin(conn_t *c, const cors_rule_t *r, s3_str_t origin) {
    int any = 0;
    for (size_t i = 0; i < r->n_origins; i++)
        if (strcmp(r->origins[i], "*") == 0) any = 1;
    char o[512];
    snprintf(o, sizeof(o), "%.*s", (int)(origin.n < 500 ? origin.n : 500), origin.p);
    conn_add_header(c, "Access-Control-Allow-Origin", any ? "*" : o);
    conn_add_header(c, "Vary", "Origin");
}

/* Bucket name from the raw path's first segment (decoded), or 0. */
static int path_bucket(const conn_t *c, char out[64], s3_str_t *b) {
    s3_str_t p = c->req.path;
    if (p.n < 2 || p.p[0] != '/') return 0;
    size_t i = 1, o = 0;
    while (i < p.n && p.p[i] != '/') {
        if (o >= 63) return 0;
        out[o++] = p.p[i++];
    }
    size_t n = pct_decode(out, o);
    out[n] = '\0';
    *b = (s3_str_t){ out, n };
    return n > 0;
}

static void cors_decorate_bucket(conn_t *c, s3_str_t bucket);

void route_cors_decorate(conn_t *c) {
    char bb[64];
    s3_str_t bucket;
    if (!path_bucket(c, bb, &bucket)) return;
    cors_decorate_bucket(c, bucket);
}

static void cors_decorate_bucket(conn_t *c, s3_str_t bucket) {
    const s3_str_t *origin = hdr_get(c, "origin");
    if (!origin || origin->n == 0) return;
    store_cfg_ref_t *r = cors_ref(c, bucket);
    if (!r) return;
    const cors_rule_t *rule = cors_match(store_cfg_obj(r), *origin,
                                         cors_method_bit(c->req.method),
                                         S3_STR_NULL);
    if (rule) {
        cors_allow_origin(c, rule, *origin);
        char m[64];
        cors_methods_str(rule->methods, m, sizeof(m));
        conn_add_header(c, "Access-Control-Allow-Methods", m);
        if (rule->n_expose) {
            char ex[1024] = "";
            size_t o = 0;
            for (size_t i = 0; i < rule->n_expose && o < sizeof(ex) - 2; i++)
                o += (size_t)snprintf(ex + o, sizeof(ex) - o, "%s%s",
                                      i ? ", " : "", rule->expose[i]);
            conn_add_header(c, "Access-Control-Expose-Headers", ex);
        }
    }
    store_sidecar_put(c->store, r);
}

/* OPTIONS /bucket[/key] — unauthenticated, never touches objects. */
static int handle_preflight(conn_t *c, s3_str_t bucket) {
    const s3_str_t *origin = hdr_get(c, "origin");
    const s3_str_t *rm = hdr_get(c, "access-control-request-method");
    if (!origin || !rm || bucket.n == 0)
        return rsp_build_s3_error(c, S3_ERR_INVALID_REQUEST, c->req.path, NULL);
    const s3_str_t *rh = hdr_get(c, "access-control-request-headers");
    store_cfg_ref_t *r = cors_ref(c, bucket);
    const cors_rule_t *rule = r ? cors_match(store_cfg_obj(r), *origin,
                                             cors_method_bit(*rm),
                                             rh ? *rh : S3_STR_NULL) : NULL;
    if (!rule) {
        if (r) store_sidecar_put(c->store, r);
        return rsp_build_s3_error(c, S3_ERR_CORS_FORBIDDEN, S3_STR_NULL, NULL);
    }
    cors_allow_origin(c, rule, *origin);
    char m[64];
    cors_methods_str(rule->methods, m, sizeof(m));
    conn_add_header(c, "Access-Control-Allow-Methods", m);
    if (rh && rh->n) {
        char hv[1024];
        snprintf(hv, sizeof(hv), "%.*s", (int)(rh->n < 1000 ? rh->n : 1000), rh->p);
        conn_add_header(c, "Access-Control-Allow-Headers", hv);
    }
    if (rule->max_age >= 0) {
        char ma[24];
        snprintf(ma, sizeof(ma), "%ld", rule->max_age);
        conn_add_header(c, "Access-Control-Max-Age", ma);
    }
    if (rule->n_expose) {
        char ex[1024] = "";
        size_t o = 0;
        for (size_t i = 0; i < rule->n_expose && o < sizeof(ex) - 2; i++)
            o += (size_t)snprintf(ex + o, sizeof(ex) - o, "%s%s",
                                  i ? ", " : "", rule->expose[i]);
        conn_add_header(c, "Access-Control-Expose-Headers", ex);
    }
    store_sidecar_put(c->store, r);
    return rsp_build_status(c, 200, "OK");
}

static int max_keys_param(const conn_t *c, const char *name) {
    s3_str_t v = q_val(c, name);
    int mk = 0;
    for (size_t i = 0; i < v.n; i++) {
        if (v.p[i] < '0' || v.p[i] > '9') { mk = 0; break; }
        mk = mk * 10 + (v.p[i] - '0');
        if (mk > 1000) { mk = 1000; break; }
    }
    return mk;
}

static int handle_bucket(conn_t *c, s3_str_t bucket, s3_action_t act) {
    switch (act) {
    case ACT_GET_BUCKET_ACL:
    case ACT_PUT_BUCKET_ACL:
    case ACT_GET_BUCKET_LOCATION:
    case ACT_GET_BUCKET_VERSIONING:
    case ACT_HEAD_BUCKET:
        if (!store_bucket_exists(c->store, bucket))
            return rsp_build_s3_error(c, S3_ERR_NO_SUCH_BUCKET,
                                      c->req.path, NULL);
        if (act == ACT_GET_BUCKET_ACL)        return rsp_build_acl(c);
        if (act == ACT_GET_BUCKET_LOCATION)   return rsp_build_bucket_location(c);
        if (act == ACT_GET_BUCKET_VERSIONING)
            return rsp_build_bucket_versioning_state(c, bucket_versioning_state(c, bucket));
        return rsp_build_status(c, 200, "OK");

    case ACT_CREATE_BUCKET: {
        /* With auth, the signer owns the new bucket. */
        const char *owner = NULL;
        if (c->auth) {
            if (!c->id.user[0])
                return rsp_build_s3_error(c, S3_ERR_ACCESS_DENIED,
                                          c->req.path, NULL);
            owner = c->id.user;
        }
        const s3_str_t *ol = hdr_get(c, "x-amz-bucket-object-lock-enabled");
        s3_err_t e = (ol && ieq_lit(*ol, "true"))
                   ? store_bucket_create_locked(c->store, bucket, owner)
                   : store_bucket_create_owned(c->store, bucket, owner);
        if (e == S3_OK) {
            char loc[1100];
            snprintf(loc, sizeof(loc), "Location: /" S3_STR_FMT "\r\n",
                     S3_STR_ARG(bucket));
            return rsp_build_status_with_headers(c, 200, "OK", loc);
        }
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }

    case ACT_DELETE_BUCKET: {
        s3_err_t e = store_bucket_delete(c->store, bucket);
        if (e == S3_OK) return rsp_build_status(c, 204, "No Content");
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }

    case ACT_DELETE_OBJECTS:
        return handle_bulk_delete_begin(c, bucket);

    case ACT_PUT_BUCKET_VERSIONING:
        return cfg_put_begin(c, bucket, act);

    case ACT_LIST_OBJECT_VERSIONS: {
        s3_version_list_opts_t o = {
            .prefix = q_val(c, "prefix"), .delimiter = q_val(c, "delimiter"),
            .key_marker = q_val(c, "key-marker"),
            .version_id_marker = q_val(c, "version-id-marker"),
            .max_keys = max_keys_param(c, "max-keys"),
        };
        s3_version_info_t *v = NULL;
        size_t n = 0;
        int trunc = 0;
        char *nk = NULL, nv[33];
        s3_err_t e = store_list_versions(c->store, bucket, &o, &v, &n, &trunc, &nk, nv);
        if (e != S3_OK) return rsp_build_s3_error(c, e, c->req.path, NULL);
        int rc = rsp_build_list_versions(c, bucket, &o, v, n, trunc, nk, nv);
        store_versions_free(v, n);
        free(nk);
        return rc;
    }

    case ACT_LIST_MPU_UPLOADS: {
        s3_str_t prefix = q_val(c, "prefix");
        s3_mpu_info_t *ups = NULL;
        size_t n_ups = 0;
        s3_err_t e = store_list_mpu_uploads(c->store, bucket, prefix,
                                            &ups, &n_ups);
        if (e != S3_OK) return rsp_build_s3_error(c, e, c->req.path, NULL);
        int rc = rsp_build_list_mpu_uploads(c, bucket, prefix, ups, n_ups);
        store_mpu_uploads_free(ups, n_ups);
        return rc;
    }

    case ACT_LIST_OBJECTS: {
        s3_list_opts_t opts = { 0 };
        opts.prefix    = q_val(c, "prefix");
        opts.delimiter = q_val(c, "delimiter");
        opts.marker    = q_val(c, "marker");
        opts.max_keys  = max_keys_param(c, "max-keys");
        s3_lister_t *l;
        s3_err_t e = store_list_begin(c->store, bucket, &opts, &l);
        if (e != S3_OK) return rsp_build_s3_error(c, e, c->req.path, NULL);
        return rsp_build_list_bucket(c, bucket, &opts, l);
    }

    default: {
        const cfg_kind_t *k = cfg_kind_for(act);
        if (k && act == k->put) return cfg_put_begin(c, bucket, act);
        if (k && act == k->get) return cfg_get(c, bucket, k);
        if (k && act == k->del) return cfg_delete(c, bucket, k);
        return rsp_build_s3_error(c, S3_ERR_NOT_IMPLEMENTED, c->req.path, NULL);
    }
    }
}

/* ===================================================================== */
/* Object-level (PATH = "/bucket/key...")                                 */
/* ===================================================================== */

/* PUT: open a writer and stream body bytes. Response built at message
 * complete time. */
/* ===================================================================== */
/* Blocking store work on the iopool                                      */
/* ===================================================================== */
/*
 * Commits (fsync + rename), MPU completion (concatenate + fsync) and
 * server-side copy can take from milliseconds to minutes. They run as
 * iopool jobs so the event loop keeps serving other connections; the
 * conn parks in CST_WAIT_JOB until the job's done() builds the response.
 *
 * A job's run() executes on a worker thread and must only touch what the
 * job owns (writers/readers handed over from the conn, copied names).
 * done() runs back on the loop thread; if the client went away meanwhile,
 * job->conn is NULL and done() only cleans up.
 */

/* Park the conn on `j`. Returns -1 if the job (run inline, pool == NULL)
 * already failed to build a response, so the caller drops the conn. */
static int job_submit(conn_t *c, iojob_t *j) {
    j->conn = c;
    c->job = j;
    c->state = CST_WAIT_JOB;
    iopool_submit(c->pool, j);
    return c->state == CST_CLOSING ? -1 : 0;
}

/* In done(): detach from the conn. Returns it, or NULL if orphaned. */
static conn_t *job_finish(iojob_t *j) {
    conn_t *c = j->conn;
    if (c) c->job = NULL;
    return c;
}

/* In done(): a response builder can no longer return -1 up through
 * llhttp, so a failure marks the conn for closing instead. */
static void job_respond(conn_t *c, int rc) {
    if (rc < 0) c->state = CST_CLOSING;
}

/* ---- Commit of a streamed PUT or MPU part --------------------------- */

typedef struct {
    iojob_t        base;
    s3_writer_t   *w;
    int            is_part;
    s3_err_t       err;
    s3_obj_meta_t  meta;          /* PUT */
    char           etag_hex[33];  /* part */
} commit_job_t;

static void commit_run(iojob_t *j) {
    commit_job_t *cj = (commit_job_t *)j;
    if (cj->is_part) cj->err = store_mpu_part_commit(cj->w, cj->etag_hex);
    else             cj->err = store_put_commit(cj->w, &cj->meta);
}

static void commit_done(iojob_t *j) {
    commit_job_t *cj = (commit_job_t *)j;
    conn_t *c = job_finish(j);
    if (c) {
        int rc;
        if (cj->err != S3_OK) {
            rc = rsp_build_s3_error(c, cj->err, c->req.path, NULL);
        } else {
            char extra[80];
            if (cj->is_part) {
                snprintf(extra, sizeof(extra), "ETag: \"%s\"\r\n",
                         cj->etag_hex);
            } else {
                char etag[35]; rsp_format_etag(cj->meta.etag, etag);
                snprintf(extra, sizeof(extra), "ETag: %s\r\n", etag);
            }
            echo_request_checksum(c);
            if (!cj->is_part) {
                char bb[64];
                s3_str_t bk;
                if (path_bucket(c, bb, &bk)) {
                    add_version_header(c, bk, cj->meta.version_id);
                    if (c->lock_pending) {
                        /* Key = path minus "/<bucket>/" (decoded). */
                        /* Raw (encoded) bucket segment length. */
                        const char *sl = memchr(c->req.path.p + 1, '/', c->req.path.n - 1);
                        size_t off = sl ? (size_t)(sl - c->req.path.p) + 1 : c->req.path.n;
                        char *kb = scratch_alloc(c, c->req.path.n);
                        if (kb && c->req.path.n > off) {
                            memcpy(kb, c->req.path.p + off, c->req.path.n - off);
                            size_t kn = pct_decode(kb, c->req.path.n - off);
                            store_lock_write(c->store, bk, (s3_str_t){ kb, kn },
                                             cj->meta.version_id, &c->lock_new);
                        }
                    }
                }
            }
            rc = rsp_build_status_with_headers(c, 200, "OK", extra);
        }
        job_respond(c, rc);
    }
    free(cj);
}

/* Hand c->put_writer to a commit job. */
static int submit_commit(conn_t *c, int is_part) {
    if (!c->put_writer) return -1;  /* programming error */
    commit_job_t *cj = calloc(1, sizeof(*cj));
    if (!cj) {
        if (is_part) store_mpu_part_abort(c->put_writer);
        else         store_put_abort(c->put_writer);
        c->put_writer = NULL;
        return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    }
    cj->base.run  = commit_run;
    cj->base.done = commit_done;
    cj->w       = c->put_writer;
    cj->is_part = is_part;
    c->put_writer = NULL;          /* owned by the job now */
    return job_submit(c, &cj->base);
}

static int handle_object_put_begin(conn_t *c, s3_str_t bucket, s3_str_t key) {
    const s3_str_t *ct_hdr = hdr_get(c, "content-type");
    char ct_buf[128] = {0};
    if (ct_hdr) {
        size_t n = ct_hdr->n;
        if (n >= sizeof(ct_buf)) n = sizeof(ct_buf) - 1;
        memcpy(ct_buf, ct_hdr->p, n);
    }

    s3_writer_t *w;
    s3_err_t e = store_put_begin(c->store, bucket, key, ct_buf, &w);
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }
    c->put_writer = w;
    return 0;
}

/* 200 OK with ETag header, once the commit job finishes. */
static int handle_object_put_complete(conn_t *c) {
    return submit_commit(c, 0);
}

/* Parse an HTTP Range header value of the form "bytes=A-B", "bytes=A-",
 * or "bytes=-N". Returns 1 if a satisfiable range was decoded and written
 * to first_out/last_out, 0 if the header is absent or uses an
 * unrecognized unit (treat as full GET), or -1 if the range is syntactically
 * invalid or outside the object (send 416). */
static int parse_byte_range(const s3_str_t *hdr, uint64_t obj_size,
                             uint64_t *first_out, uint64_t *last_out) {
    if (!hdr || hdr->n == 0) return 0;
    static const char prefix[] = "bytes=";
    const size_t prefix_n = sizeof(prefix) - 1;
    if (hdr->n < prefix_n || memcmp(hdr->p, prefix, prefix_n) != 0) return 0;

    const char *spec  = hdr->p + prefix_n;
    size_t      spec_n = hdr->n - prefix_n;

    const char *dash = memchr(spec, '-', spec_n);
    if (!dash) return 0;  /* no '-' → unrecognized form */

    size_t before_n = (size_t)(dash - spec);
    size_t after_n  = spec_n - before_n - 1;

    if (before_n == 0 && after_n == 0) return -1;  /* "bytes=-" is invalid */

    if (obj_size == 0) return -1;  /* no valid range on empty object */

    uint64_t first, last;
    if (before_n == 0) {
        /* "bytes=-N" — last N bytes */
        uint64_t suffix = 0;
        for (size_t i = 0; i < after_n; i++) {
            char ch = dash[1 + i];
            if (ch < '0' || ch > '9') return -1;
            suffix = suffix * 10 + (uint64_t)(ch - '0');
        }
        if (suffix == 0) return -1;
        first = (suffix >= obj_size) ? 0 : obj_size - suffix;
        last  = obj_size - 1;
    } else if (after_n == 0) {
        /* "bytes=A-" — from A to end */
        first = 0;
        for (size_t i = 0; i < before_n; i++) {
            char ch = spec[i];
            if (ch < '0' || ch > '9') return -1;
            first = first * 10 + (uint64_t)(ch - '0');
        }
        if (first >= obj_size) return -1;
        last = obj_size - 1;
    } else {
        /* "bytes=A-B" */
        first = 0;
        for (size_t i = 0; i < before_n; i++) {
            char ch = spec[i];
            if (ch < '0' || ch > '9') return -1;
            first = first * 10 + (uint64_t)(ch - '0');
        }
        last = 0;
        for (size_t i = 0; i < after_n; i++) {
            char ch = dash[1 + i];
            if (ch < '0' || ch > '9') return -1;
            last = last * 10 + (uint64_t)(ch - '0');
        }
        if (first > last) return -1;
        if (first >= obj_size) return -1;
        if (last >= obj_size) last = obj_size - 1;  /* clamp per RFC 9110 */
    }
    *first_out = first;
    *last_out  = last;
    return 1;
}

static int handle_object_get(conn_t *c, s3_str_t bucket, s3_str_t key,
                             int head_only) {
    s3_reader_t *r;
    s3_obj_meta_t m;
    uint8_t vid[16];
    int hv = c->is_web ? 0 : version_param(c, vid);
    if (hv < 0) return rsp_build_s3_error(c, S3_ERR_INVALID_ARGUMENT, c->req.path, NULL);
    s3_err_t e = store_get_open_version(c->store, bucket, key, hv ? vid : NULL, &r, &m);
    if (e != S3_OK) {
        if (m.flags & S3_OBJF_DELETE_MARKER) {
            conn_add_header(c, "x-amz-delete-marker", "true");
            add_version_header(c, bucket, m.version_id);
            if (e == S3_ERR_METHOD_NOT_ALLOWED) conn_add_header(c, "Allow", "DELETE");
        }
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }
    if (!c->is_web) add_version_header(c, bucket, m.version_id);
    /* S7: an uploaded HTML object opened via a presigned or anonymous URL
     * must not run as an active page on this origin. */
    if (!c->is_web && (!c->id.user[0] || c->id.presigned))
        conn_add_header(c, "Content-Security-Policy", "sandbox");

    /* Parse optional Range header. */
    const s3_str_t *range_hdr = hdr_get(c, "range");
    uint64_t rfirst = 0, rlast = 0;
    int range_rc = parse_byte_range(range_hdr, m.size, &rfirst, &rlast);
    if (range_rc < 0) {
        store_get_close(r);
        return rsp_build_range_not_satisfiable(c, m.size);
    }

    if (range_rc > 0) {
        /* Satisfy range: seek the reader, build 206 head. */
        store_get_seek(r, rfirst, rlast);
        if (rsp_build_object_range(c, &m, rfirst, rlast, head_only) < 0) {
            store_get_close(r);
            return -1;
        }
        if (head_only) {
            store_get_close(r);
            return 0;
        }
        c->get_reader = r;
        return 0;
    }

    /* Full GET / HEAD. The stored checksum goes out only on request
     * (x-amz-checksum-mode: ENABLED) and never on a ranged GET. */
    const s3_str_t *cmode = hdr_get(c, "x-amz-checksum-mode");
    if (cmode && ieq_lit(*cmode, "ENABLED")) add_checksum_headers(c, &m);

    if (rsp_build_object_head(c, &m, head_only) < 0) {
        store_get_close(r);
        return -1;
    }
    if (head_only) {
        store_get_close(r);
        return 0;
    }
    /* Stash reader; conn_on_writable will sendfile after wbuf drains. */
    c->get_reader = r;
    return 0;
}

static int handle_object_delete(conn_t *c, s3_str_t bucket, s3_str_t key) {
    uint8_t vid[16];
    int hv = version_param(c, vid);
    if (hv < 0) return rsp_build_s3_error(c, S3_ERR_INVALID_ARGUMENT, c->req.path, NULL);
    const s3_str_t *bp = hdr_get(c, "x-amz-bypass-governance-retention");
    store_set_guard_bypass(bp && ieq_lit(*bp, "true") && c->id.is_admin);
    store_delete_result_t res;
    s3_err_t e = store_delete_ex(c->store, bucket, key, hv ? vid : NULL, &res);
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }
    if (res.delete_marker) conn_add_header(c, "x-amz-delete-marker", "true");
    if (res.versioned || hv) conn_add_header(c, "x-amz-version-id", res.version_id);
    return rsp_build_status(c, 204, "No Content");
}

/* ===================================================================== */
/* Object copy (PUT with x-amz-copy-source header)                       */
/* ===================================================================== */

/* The byte copy and commit, on a worker. */
typedef struct {
    iojob_t        base;
    s3_reader_t   *r;
    s3_writer_t   *w;
    s3_err_t       err;
    s3_obj_meta_t  meta;
} copy_job_t;

static void copy_run(iojob_t *j) {
    copy_job_t *cj = (copy_job_t *)j;
    char xbuf[64 * 1024];
    int stream_ok = 1;
    for (;;) {
        ssize_t n = store_get_read(cj->r, xbuf, sizeof(xbuf));
        if (n == 0) break;
        if (n < 0 || store_put_write(cj->w, xbuf, (size_t)n) != S3_OK) {
            stream_ok = 0;
            break;
        }
    }
    store_get_close(cj->r);
    if (!stream_ok) {
        store_put_abort(cj->w);
        cj->err = S3_ERR_INTERNAL;
        return;
    }
    cj->err = store_put_commit(cj->w, &cj->meta);
}

static void copy_done(iojob_t *j) {
    copy_job_t *cj = (copy_job_t *)j;
    conn_t *c = job_finish(j);
    if (c) {
        if (cj->err == S3_OK) add_version_header(c, c->copy_bucket, cj->meta.version_id);
        job_respond(c, cj->err != S3_OK
            ? rsp_build_s3_error(c, cj->err, c->req.path, NULL)
            : rsp_build_copy_object(c, &cj->meta));
    }
    free(cj);
}

/* Validate and open both ends on the loop (cheap, and errors answer
 * immediately), then hand the byte copy to the pool. */
static int handle_object_copy(conn_t *c, s3_str_t dst_bucket, s3_str_t dst_key) {
    const s3_str_t *src_hdr = hdr_get(c, "x-amz-copy-source");

    /* Decode the source path. Use malloc — it may be up to ~1100 bytes and
     * we don't want to exhaust the per-request scratch arena. */
    char *src_buf = malloc(src_hdr->n + 1);
    if (!src_buf) return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    memcpy(src_buf, src_hdr->p, src_hdr->n);
    size_t src_n = pct_decode(src_buf, src_hdr->n);

    /* Optional ?versionId=<id> selects a source version. */
    uint8_t src_vid[16];
    int has_src_vid = 0;
    char *qmark = memchr(src_buf, '?', src_n);
    if (qmark) {
        s3_str_t q = { qmark + 1, src_n - (size_t)(qmark + 1 - src_buf) };
        if (q.n < 10 || memcmp(q.p, "versionId=", 10) != 0
            || store_vid_parse((s3_str_t){ q.p + 10, q.n - 10 }, src_vid) < 0) {
            free(src_buf);
            return rsp_build_s3_error(c, S3_ERR_INVALID_ARGUMENT, c->req.path, NULL);
        }
        has_src_vid = 1;
        src_n = (size_t)(qmark - src_buf);
    }

    /* Skip optional leading '/'. */
    char *p = src_buf;
    if (src_n > 0 && p[0] == '/') { p++; src_n--; }

    /* Split at first '/' → src_bucket / src_key. */
    char *slash = memchr(p, '/', src_n);
    if (!slash || slash == p) {
        free(src_buf);
        return rsp_build_s3_error(c, S3_ERR_INVALID_ARGUMENT, c->req.path, NULL);
    }
    size_t src_bucket_n = (size_t)(slash - p);
    size_t src_key_n    = src_n - src_bucket_n - 1;
    if (src_key_n == 0) {
        free(src_buf);
        return rsp_build_s3_error(c, S3_ERR_INVALID_ARGUMENT, c->req.path, NULL);
    }
    s3_str_t src_bucket = { p,         src_bucket_n };
    s3_str_t src_key    = { slash + 1, src_key_n    };

    /* The destination was authorized at dispatch; the source is a second
     * bucket and needs its own check. */
    s3_err_t ae = authz(c, src_bucket, src_key, ACT_GET_OBJECT);
    if (ae != S3_OK && ae != S3_ERR_NO_SUCH_BUCKET) {
        free(src_buf);
        return rsp_build_s3_error(c, ae, c->req.path, NULL);
    }

    /* Open source. */
    s3_reader_t *reader = NULL;
    s3_obj_meta_t src_meta;
    s3_err_t e = store_get_open_version(c->store, src_bucket, src_key,
                                        has_src_vid ? src_vid : NULL,
                                        &reader, &src_meta);
    if (e == S3_OK && has_src_vid) {
        char vs[33];
        store_vid_format(src_vid, vs);
        conn_add_header(c, "x-amz-copy-source-version-id", vs);
    }
    if (e != S3_OK) {
        free(src_buf);
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }

    /* Open dest writer with source content-type. */
    s3_writer_t *writer = NULL;
    e = store_put_begin(c->store, dst_bucket, dst_key, src_meta.content_type, &writer);
    if (e != S3_OK) {
        store_get_close(reader);
        free(src_buf);
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }
    free(src_buf);  /* src_buf no longer needed; src_bucket/src_key no longer safe */

    copy_job_t *cj = calloc(1, sizeof(*cj));
    if (!cj) {
        store_get_close(reader);
        store_put_abort(writer);
        return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    }
    cj->base.run  = copy_run;
    cj->base.done = copy_done;
    cj->r = reader;
    cj->w = writer;
    return job_submit(c, &cj->base);
}

/* ===================================================================== */
/* Multipart upload handlers                                              */
/* ===================================================================== */

/* POST /bucket/key?uploads — generate an upload ID and return
 * <InitiateMultipartUploadResult>. */
static int handle_mpu_initiate(conn_t *c, s3_str_t bucket, s3_str_t key) {
    const s3_str_t *ct_hdr = hdr_get(c, "content-type");
    char ct_buf[128] = {0};
    if (ct_hdr) {
        size_t n = ct_hdr->n;
        if (n >= sizeof(ct_buf)) n = sizeof(ct_buf) - 1;
        memcpy(ct_buf, ct_hdr->p, n);
    }

    /* x-amz-checksum-algorithm / -type: COMPOSITE is the default except
     * for CRC64NVME, which only exists as a full-object checksum. */
    uint8_t algo = 0, type = 0;
    const s3_str_t *ah = hdr_get(c, "x-amz-checksum-algorithm");
    const s3_str_t *th = hdr_get(c, "x-amz-checksum-type");
    if (ah) {
        algo = (uint8_t)cksum_algo_from_name(*ah);
        if (!algo)
            return rsp_build_s3_error(c, S3_ERR_INVALID_CHECKSUM, c->req.path, NULL);
        type = algo == S3_CKSUM_CRC64NVME ? S3_CKSUM_TYPE_FULL_OBJECT
                                          : S3_CKSUM_TYPE_COMPOSITE;
    }
    if (th) {
        if (!algo)
            return rsp_build_s3_error(c, S3_ERR_INVALID_CHECKSUM, c->req.path, NULL);
        if (ieq_lit(*th, "FULL_OBJECT")) type = S3_CKSUM_TYPE_FULL_OBJECT;
        else if (ieq_lit(*th, "COMPOSITE")) type = S3_CKSUM_TYPE_COMPOSITE;
        else return rsp_build_s3_error(c, S3_ERR_INVALID_CHECKSUM, c->req.path, NULL);
        if (type == S3_CKSUM_TYPE_COMPOSITE && algo == S3_CKSUM_CRC64NVME)
            return rsp_build_s3_error(c, S3_ERR_INVALID_CHECKSUM, c->req.path, NULL);
    }

    char upload_id[33];
    s3_err_t e = store_mpu_create_opts(c->store, bucket, key,
                                       ct_hdr ? ct_buf : NULL, algo, type,
                                       upload_id);
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }
    if (algo) {
        conn_add_header(c, "x-amz-checksum-algorithm", cksum_upper_name(algo));
        conn_add_header(c, "x-amz-checksum-type",
                        type == S3_CKSUM_TYPE_COMPOSITE ? "COMPOSITE" : "FULL_OBJECT");
    }
    return rsp_build_initiate_mpu(c, bucket, key, upload_id);
}

/* PUT /bucket/key?partNumber=N&uploadId=ID — open a part writer.
 * Body streams via cb_on_body. The matching commit happens in
 * handle_mpu_part_complete from route_dispatch_complete. */
static int handle_mpu_upload_part_begin(conn_t *c, s3_str_t bucket, s3_str_t key,
                                         int part_number, const char *upload_id) {
    s3_writer_t *w;
    s3_err_t e = store_mpu_part_begin(c->store, bucket, key,
                                       upload_id, part_number, &w);
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }
    c->put_writer = w;
    c->mpu_is_part_upload = 1;
    return 0;
}

/* Commit the in-flight part; build a 200 with ETag header. Called from
 * route_dispatch_complete for an active part-upload writer. */
static int handle_mpu_part_complete(conn_t *c) {
    return submit_commit(c, 1);
}

/* POST /bucket/key?uploadId=ID — complete. The XML body lists the parts.
 * We allocate a 1 MiB body buffer; cb_on_body fills it; the actual
 * completion happens in handle_mpu_complete_finish. */
#define MPU_COMPLETE_BODY_CAP (1024 * 1024)

static int handle_mpu_complete_begin(conn_t *c) {
    /* Allocate buffer to receive the XML body. */
    free(c->req_body_buf);
    c->req_body_buf = malloc(MPU_COMPLETE_BODY_CAP);
    if (!c->req_body_buf) {
        return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    }
    c->req_body_len = 0;
    c->req_body_cap = MPU_COMPLETE_BODY_CAP;
    return 0;
}

/* Parse one <Part>...<PartNumber>N</PartNumber><ETag>"hex"</ETag>...</Part>
 * out of the body. Returns the byte offset just after the closing </Part>,
 * or -1 if no further <Part> found, or -2 on malformed input. Fills `out`
 * with the parsed values when found. */
static long parse_one_part(const char *body, size_t n, size_t start,
                            s3_part_ref_t *out) {
    /* Find next "<Part>" — but not "<Parts>" (used in some clients) or
     * any other tag starting with "Part". Easiest: scan for "<Part>". */
    static const char open_tag[] = "<Part>";
    static const char close_tag[] = "</Part>";
    const char *p = memmem(body + start, n - start, open_tag, sizeof(open_tag) - 1);
    if (!p) return -1;
    size_t inner_start = (size_t)(p - body) + sizeof(open_tag) - 1;
    const char *q = memmem(body + inner_start, n - inner_start,
                           close_tag, sizeof(close_tag) - 1);
    if (!q) return -2;
    size_t inner_end = (size_t)(q - body);
    /* Now within [inner_start, inner_end), find PartNumber and ETag. */
    /* Look for <PartNumber>...</PartNumber> */
    static const char pn_open[] = "<PartNumber>";
    static const char pn_close[] = "</PartNumber>";
    const char *pn_p = memmem(body + inner_start, inner_end - inner_start,
                              pn_open, sizeof(pn_open) - 1);
    if (!pn_p) return -2;
    size_t pn_v0 = (size_t)(pn_p - body) + sizeof(pn_open) - 1;
    const char *pn_q = memmem(body + pn_v0, inner_end - pn_v0,
                              pn_close, sizeof(pn_close) - 1);
    if (!pn_q) return -2;
    size_t pn_vn = (size_t)(pn_q - body) - pn_v0;
    /* Parse decimal */
    int part_number = 0;
    for (size_t i = 0; i < pn_vn; i++) {
        char ch = body[pn_v0 + i];
        if (ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r') continue;
        if (ch < '0' || ch > '9') return -2;
        part_number = part_number * 10 + (ch - '0');
        if (part_number > 10000) return -2;
    }
    if (part_number < 1) return -2;

    /* ETag — value is wrapped in quotes by S3 convention, but be tolerant. */
    static const char et_open[] = "<ETag>";
    static const char et_close[] = "</ETag>";
    const char *et_p = memmem(body + inner_start, inner_end - inner_start,
                              et_open, sizeof(et_open) - 1);
    if (!et_p) return -2;
    size_t et_v0 = (size_t)(et_p - body) + sizeof(et_open) - 1;
    const char *et_q = memmem(body + et_v0, inner_end - et_v0,
                              et_close, sizeof(et_close) - 1);
    if (!et_q) return -2;
    size_t et_vn = (size_t)(et_q - body) - et_v0;
    /* Strip surrounding quotes/whitespace */
    while (et_vn > 0 && (body[et_v0] == '"' || body[et_v0] == ' '
                         || body[et_v0] == '\t' || body[et_v0] == '\n'
                         || body[et_v0] == '\r' || body[et_v0] == '&')) {
        /* '&' would be the start of "&quot;" — skip the whole entity. */
        if (body[et_v0] == '&') {
            const char *amp_end = memchr(body + et_v0, ';', et_vn);
            if (!amp_end) return -2;
            size_t adv = (size_t)(amp_end - (body + et_v0)) + 1;
            if (adv > et_vn) return -2;
            et_v0 += adv; et_vn -= adv;
            continue;
        }
        et_v0++; et_vn--;
    }
    while (et_vn > 0 && (body[et_v0 + et_vn - 1] == '"'
                         || body[et_v0 + et_vn - 1] == ' '
                         || body[et_v0 + et_vn - 1] == '\t'
                         || body[et_v0 + et_vn - 1] == '\n'
                         || body[et_v0 + et_vn - 1] == '\r'
                         || body[et_v0 + et_vn - 1] == ';')) {
        /* Trailing ";" might come from "&quot;" — strip the whole entity. */
        if (body[et_v0 + et_vn - 1] == ';') {
            const char *semi = body + et_v0 + et_vn - 1;
            const char *amp = memrchr(body + et_v0, '&', et_vn);
            if (!amp || amp > semi) return -2;
            et_vn = (size_t)(amp - (body + et_v0));
            continue;
        }
        et_vn--;
    }
    if (et_vn != 32) return -2;
    for (size_t i = 0; i < 32; i++) {
        char ch = body[et_v0 + i];
        if (!((ch >= '0' && ch <= '9')
              || (ch >= 'a' && ch <= 'f')
              || (ch >= 'A' && ch <= 'F'))) return -2;
    }
    out->part_number = part_number;
    memcpy(out->etag_hex, body + et_v0, 32);
    out->etag_hex[32] = '\0';
    out->cksum_n = 0;
    for (int algo = 1; algo < S3_CKSUM_MAX; algo++) {
        char open_t[40], close_t[40];
        int on = snprintf(open_t, sizeof(open_t), "<%s>", cksum_xml_name(algo));
        int cn = snprintf(close_t, sizeof(close_t), "</%s>", cksum_xml_name(algo));
        const char *cp = memmem(body + inner_start, inner_end - inner_start,
                                open_t, (size_t)on);
        if (!cp) continue;
        size_t v0 = (size_t)(cp - body) + (size_t)on;
        const char *cq = memmem(body + v0, inner_end - v0, close_t, (size_t)cn);
        if (!cq || out->cksum_n) return -2;
        int dn = base64_decode(body + v0, (size_t)(cq - body) - v0,
                               out->cksum, sizeof(out->cksum));
        if (dn != (int)cksum_digest_len(algo)) return -2;
        out->cksum_n = (uint8_t)dn;
    }
    return (long)((size_t)(q - body) + sizeof(close_tag) - 1);
}

/* Concatenation + fsync + publish, on a worker. Names are copied: the
 * worker must not read the conn's request buffers. */
typedef struct {
    iojob_t         base;
    s3_store_t     *store;
    char           *names;        /* bucket bytes then key bytes */
    size_t          bucket_n, key_n;
    char            upload_id[33];
    s3_part_ref_t  *parts;
    size_t          n_parts;
    uint8_t         full[32];     /* x-amz-checksum-<algo> on Complete */
    size_t          full_n;       /* 0 = none */
    s3_err_t        err;
    char            etag[40];
    s3_obj_meta_t   meta;
} mpu_complete_job_t;

static void mpu_complete_run(iojob_t *j) {
    mpu_complete_job_t *mj = (mpu_complete_job_t *)j;
    s3_str_t bucket = { mj->names, mj->bucket_n };
    s3_str_t key    = { mj->names + mj->bucket_n, mj->key_n };
    mj->err = store_mpu_complete2(mj->store, bucket, key, mj->upload_id,
                                  mj->parts, mj->n_parts,
                                  mj->full_n ? mj->full : NULL, mj->full_n,
                                  mj->etag, &mj->meta);
}

static void mpu_complete_done(iojob_t *j) {
    mpu_complete_job_t *mj = (mpu_complete_job_t *)j;
    conn_t *c = job_finish(j);
    if (c) {
        /* c->mpu_bucket/mpu_key are still valid: the request isn't reset
         * until its response has been written. */
        job_respond(c, mj->err != S3_OK
            ? rsp_build_s3_error(c, mj->err, c->req.path, NULL)
            : (add_checksum_headers(c, &mj->meta),
               add_version_header(c, c->mpu_bucket, mj->meta.version_id),
               rsp_build_complete_mpu2(c, c->mpu_bucket, c->mpu_key, mj->etag,
                                       &mj->meta)));
    }
    free(mj->parts);
    free(mj->names);
    free(mj);
}

static int handle_mpu_complete_finish(conn_t *c, s3_str_t bucket, s3_str_t key,
                                       const char *upload_id) {
    /* Reject if body overflowed the cap. */
    if (c->req_body_len > c->req_body_cap) {
        return rsp_build_s3_error(c, S3_ERR_INVALID_REQUEST, c->req.path, NULL);
    }

    /* Parse <Part> entries. We allocate up to 10000 part refs; in practice
     * the body cap of 1 MiB will limit this well below that. */
    s3_part_ref_t *parts = NULL;
    size_t parts_n = 0, parts_cap = 0;
    size_t pos = 0;
    while (pos < c->req_body_len) {
        if (parts_n == parts_cap) {
            size_t nc = parts_cap ? parts_cap * 2 : 16;
            if (nc > 10000) nc = 10000;
            s3_part_ref_t *np = realloc(parts, nc * sizeof(*np));
            if (!np) {
                free(parts);
                return rsp_build_s3_error(c, S3_ERR_INTERNAL,
                                          c->req.path, NULL);
            }
            parts = np;
            parts_cap = nc;
        }
        long r = parse_one_part(c->req_body_buf, c->req_body_len, pos,
                                &parts[parts_n]);
        if (r == -1) break;       /* no more parts */
        if (r == -2) {
            free(parts);
            return rsp_build_s3_error(c, S3_ERR_MALFORMED_XML,
                                      c->req.path, NULL);
        }
        parts_n++;
        if (parts_n >= 10000) break;
        pos = (size_t)r;
    }
    if (parts_n == 0) {
        free(parts);
        return rsp_build_s3_error(c, S3_ERR_INVALID_REQUEST,
                                  c->req.path, NULL);
    }

    mpu_complete_job_t *mj = calloc(1, sizeof(*mj));
    char *names = malloc(bucket.n + key.n + 1);
    if (!mj || !names) {
        free(mj); free(names); free(parts);
        return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    }
    memcpy(names, bucket.p, bucket.n);
    memcpy(names + bucket.n, key.p, key.n);
    mj->base.run  = mpu_complete_run;
    mj->base.done = mpu_complete_done;
    mj->store    = c->store;
    mj->names    = names;
    mj->bucket_n = bucket.n;
    mj->key_n    = key.n;
    snprintf(mj->upload_id, sizeof(mj->upload_id), "%s", upload_id);
    mj->parts    = parts;
    mj->n_parts  = parts_n;
    /* FULL_OBJECT uploads: the whole-object checksum comes as a header on
     * Complete (conn.c does not treat it as a body checksum here). */
    for (size_t i = 0; i < c->req.n_headers; i++) {
        int a = cksum_algo_from_header(c->req.headers[i].k);
        if (!a) continue;
        const s3_str_t *v = &c->req.headers[i].v;
        int dn = base64_decode(v->p, v->n, mj->full, sizeof(mj->full));
        if (dn != (int)cksum_digest_len(a) || mj->full_n) {
            free(mj); free(names); free(parts);
            return rsp_build_s3_error(c, S3_ERR_INVALID_CHECKSUM, c->req.path, NULL);
        }
        mj->full_n = (size_t)dn;
    }
    return job_submit(c, &mj->base);
}

/* DELETE /bucket/key?uploadId=ID */
static int handle_mpu_abort(conn_t *c, s3_str_t bucket, s3_str_t key,
                             const char *upload_id) {
    s3_err_t e = store_mpu_abort(c->store, bucket, key, upload_id);
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }
    return rsp_build_status(c, 204, "No Content");
}

/* ===================================================================== */
/* Top-level dispatch                                                     */
/* ===================================================================== */

static int is_known_subresource(s3_str_t k);

/* ===================================================================== */
/* Static website listener (item 6)                                       */
/* ===================================================================== */
/*
 * Garage's model: a website config enables anonymous GET/HEAD *only on a
 * dedicated listener*, so the S3 endpoint's auth model is untouched.
 * Authorization headers are ignored entirely (no confused deputy), no
 * subresources or listing, and errors are HTML, never S3 XML.
 */

static int web_html(conn_t *c, int status, const char *reason, const char *msg) {
    char *b = malloc(512);
    if (!b) return -1;
    int n = snprintf(b, 512,
        "<!DOCTYPE html>\n<html><head><title>%d %s</title></head>"
        "<body><h1>%d %s</h1><p>%s</p></body></html>\n",
        status, reason, status, reason, msg);
    return rsp_build_raw(c, status, reason, "text/html; charset=utf-8", b,
                         (size_t)n);
}

/* Bucket from Host: "<bucket>.<root-domain>" or, for custom domains
 * behind the DSM proxy, a Host equal to a bucket name. Port stripped;
 * the result must pass the S3 bucket-name rules (S5). */
static int web_bucket_from_host(conn_t *c, char out[64], s3_str_t *b) {
    const s3_str_t *h = hdr_get(c, "host");
    if (!h || h->n == 0 || h->n > 300) return 0;
    char host[301];
    size_t hn = 0;
    for (size_t i = 0; i < h->n && h->p[i] != ':'; i++) {
        char ch = h->p[i];
        host[hn++] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
    }
    host[hn] = '\0';
    if (hn && host[hn - 1] == '.') host[--hn] = '\0';
    const char *root = c->web_root_domain;
    size_t rn = root ? strlen(root) : 0;
    size_t bn = hn;
    if (rn && hn > rn + 1 && host[hn - rn - 1] == '.'
        && strcmp(host + hn - rn, root) == 0)
        bn = hn - rn - 1;
    if (bn == 0 || bn > 63) return 0;
    memcpy(out, host, bn);
    out[bn] = '\0';
    *b = (s3_str_t){ out, bn };
    return store_valid_bucket_name(*b);
}

/* Location for a directory redirect: one leading '/', no empty segments
 * (so "//evil.example" can never become a protocol-relative URL — S7),
 * percent-encoded except unreserved and '/'. */
static void web_dir_location(s3_str_t key, char *out, size_t cap) {
    static const char H[] = "0123456789ABCDEF";
    size_t o = 0;
    out[o++] = '/';
    for (size_t i = 0; i < key.n && o + 4 < cap; i++) {
        unsigned char ch = (unsigned char)key.p[i];
        if (ch == '/') {
            if (out[o - 1] != '/') out[o++] = '/';
        } else if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                   || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_'
                   || ch == '.' || ch == '~') {
            out[o++] = (char)ch;
        } else {
            out[o++] = '%'; out[o++] = H[ch >> 4]; out[o++] = H[ch & 15];
        }
    }
    if (out[o - 1] != '/' && o + 1 < cap) out[o++] = '/';
    out[o] = '\0';
}

static int web_store_key_exists(conn_t *c, s3_str_t bucket, s3_str_t key) {
    s3_obj_meta_t m;
    return store_head(c->store, bucket, key, &m) == S3_OK
        && !(m.flags & S3_OBJF_DELETE_MARKER);
}

static int web_dispatch(conn_t *c) {
    int head = method_is(c, "HEAD");
    if (!method_is(c, "GET") && !head) {
        conn_add_header(c, "Allow", "GET, HEAD");
        return web_html(c, 405, "Method Not Allowed", "Only GET and HEAD.");
    }
    for (size_t i = 0; i < c->req.n_qp; i++) {
        s3_str_t k = c->req.qp[i].k;
        if (is_known_subresource(k)
            || (k.n >= 6 && (memcmp(k.p, "X-Amz-", 6) == 0 || memcmp(k.p, "x-amz-", 6) == 0)))
            return web_html(c, 400, "Bad Request", "Unsupported query parameter.");
    }
    char bb[64];
    s3_str_t bucket;
    if (!web_bucket_from_host(c, bb, &bucket))
        return web_html(c, 404, "Not Found", "No such website.");
    store_cfg_ref_t *ref = store_sidecar_get_ttl(c->store, bucket, "website.xml",
                                                 WEB_MAX_BYTES, web_parse_cb,
                                                 web_free_cb, 1000);
    if (!ref) return web_html(c, 404, "Not Found", "No such website.");
    const web_config_t *w = store_cfg_obj(ref);
    cors_decorate_bucket(c, bucket);

    int rc;
    if (w->redirect_host) {
        char loc[2048];
        snprintf(loc, sizeof(loc), "%s://%s%.*s",
                 w->redirect_proto ? w->redirect_proto : "http", w->redirect_host,
                 (int)(c->req.path.n < 1500 ? c->req.path.n : 1500), c->req.path.p);
        conn_add_header(c, "Location", loc);
        rc = web_html(c, 301, "Moved Permanently", "Moved.");
        goto out;
    }

    /* Key from the decoded path (leading '/' dropped). */
    char *kb = scratch_alloc(c, c->req.path.n + strlen(w->index_suffix) + 2);
    if (!kb) { rc = web_html(c, 414, "URI Too Long", "Path too long."); goto out; }
    memcpy(kb, c->req.path.p, c->req.path.n);
    size_t kn = pct_decode(kb, c->req.path.n);
    char *key = kb;
    while (kn && *key == '/') { key++; kn--; }
    if (kn == 0 || key[kn - 1] == '/') {
        size_t sn = strlen(w->index_suffix);
        memcpy(key + kn, w->index_suffix, sn);
        kn += sn;
    }
    s3_str_t k = { key, kn };
    if (web_store_key_exists(c, bucket, k)) {
        rc = handle_object_get(c, bucket, k, head);
        goto out;
    }
    /* "dir" missing but "dir/<index>" present → 302 to "dir/". */
    if (kn && key[kn - 1] != '/') {
        size_t sn = strlen(w->index_suffix);
        char *alt = scratch_alloc(c, kn + sn + 2);
        if (alt) {
            memcpy(alt, key, kn);
            alt[kn] = '/';
            memcpy(alt + kn + 1, w->index_suffix, sn);
            if (web_store_key_exists(c, bucket, (s3_str_t){ alt, kn + 1 + sn })) {
                char loc[2048];
                web_dir_location(k, loc, sizeof(loc));
                conn_add_header(c, "Location", loc);
                rc = web_html(c, 302, "Found", "Moved.");
                goto out;
            }
        }
    }
    if (w->error_key) {
        s3_str_t ek = { w->error_key, strlen(w->error_key) };
        s3_reader_t *r;
        s3_obj_meta_t m;
        if (store_get_open(c->store, bucket, ek, &r, &m) == S3_OK) {
            if (rsp_build_object_head_status(c, &m, head, 404, "Not Found") < 0) {
                store_get_close(r);
                rc = -1;
                goto out;
            }
            if (head) store_get_close(r);
            else c->get_reader = r;
            rc = 0;
            goto out;
        }
    }
    rc = web_html(c, 404, "Not Found", "The requested page does not exist.");
out:
    store_sidecar_put(c->store, ref);
    return rc;
}

/* ===================================================================== */
/* Object Lock: ?retention / ?legal-hold (item 10)                        */
/* ===================================================================== */

/* Resolve the version a lock subresource targets (versionId or current). */
static s3_err_t lock_target(conn_t *c, s3_str_t bucket, s3_str_t key,
                            s3_obj_meta_t *m) {
    if (!store_bucket_object_lock(c->store, bucket)) return S3_ERR_INVALID_REQUEST;
    uint8_t vid[16];
    int hv = version_param(c, vid);
    if (hv < 0) return S3_ERR_INVALID_ARGUMENT;
    s3_reader_t *r;
    s3_err_t e = store_get_open_version(c->store, bucket, key, hv ? vid : NULL, &r, m);
    if (e == S3_OK) store_get_close(r);
    return e;
}

static int lock_get(conn_t *c, s3_str_t bucket, s3_str_t key, int legal) {
    s3_obj_meta_t m;
    s3_err_t e = lock_target(c, bucket, key, &m);
    if (e != S3_OK) return rsp_build_s3_error(c, e, c->req.path, NULL);
    s3_lock_t l;
    olock_effective(c->store, bucket, key, &m, &l);
    char *b = malloc(512);
    if (!b) return -1;
    int n;
    if (legal) {
        n = snprintf(b, 512, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                     "<LegalHold xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                     "<Status>%s</Status></LegalHold>", l.legal_hold ? "ON" : "OFF");
    } else {
        if (!l.mode) {
            free(b);
            return rsp_build_s3_error(c, S3_ERR_NO_SUCH_OBJECT_LOCK, c->req.path, NULL);
        }
        char ts[32];
        rsp_format_iso8601(l.until_ms, ts);
        n = snprintf(b, 512, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                     "<Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
                     "<Mode>%s</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>",
                     olock_mode_name(l.mode), ts);
    }
    return rsp_build_raw(c, 200, "OK", "application/xml", b, (size_t)n);
}

static int lock_put_finish(conn_t *c, int legal) {
    if (c->req_body_len > c->req_body_cap)
        return rsp_build_s3_error(c, S3_ERR_ENTITY_TOO_LARGE, c->req.path, NULL);
    s3_obj_meta_t m;
    s3_err_t e = lock_target(c, c->cfg_bucket, c->cfg_key, &m);
    if (e != S3_OK) return rsp_build_s3_error(c, e, c->req.path, NULL);
    s3_lock_t cur, next;
    olock_effective(c->store, c->cfg_bucket, c->cfg_key, &m, &cur);
    next = cur;
    if (legal) {
        int on;
        if (olock_parse_legal_hold(c->req_body_buf, c->req_body_len, &on) < 0)
            return rsp_build_s3_error(c, S3_ERR_MALFORMED_XML, c->req.path, NULL);
        next.legal_hold = on;
    } else {
        s3_lock_t r;
        if (olock_parse_retention(c->req_body_buf, c->req_body_len, &r) < 0)
            return rsp_build_s3_error(c, S3_ERR_MALFORMED_XML, c->req.path, NULL);
        const s3_str_t *bp = hdr_get(c, "x-amz-bypass-governance-retention");
        int bypass = bp && ieq_lit(*bp, "true") && c->id.is_admin;
        e = olock_check_retention_change(&cur, &r, bypass, c->max_retention_ms);
        if (e != S3_OK) return rsp_build_s3_error(c, e, c->req.path, NULL);
        next.mode = r.mode;
        next.until_ms = r.until_ms;
    }
    e = store_lock_write(c->store, c->cfg_bucket, c->cfg_key, m.version_id, &next);
    if (e != S3_OK) return rsp_build_s3_error(c, e, c->req.path, NULL);
    return rsp_build_status(c, 200, "OK");
}

/* PUT object with x-amz-object-lock-* headers: validate now, apply to
 * the new version after commit. S3 requires an integrity check on such
 * PUTs (Content-MD5 or x-amz-checksum-*), and setting retention needs the
 * PutObjectRetention / PutObjectLegalHold permission (o, not w — S9). */
static s3_err_t lock_headers_begin(conn_t *c, s3_str_t bucket, s3_str_t key) {
    const s3_str_t *mh = hdr_get(c, "x-amz-object-lock-mode");
    const s3_str_t *uh = hdr_get(c, "x-amz-object-lock-retain-until-date");
    const s3_str_t *lh = hdr_get(c, "x-amz-object-lock-legal-hold");
    if (!mh && !uh && !lh) return S3_OK;
    if (!store_bucket_object_lock(c->store, bucket)) return S3_ERR_INVALID_REQUEST;
    int has_ck = hdr_get(c, "content-md5") || hdr_get(c, "x-amz-trailer");
    for (size_t i = 0; i < c->req.n_headers && !has_ck; i++)
        has_ck = cksum_algo_from_header(c->req.headers[i].k) != 0;
    if (!has_ck) return S3_ERR_INVALID_REQUEST;
    memset(&c->lock_new, 0, sizeof(c->lock_new));
    if (mh || uh) {
        if (!mh || !uh) return S3_ERR_INVALID_ARGUMENT;
        char buf[64];
        snprintf(buf, sizeof(buf), "%.*s", (int)(mh->n < 60 ? mh->n : 60), mh->p);
        c->lock_new.mode = olock_mode_parse(buf);
        snprintf(buf, sizeof(buf), "%.*s", (int)(uh->n < 60 ? uh->n : 60), uh->p);
        if (c->lock_new.mode < 0 || olock_parse_date(buf, &c->lock_new.until_ms) < 0)
            return S3_ERR_INVALID_ARGUMENT;
        s3_lock_t none = {0};
        s3_err_t e = olock_check_retention_change(&none, &c->lock_new, 0, c->max_retention_ms);
        if (e != S3_OK) return e;
        e = authz(c, bucket, key, ACT_PUT_OBJECT_RETENTION);
        if (e != S3_OK) return e;
    }
    if (lh) {
        if (ieq_lit(*lh, "ON")) c->lock_new.legal_hold = 1;
        else if (!ieq_lit(*lh, "OFF")) return S3_ERR_INVALID_ARGUMENT;
        s3_err_t e = authz(c, bucket, key, ACT_PUT_OBJECT_LEGAL_HOLD);
        if (e != S3_OK) return e;
    }
    c->lock_pending = 1;
    return S3_OK;
}

/* ---- Request classification (S0 + F2) -------------------------------
 *
 * Every request is mapped to exactly one S3 operation from its method,
 * path shape and query *subresource*. Query parameters fall in three
 * groups:
 *
 *   - subresources this server implements: they select the operation;
 *   - modifiers of a plain operation (response-*, X-Amz-*, list params,
 *     uploadId/partNumber, x-id): they never change which operation runs;
 *   - every other recognised S3 subresource name: 501 NotImplemented.
 *
 * The last group is the S0 fix: before, "PUT /b/k?tagging" fell through
 * to a plain PUT and overwrote the object with the XML body, and
 * "DELETE /b/k?versionId=…" deleted the current object. Unknown
 * parameters that are not S3 subresource names (cache busters and the
 * like) are ignored, as S3 does. */

static const char *const KNOWN_SUBRESOURCES[] = {
    "accelerate", "acl", "analytics", "attributes", "cors", "delete",
    "encryption", "intelligent-tiering", "inventory", "legal-hold",
    "lifecycle", "location", "logging", "metrics", "notification",
    "object-lock", "ownershipControls", "policy", "policyStatus",
    "publicAccessBlock", "replication", "requestPayment", "restore",
    "retention", "select", "select-type", "tagging", "torrent", "uploads",
    "versioning", "versions", "website", "renameObject", "session",
    "metadataTable", "partNumber", "uploadId", "versionId",
};

static int is_known_subresource(s3_str_t k) {
    for (size_t i = 0; i < sizeof(KNOWN_SUBRESOURCES) / sizeof(*KNOWN_SUBRESOURCES); i++)
        if (s3_str_eq_lit(k, KNOWN_SUBRESOURCES[i])) return 1;
    return 0;
}

/* The single subresource present among `handled` (names this code path
 * understands), or the first unhandled recognised subresource. Returns
 * NULL if none at all. *unhandled_out is set when an unhandled one is
 * present (which wins: an ambiguous combination is refused). */
static const char *pick_subresource(const conn_t *c, const char *const *handled,
                                    int *unhandled_out) {
    const char *found = NULL;
    *unhandled_out = 0;
    for (size_t i = 0; i < c->req.n_qp; i++) {
        s3_str_t k = c->req.qp[i].k;
        if (!is_known_subresource(k)) continue;
        int ok = 0;
        for (size_t h = 0; handled[h]; h++) {
            if (s3_str_eq_lit(k, handled[h])) {
                ok = 1;
                if (!found) found = handled[h];
                else if (strcmp(found, handled[h]) != 0) *unhandled_out = 1;
                break;
            }
        }
        if (!ok) *unhandled_out = 1;
    }
    return found;
}

static s3_action_t classify_service(const conn_t *c, s3_err_t *err) {
    if (method_is(c, "GET")) return ACT_LIST_BUCKETS;
    *err = S3_ERR_METHOD_NOT_ALLOWED;
    return ACT_NONE;
}

static s3_action_t classify_bucket(const conn_t *c, s3_err_t *err) {
    static const char *const handled[] = {
        "acl", "location", "versioning", "uploads", "delete", "cors",
        "lifecycle", "website", "versions", "policy", "object-lock", NULL
    };
    int unhandled;
    const char *sub = pick_subresource(c, handled, &unhandled);
    if (unhandled) { *err = S3_ERR_NOT_IMPLEMENTED; return ACT_NONE; }
    int get = method_is(c, "GET"), put = method_is(c, "PUT");
    int del = method_is(c, "DELETE"), post = method_is(c, "POST");
    int head = method_is(c, "HEAD");

    if (!sub) {
        if (get)  return ACT_LIST_OBJECTS;
        if (put)  return ACT_CREATE_BUCKET;
        if (del)  return ACT_DELETE_BUCKET;
        if (head) return ACT_HEAD_BUCKET;
    } else if (!strcmp(sub, "acl")) {
        if (get) return ACT_GET_BUCKET_ACL;
        if (put) return ACT_PUT_BUCKET_ACL;
    } else if (!strcmp(sub, "location")) {
        if (get) return ACT_GET_BUCKET_LOCATION;
    } else if (!strcmp(sub, "versioning")) {
        if (get) return ACT_GET_BUCKET_VERSIONING;
        if (put) return ACT_PUT_BUCKET_VERSIONING;
    } else if (!strcmp(sub, "versions")) {
        if (get) return ACT_LIST_OBJECT_VERSIONS;
    } else if (!strcmp(sub, "uploads")) {
        if (get) return ACT_LIST_MPU_UPLOADS;
    } else if (!strcmp(sub, "delete")) {
        if (post) return ACT_DELETE_OBJECTS;
    } else if (!strcmp(sub, "cors")) {
        if (get) return ACT_GET_BUCKET_CORS;
        if (put) return ACT_PUT_BUCKET_CORS;
        if (del) return ACT_DELETE_BUCKET_CORS;
    } else if (!strcmp(sub, "lifecycle")) {
        if (get) return ACT_GET_BUCKET_LIFECYCLE;
        if (put) return ACT_PUT_BUCKET_LIFECYCLE;
        if (del) return ACT_DELETE_BUCKET_LIFECYCLE;
    } else if (!strcmp(sub, "object-lock")) {
        if (get) return ACT_GET_BUCKET_OBJECT_LOCK;
        if (put) return ACT_PUT_BUCKET_OBJECT_LOCK;
    } else if (!strcmp(sub, "policy")) {
        if (get) return ACT_GET_BUCKET_POLICY;
        if (put) return ACT_PUT_BUCKET_POLICY;
        if (del) return ACT_DELETE_BUCKET_POLICY;
    } else if (!strcmp(sub, "website")) {
        if (get) return ACT_GET_BUCKET_WEBSITE;
        if (put) return ACT_PUT_BUCKET_WEBSITE;
        if (del) return ACT_DELETE_BUCKET_WEBSITE;
    }
    *err = S3_ERR_METHOD_NOT_ALLOWED;
    return ACT_NONE;
}

static s3_action_t classify_object(const conn_t *c, s3_err_t *err) {
    static const char *const handled[] = {
        "acl", "uploads", "uploadId", "partNumber", "retention", "legal-hold", NULL
    };
    int get = method_is(c, "GET"), put = method_is(c, "PUT");
    int del = method_is(c, "DELETE"), post = method_is(c, "POST");
    int head = method_is(c, "HEAD");
    int has_upload_id = q_has(c, "uploadId");
    int has_part = q_has(c, "partNumber");

    /* uploadId + partNumber is one subresource pair, not two. */
    int unhandled = 0;
    const char *sub = NULL;
    for (size_t i = 0; i < c->req.n_qp; i++) {
        s3_str_t k = c->req.qp[i].k;
        if (!is_known_subresource(k)) continue;
        if (s3_str_eq_lit(k, "uploadId") || s3_str_eq_lit(k, "partNumber"))
            continue;
        /* versionId modifies GET/HEAD/DELETE (and ?acl etc.); a PUT can't
         * target a version. */
        if (s3_str_eq_lit(k, "versionId")) {
            if ((put && !q_has(c, "retention") && !q_has(c, "legal-hold")) || post) {
                *err = S3_ERR_INVALID_ARGUMENT; return ACT_NONE;
            }
            continue;
        }
        int ok = 0;
        for (size_t h = 0; handled[h]; h++)
            if (s3_str_eq_lit(k, handled[h])) { ok = 1; break; }
        if (!ok || sub) { unhandled = 1; break; }
        sub = s3_str_eq_lit(k, "acl") ? "acl" : s3_str_eq_lit(k, "retention") ? "retention"
            : s3_str_eq_lit(k, "legal-hold") ? "legal-hold" : "uploads";
    }
    if (unhandled) { *err = S3_ERR_NOT_IMPLEMENTED; return ACT_NONE; }

    if (sub && (has_upload_id || has_part)) {
        *err = S3_ERR_INVALID_REQUEST; return ACT_NONE;
    }
    if (sub && !strcmp(sub, "acl")) {
        if (get) return ACT_GET_OBJECT_ACL;
        if (put) return ACT_PUT_OBJECT_ACL;
    } else if (sub && !strcmp(sub, "retention")) {
        if (get) return ACT_GET_OBJECT_RETENTION;
        if (put) return ACT_PUT_OBJECT_RETENTION;
    } else if (sub && !strcmp(sub, "legal-hold")) {
        if (get) return ACT_GET_OBJECT_LEGAL_HOLD;
        if (put) return ACT_PUT_OBJECT_LEGAL_HOLD;
    } else if (sub) {   /* uploads */
        if (post) return ACT_MPU_CREATE;
    } else if (has_upload_id) {
        if (put && has_part) {
            /* UploadPartCopy is not implemented: refuse rather than
             * store the (empty) request body as the part. */
            if (hdr_get(c, "x-amz-copy-source")) {
                *err = S3_ERR_NOT_IMPLEMENTED; return ACT_NONE;
            }
            return ACT_MPU_UPLOAD_PART;
        }
        if (post && !has_part) return ACT_MPU_COMPLETE;
        if (del && !has_part)  return ACT_MPU_ABORT;
        if (get && !has_part)  { *err = S3_ERR_NOT_IMPLEMENTED; return ACT_NONE; }
        *err = S3_ERR_INVALID_REQUEST; return ACT_NONE;
    } else if (has_part) {
        /* GetObject/HeadObject ?partNumber=N: only part 1 of a
         * single-part object is the whole object; anything else would
         * silently return the wrong bytes. */
        if ((get || head) && s3_str_eq_lit(q_val(c, "partNumber"), "1"))
            return get ? ACT_GET_OBJECT : ACT_HEAD_OBJECT;
        *err = (get || head) ? S3_ERR_NOT_IMPLEMENTED : S3_ERR_INVALID_REQUEST;
        return ACT_NONE;
    } else {
        if (get)  return ACT_GET_OBJECT;
        if (head) return ACT_HEAD_OBJECT;
        if (put)  return hdr_get(c, "x-amz-copy-source") ? ACT_COPY_OBJECT
                                                         : ACT_PUT_OBJECT;
        if (del)  return ACT_DELETE_OBJECT;
    }
    *err = S3_ERR_METHOD_NOT_ALLOWED;
    return ACT_NONE;
}

/* Classify the current request. Exposed for tests. */
s3_action_t route_classify(const conn_t *c, s3_str_t bucket, s3_str_t key,
                           s3_err_t *err) {
    *err = S3_OK;
    if (bucket.n == 0) return classify_service(c, err);
    if (key.n == 0)    return classify_bucket(c, err);
    return classify_object(c, err);
}

/* Parse ?uploadId into a 33-byte buffer. 0 ok, -1 malformed. */
static int parse_upload_id(const conn_t *c, char out[33]) {
    s3_str_t v = q_val(c, "uploadId");
    if (v.n != 32) return -1;
    for (size_t i = 0; i < 32; i++) {
        char ch = v.p[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')
              || (ch >= 'A' && ch <= 'F'))) return -1;
    }
    memcpy(out, v.p, 32);
    out[32] = '\0';
    return 0;
}

int route_dispatch_headers(conn_t *c) {
    scratch_reset(c);
    if (c->is_web) return web_dispatch(c);

    /* Health check — handled on the raw path before any bucket/key routing. */
    if (c->req.path.n == 8 && memcmp(c->req.path.p, "/_health", 8) == 0) {
        if (!method_is(c, "GET") && !method_is(c, "HEAD"))
            return rsp_build_s3_error(c, S3_ERR_METHOD_NOT_ALLOWED,
                                      c->req.path, NULL);
        return rsp_build_health(c);
    }

    /* Decode path into bucket + key spans. */
    char *path_scratch = scratch_alloc(c, c->req.path.n);
    if (!path_scratch) {
        return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    }
    s3_str_t bucket, key;
    if (parse_path(c->req.path, path_scratch, c->req.path.n, &bucket, &key) < 0) {
        return rsp_build_s3_error(c, S3_ERR_INVALID_REQUEST, c->req.path, NULL);
    }

    if (method_is(c, "OPTIONS")) return handle_preflight(c, bucket);

    s3_err_t ce;
    s3_action_t act = route_classify(c, bucket, key, &ce);
    c->req.act = (int)act;
    if (act == ACT_NONE)
        return rsp_build_s3_error(c, ce, c->req.path, NULL);

    s3_err_t ae = authz(c, bucket, key, act);
    if (ae != S3_OK && ae != S3_ERR_NO_SUCH_BUCKET)
        return rsp_build_s3_error(c, ae, c->req.path, NULL);

    if (bucket.n == 0) return handle_service(c);
    if (key.n == 0)    return handle_bucket(c, bucket, act);

    char upload_id_buf[33] = {0};
    switch (act) {
    case ACT_GET_OBJECT_ACL: {
        s3_obj_meta_t m;
        s3_err_t e = store_head(c->store, bucket, key, &m);
        if (e != S3_OK) return rsp_build_s3_error(c, e, c->req.path, NULL);
        return rsp_build_acl(c);
    }
    case ACT_PUT_OBJECT_ACL:
        return rsp_build_status(c, 200, "OK");

    case ACT_GET_OBJECT_RETENTION:  return lock_get(c, bucket, key, 0);
    case ACT_GET_OBJECT_LEGAL_HOLD: return lock_get(c, bucket, key, 1);
    case ACT_PUT_OBJECT_RETENTION:
    case ACT_PUT_OBJECT_LEGAL_HOLD:
        c->cfg_key = key;
        return cfg_put_begin(c, bucket, act);

    case ACT_MPU_CREATE:
        return handle_mpu_initiate(c, bucket, key);

    case ACT_MPU_COMPLETE:
    case ACT_MPU_ABORT:
    case ACT_MPU_UPLOAD_PART:
        if (parse_upload_id(c, upload_id_buf) < 0)
            return rsp_build_s3_error(c, S3_ERR_NO_SUCH_UPLOAD, c->req.path, NULL);
        if (act == ACT_MPU_ABORT)
            return handle_mpu_abort(c, bucket, key, upload_id_buf);
        if (act == ACT_MPU_COMPLETE) {
            c->mpu_complete_pending = 1;
            c->mpu_bucket = bucket;          /* points into req_scratch */
            c->mpu_key    = key;
            memcpy(c->mpu_upload_id, upload_id_buf, 33);
            return handle_mpu_complete_begin(c);
        }
        {
            s3_str_t v = q_val(c, "partNumber");
            int pn = 0;
            for (size_t i = 0; i < v.n; i++) {
                char ch = v.p[i];
                if (ch < '0' || ch > '9') { pn = 0; break; }
                pn = pn * 10 + (ch - '0');
                if (pn > 10000) { pn = 0; break; }
            }
            if (pn < 1)
                return rsp_build_s3_error(c, S3_ERR_INVALID_ARGUMENT,
                                          c->req.path, NULL);
            return handle_mpu_upload_part_begin(c, bucket, key, pn,
                                                upload_id_buf);
        }

    case ACT_COPY_OBJECT:
        /* Runs at message-complete (after any body is verified),
         * like every other request that needs an iopool job. */
        c->copy_pending = 1;
        c->copy_bucket  = bucket;   /* points into req_scratch */
        c->copy_key     = key;
        return 0;

    case ACT_PUT_OBJECT: {
        s3_err_t le = lock_headers_begin(c, bucket, key);
        if (le != S3_OK) return rsp_build_s3_error(c, le, c->req.path, NULL);
        return handle_object_put_begin(c, bucket, key);
    }
    case ACT_GET_OBJECT:    return handle_object_get(c, bucket, key, 0);
    case ACT_HEAD_OBJECT:   return handle_object_get(c, bucket, key, 1);
    case ACT_DELETE_OBJECT: return handle_object_delete(c, bucket, key);
    default:
        return rsp_build_s3_error(c, S3_ERR_NOT_IMPLEMENTED, c->req.path, NULL);
    }
}

int route_dispatch_body(conn_t *c, const char *data, size_t len) {
    if (c->put_writer) {
        s3_err_t e = store_put_write(c->put_writer, data, len);
        if (e != S3_OK) {
            store_put_abort(c->put_writer);
            c->put_writer = NULL;
            /* Build error response now; further body bytes will be
             * absorbed by llhttp but ignored. */
            return rsp_build_s3_error(c, e, c->req.path, NULL);
        }
        return 0;
    }
    /* If a handler asked us to buffer the body (e.g. CompleteMultipartUpload
     * needs the XML body parsed before commit), accumulate into req_body_buf
     * up to req_body_cap. Anything beyond the cap is rejected as
     * EntityTooLarge — but we only check after the body is complete to keep
     * this path simple; cap should be set generously. */
    if (c->req_body_buf && c->req_body_cap > 0) {
        if (c->req_body_len + len > c->req_body_cap) {
            /* Truncate to cap and remember we overflowed. */
            size_t take = c->req_body_cap - c->req_body_len;
            if (take > 0) {
                memcpy(c->req_body_buf + c->req_body_len, data, take);
                c->req_body_len += take;
            }
            /* Mark overflow by setting len > cap (we'll detect at complete). */
            c->req_body_len = c->req_body_cap + 1;
            return 0;
        }
        memcpy(c->req_body_buf + c->req_body_len, data, len);
        c->req_body_len += len;
        return 0;
    }
    /* If no writer and no buffer, body bytes are simply discarded
     * (e.g. on a method we'd already errored on; or a body sent on GET,
     * which we ignore). */
    return 0;
}

int route_dispatch_complete(conn_t *c) {
    if (c->put_writer) {
        if (c->mpu_is_part_upload) {
            return handle_mpu_part_complete(c);
        }
        return handle_object_put_complete(c);
    }
    if (c->mpu_complete_pending) {
        c->mpu_complete_pending = 0;
        return handle_mpu_complete_finish(c, c->mpu_bucket, c->mpu_key,
                                          c->mpu_upload_id);
    }
    if (c->copy_pending) {
        c->copy_pending = 0;
        return handle_object_copy(c, c->copy_bucket, c->copy_key);
    }
    if (c->delete_pending) {
        c->delete_pending = 0;
        return handle_bulk_delete_finish(c, c->delete_bucket);
    }
    if (c->cfg_act) return cfg_put_finish(c);
    /* Non-streaming requests already built their response in
     * route_dispatch_headers. Nothing more to do here. */
    return 0;
}

int route_dispatch_send_body(conn_t *c) {
    if (!c->get_reader) return 0;
    /* Send up to a chunk per call so we don't block too long. */
    ssize_t n = store_get_sendfile(c->get_reader, c->fd, 1 << 20);  /* 1 MiB */
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 1;
        LOG_W("sendfile fd=%d: %s", c->fd, strerror(errno));
        store_get_close(c->get_reader);
        c->get_reader = NULL;
        return -1;
    }
    if (n > 0) c->bytes_out_body += (uint64_t)n;
    if (n == 0) {
        /* EOF — body fully sent. */
        store_get_close(c->get_reader);
        c->get_reader = NULL;
        return 0;
    }
    return 1;  /* more bytes remaining */
}

/* ===================================================================== */
/* Auth-hook helper                                                       */
/* ===================================================================== */

/* Build an S3 error response immediately. Used from the SigV4 hookpoint
 * in cb_on_headers_complete to short-circuit dispatch. The caller has
 * NOT set up any handler-owned state (no writer, no reader), so this
 * is essentially a wrapper around rsp_build_s3_error that also resets
 * the per-request scratch arena. */
int route_build_error(conn_t *c, s3_err_t err) {
    /* Make sure scratch is fresh (in case the auth hook fires before
     * the route layer would normally call scratch_reset). */
    c->req_scratch_used = 0;
    return rsp_build_s3_error(c, err, c->req.path, NULL);
}
