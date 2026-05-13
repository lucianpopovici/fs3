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
#include "conn.h"
#include "log.h"
#include "response.h"
#include "store.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
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

/* Extract a query parameter value. Returns 1 if found, 0 if not.
 * The returned span points into a caller-owned scratch buffer that
 * must hold at least query.n bytes; the value is percent-decoded. */
static int query_param(s3_str_t query, const char *name,
                       char *scratch, size_t cap, s3_str_t *out) {
    size_t name_len = strlen(name);
    size_t i = 0;
    while (i < query.n) {
        size_t j = i;
        while (j < query.n && query.p[j] != '=' && query.p[j] != '&') j++;
        size_t key_n = j - i;
        if (key_n == name_len && memcmp(query.p + i, name, name_len) == 0) {
            /* Match. Find value span. */
            if (j < query.n && query.p[j] == '=') {
                size_t v0 = j + 1;
                size_t v1 = v0;
                while (v1 < query.n && query.p[v1] != '&') v1++;
                size_t vn = v1 - v0;
                if (vn > cap) vn = cap;
                memcpy(scratch, query.p + v0, vn);
                vn = pct_decode(scratch, vn);
                *out = (s3_str_t){ scratch, vn };
            } else {
                *out = S3_STR_NULL;
            }
            return 1;
        }
        i = j;
        while (i < query.n && query.p[i] != '&') i++;
        if (i < query.n) i++;  /* skip '&' */
    }
    return 0;
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

static int handle_service(conn_t *c) {
    /* Only GET is meaningful; everything else is method-not-allowed. */
    if (!method_is(c, "GET")) {
        return rsp_build_s3_error(c, S3_ERR_METHOD_NOT_ALLOWED,
                                  S3_STR_LIT("/"), NULL);
    }
    /* GET / → ListAllMyBuckets */
    s3_bucket_info_t *buckets = NULL;
    size_t n_buckets = 0;
    s3_err_t e = store_list_buckets(c->store, &buckets, &n_buckets);
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, S3_STR_LIT("/"), NULL);
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
                              char ***keys_out, size_t *n_out, int *quiet_out) {
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

    char **keys = NULL;
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
                    keys = nk; cap = nc;
                }
                keys[n_keys++] = k;
            }
        }
        pos = obj_end + sizeof(obj_close) - 1;
    }

    *keys_out = keys;
    *n_out    = n_keys;
    return 0;
oom:
    for (size_t i = 0; i < n_keys; i++) free(keys[i]);
    free(keys);
    return -1;
}

static int handle_bulk_delete_finish(conn_t *c, s3_str_t bucket) {
    if (c->req_body_len > c->req_body_cap) {
        return rsp_build_s3_error(c, S3_ERR_ENTITY_TOO_LARGE, c->req.path, NULL);
    }
    char **keys = NULL;
    size_t n_keys = 0;
    int quiet = 0;
    if (parse_delete_body(c->req_body_buf, c->req_body_len,
                          &keys, &n_keys, &quiet) < 0) {
        return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    }
    if (n_keys == 0) {
        return rsp_build_s3_error(c, S3_ERR_MALFORMED_XML, c->req.path, NULL);
    }
    const char **deleted_keys = malloc(n_keys * sizeof(*deleted_keys));
    const char **error_keys   = malloc(n_keys * sizeof(*error_keys));
    size_t n_deleted = 0, n_errors = 0;
    if (!deleted_keys || !error_keys) {
        for (size_t i = 0; i < n_keys; i++) free(keys[i]);
        free(keys); free(deleted_keys); free(error_keys);
        return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    }
    for (size_t i = 0; i < n_keys; i++) {
        s3_str_t k = { keys[i], strlen(keys[i]) };
        s3_err_t e = store_delete(c->store, bucket, k);
        if (e == S3_OK) {
            if (!quiet) deleted_keys[n_deleted++] = keys[i];
        } else {
            error_keys[n_errors++] = keys[i];
        }
    }
    int rc = rsp_build_delete_objects(c, deleted_keys, n_deleted,
                                       error_keys, n_errors);
    for (size_t i = 0; i < n_keys; i++) free(keys[i]);
    free(keys); free(deleted_keys); free(error_keys);
    return rc;
}

/* ===================================================================== */
/* Bucket-level (PATH = "/bucket" or "/bucket/")                          */
/* ===================================================================== */

static int handle_bucket(conn_t *c, s3_str_t bucket) {
    /* ?acl — GET returns ACL XML; PUT accepts and discards the body. */
    if (c->req.query.n > 0) {
        char *qb = scratch_alloc(c, c->req.query.n + 1);
        s3_str_t v;
        if (qb && query_param(c->req.query, "acl", qb, c->req.query.n, &v)) {
            if (!store_bucket_exists(c->store, bucket)) {
                return rsp_build_s3_error(c, S3_ERR_NO_SUCH_BUCKET,
                                          c->req.path, NULL);
            }
            if (method_is(c, "GET"))  return rsp_build_acl(c);
            if (method_is(c, "PUT"))  return rsp_build_status(c, 200, "OK");
            return rsp_build_s3_error(c, S3_ERR_METHOD_NOT_ALLOWED,
                                      c->req.path, NULL);
        }
    }

    if (method_is(c, "PUT")) {
        s3_err_t e = store_bucket_create(c->store, bucket);
        if (e == S3_OK) {
            char loc[1100];
            int n = snprintf(loc, sizeof(loc),
                             "Location: /" S3_STR_FMT "\r\n",
                             S3_STR_ARG(bucket));
            (void)n;
            return rsp_build_status_with_headers(c, 200, "OK", loc);
        }
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }

    if (method_is(c, "DELETE")) {
        s3_err_t e = store_bucket_delete(c->store, bucket);
        if (e == S3_OK) return rsp_build_status(c, 204, "No Content");
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }

    if (method_is(c, "HEAD")) {
        if (!store_bucket_exists(c->store, bucket)) {
            return rsp_build_s3_error(c, S3_ERR_NO_SUCH_BUCKET, c->req.path, NULL);
        }
        return rsp_build_status(c, 200, "OK");
    }

    if (method_is(c, "POST")) {
        if (c->req.query.n > 0) {
            char *qb = scratch_alloc(c, c->req.query.n + 1);
            s3_str_t v;
            if (qb && query_param(c->req.query, "delete",
                                  qb, c->req.query.n, &v)) {
                return handle_bulk_delete_begin(c, bucket);
            }
        }
        return rsp_build_s3_error(c, S3_ERR_METHOD_NOT_ALLOWED,
                                  c->req.path, NULL);
    }

    if (method_is(c, "GET")) {
        /* Check for bucket subresources before falling through to listing. */
        if (c->req.query.n > 0) {
            char *qb_loc = scratch_alloc(c, c->req.query.n + 1);
            s3_str_t v_loc;
            if (qb_loc && query_param(c->req.query, "location",
                                      qb_loc, c->req.query.n, &v_loc)) {
                if (!store_bucket_exists(c->store, bucket)) {
                    return rsp_build_s3_error(c, S3_ERR_NO_SUCH_BUCKET,
                                              c->req.path, NULL);
                }
                return rsp_build_bucket_location(c);
            }
            char *qb_ver = scratch_alloc(c, c->req.query.n + 1);
            s3_str_t v_ver;
            if (qb_ver && query_param(c->req.query, "versioning",
                                      qb_ver, c->req.query.n, &v_ver)) {
                if (!store_bucket_exists(c->store, bucket)) {
                    return rsp_build_s3_error(c, S3_ERR_NO_SUCH_BUCKET,
                                              c->req.path, NULL);
                }
                return rsp_build_bucket_versioning(c);
            }
        }

        /* Detect "?uploads" — bucket-level subresource for
         * ListMultipartUploads. */
        if (c->req.query.n > 0) {
            char *qb_u = scratch_alloc(c, c->req.query.n + 1);
            s3_str_t v_u;
            if (qb_u && query_param(c->req.query, "uploads",
                                    qb_u, c->req.query.n, &v_u)) {
                /* Optional prefix filter. */
                s3_str_t prefix = S3_STR_NULL;
                char *qb_p = scratch_alloc(c, c->req.query.n + 1);
                if (qb_p) {
                    s3_str_t pv;
                    if (query_param(c->req.query, "prefix",
                                    qb_p, c->req.query.n, &pv)) {
                        prefix = pv;
                    }
                }
                s3_mpu_info_t *ups = NULL;
                size_t n_ups = 0;
                s3_err_t e = store_list_mpu_uploads(c->store, bucket,
                                                    prefix, &ups, &n_ups);
                if (e != S3_OK) {
                    return rsp_build_s3_error(c, e, c->req.path, NULL);
                }
                int rc = rsp_build_list_mpu_uploads(c, bucket, prefix,
                                                    ups, n_ups);
                store_mpu_uploads_free(ups, n_ups);
                return rc;
            }
        }

        /* List objects. Parse query parameters. */
        s3_list_opts_t opts = { 0 };
        char *qb = scratch_alloc(c, c->req.query.n + 1);
        if (qb && c->req.query.n > 0) {
            s3_str_t v;
            if (query_param(c->req.query, "prefix", qb, c->req.query.n, &v))
                opts.prefix = v;
            char *qb2 = scratch_alloc(c, c->req.query.n + 1);
            if (qb2 && query_param(c->req.query, "delimiter",
                                   qb2, c->req.query.n, &v))
                opts.delimiter = v;
            char *qb3 = scratch_alloc(c, c->req.query.n + 1);
            if (qb3 && query_param(c->req.query, "marker",
                                   qb3, c->req.query.n, &v))
                opts.marker = v;
            char *qb4 = scratch_alloc(c, c->req.query.n + 1);
            if (qb4 && query_param(c->req.query, "max-keys",
                                   qb4, c->req.query.n, &v)) {
                /* parse integer */
                int mk = 0;
                for (size_t i = 0; i < v.n; i++) {
                    if (v.p[i] < '0' || v.p[i] > '9') { mk = 0; break; }
                    mk = mk * 10 + (v.p[i] - '0');
                    if (mk > 1000) { mk = 1000; break; }
                }
                opts.max_keys = mk;
            }
        }

        s3_lister_t *l;
        s3_err_t e = store_list_begin(c->store, bucket, &opts, &l);
        if (e != S3_OK) {
            return rsp_build_s3_error(c, e, c->req.path, NULL);
        }
        return rsp_build_list_bucket(c, bucket, &opts, l);
    }

    return rsp_build_s3_error(c, S3_ERR_METHOD_NOT_ALLOWED, c->req.path, NULL);
}

/* ===================================================================== */
/* Object-level (PATH = "/bucket/key...")                                 */
/* ===================================================================== */

/* PUT: open a writer and stream body bytes. Response built at message
 * complete time. */
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

static int handle_object_put_complete(conn_t *c) {
    if (!c->put_writer) return -1;  /* programming error */
    s3_obj_meta_t m;
    s3_err_t e = store_put_commit(c->put_writer, &m);
    c->put_writer = NULL;
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }
    /* 200 OK with ETag header. */
    char etag[35]; rsp_format_etag(m.etag, etag);
    char extra[80];
    snprintf(extra, sizeof(extra), "ETag: %s\r\n", etag);
    return rsp_build_status_with_headers(c, 200, "OK", extra);
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
    s3_err_t e = store_get_open(c->store, bucket, key, &r, &m);
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }

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

    /* Full GET / HEAD */
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
    s3_err_t e = store_delete(c->store, bucket, key);
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }
    return rsp_build_status(c, 204, "No Content");
}

/* ===================================================================== */
/* Object copy (PUT with x-amz-copy-source header)                       */
/* ===================================================================== */

static int handle_object_copy(conn_t *c, s3_str_t dst_bucket, s3_str_t dst_key) {
    const s3_str_t *src_hdr = hdr_get(c, "x-amz-copy-source");

    /* Decode the source path. Use malloc — it may be up to ~1100 bytes and
     * we don't want to exhaust the per-request scratch arena. */
    char *src_buf = malloc(src_hdr->n + 1);
    if (!src_buf) return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    memcpy(src_buf, src_hdr->p, src_hdr->n);
    size_t src_n = pct_decode(src_buf, src_hdr->n);

    /* Strip optional versionId query string (we ignore versions). */
    char *qmark = memchr(src_buf, '?', src_n);
    if (qmark) src_n = (size_t)(qmark - src_buf);

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

    /* Open source. */
    s3_reader_t *reader = NULL;
    s3_obj_meta_t src_meta;
    s3_err_t e = store_get_open(c->store, src_bucket, src_key, &reader, &src_meta);
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

    /* Stream. */
    char xbuf[8192];
    int stream_ok = 1;
    for (;;) {
        ssize_t n = store_get_read(reader, xbuf, sizeof(xbuf));
        if (n == 0) break;
        if (n < 0 || store_put_write(writer, xbuf, (size_t)n) != S3_OK) {
            stream_ok = 0;
            break;
        }
    }
    store_get_close(reader);

    if (!stream_ok) {
        store_put_abort(writer);
        return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    }

    s3_obj_meta_t dst_meta;
    e = store_put_commit(writer, &dst_meta);
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }
    return rsp_build_copy_object(c, &dst_meta);
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

    char upload_id[33];
    s3_err_t e = store_mpu_create(c->store, bucket, key,
                                   ct_hdr ? ct_buf : NULL, upload_id);
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, c->req.path, NULL);
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
    if (!c->put_writer) return -1;
    char etag_hex[33];
    s3_err_t e = store_mpu_part_commit(c->put_writer, etag_hex);
    c->put_writer = NULL;
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }
    char extra[80];
    snprintf(extra, sizeof(extra), "ETag: \"%s\"\r\n", etag_hex);
    return rsp_build_status_with_headers(c, 200, "OK", extra);
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
    return (long)((size_t)(q - body) + sizeof(close_tag) - 1);
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

    char etag[40];
    s3_obj_meta_t meta;
    s3_err_t e = store_mpu_complete(c->store, bucket, key,
                                     upload_id, parts, parts_n,
                                     etag, &meta);
    free(parts);
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }
    return rsp_build_complete_mpu(c, bucket, key, etag);
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

int route_dispatch_headers(conn_t *c) {
    scratch_reset(c);

    /* Decode path into bucket + key spans. */
    char *path_scratch = scratch_alloc(c, c->req.path.n);
    if (!path_scratch) {
        return rsp_build_s3_error(c, S3_ERR_INTERNAL, c->req.path, NULL);
    }
    s3_str_t bucket, key;
    if (parse_path(c->req.path, path_scratch, c->req.path.n, &bucket, &key) < 0) {
        return rsp_build_s3_error(c, S3_ERR_INVALID_REQUEST, c->req.path, NULL);
    }

    /* Service-level: "/" */
    if (bucket.n == 0) {
        return handle_service(c);
    }

    /* Bucket-level: "/bucket" or "/bucket/" with no key */
    if (key.n == 0) {
        return handle_bucket(c, bucket);
    }

    /* Object-level: "/bucket/key" */

    /* Object-level ?acl: GET returns ACL XML; PUT accepts and ignores body.
     * Both require the object to exist for GET. PUT is a no-op for fs3
     * (no real ACL model). Must be checked before MPU params to short-circuit
     * ambiguous query strings like "?acl&uploadId=...". */
    if (c->req.query.n > 0) {
        char *qb_acl = scratch_alloc(c, c->req.query.n + 1);
        s3_str_t v_acl;
        if (qb_acl && query_param(c->req.query, "acl",
                                  qb_acl, c->req.query.n, &v_acl)) {
            if (method_is(c, "GET")) {
                s3_obj_meta_t m;
                s3_err_t e = store_head(c->store, bucket, key, &m);
                if (e != S3_OK)
                    return rsp_build_s3_error(c, e, c->req.path, NULL);
                return rsp_build_acl(c);
            }
            if (method_is(c, "PUT")) return rsp_build_status(c, 200, "OK");
            return rsp_build_s3_error(c, S3_ERR_METHOD_NOT_ALLOWED,
                                      c->req.path, NULL);
        }
    }

    /* Multipart upload subresources are signalled by query parameters.
     * Decode them once into a scratch buffer; query_param mutates in place
     * during pct_decode, so each call needs a fresh buffer. */
    s3_str_t v_uploads = S3_STR_NULL;
    s3_str_t v_upload_id = S3_STR_NULL;
    s3_str_t v_part_number = S3_STR_NULL;
    int has_uploads = 0;       /* "?uploads" (no value) */
    int has_upload_id = 0;
    int has_part_number = 0;
    if (c->req.query.n > 0) {
        char *qb1 = scratch_alloc(c, c->req.query.n + 1);
        char *qb2 = scratch_alloc(c, c->req.query.n + 1);
        char *qb3 = scratch_alloc(c, c->req.query.n + 1);
        if (qb1 && query_param(c->req.query, "uploads",
                               qb1, c->req.query.n, &v_uploads)) {
            has_uploads = 1;
        }
        if (qb2 && query_param(c->req.query, "uploadId",
                               qb2, c->req.query.n, &v_upload_id)) {
            has_upload_id = 1;
        }
        if (qb3 && query_param(c->req.query, "partNumber",
                               qb3, c->req.query.n, &v_part_number)) {
            has_part_number = 1;
        }
    }

    /* Validate uploadId looks like 32 hex chars (matches what we generate). */
    char upload_id_buf[33] = {0};
    if (has_upload_id) {
        if (v_upload_id.n != 32) {
            return rsp_build_s3_error(c, S3_ERR_NO_SUCH_UPLOAD,
                                      c->req.path, NULL);
        }
        for (size_t i = 0; i < 32; i++) {
            char ch = v_upload_id.p[i];
            if (!((ch >= '0' && ch <= '9')
                  || (ch >= 'a' && ch <= 'f')
                  || (ch >= 'A' && ch <= 'F'))) {
                return rsp_build_s3_error(c, S3_ERR_NO_SUCH_UPLOAD,
                                          c->req.path, NULL);
            }
        }
        memcpy(upload_id_buf, v_upload_id.p, 32);
    }

    if (method_is(c, "POST") && has_uploads) {
        return handle_mpu_initiate(c, bucket, key);
    }
    if (method_is(c, "POST") && has_upload_id) {
        c->mpu_complete_pending = 1;
        c->mpu_bucket = bucket;          /* points into req_scratch */
        c->mpu_key    = key;
        memcpy(c->mpu_upload_id, upload_id_buf, 33);
        return handle_mpu_complete_begin(c);
    }
    if (method_is(c, "PUT") && has_upload_id && has_part_number) {
        /* Parse partNumber — must be a small positive integer. */
        int pn = 0;
        for (size_t i = 0; i < v_part_number.n; i++) {
            char ch = v_part_number.p[i];
            if (ch < '0' || ch > '9') { pn = 0; break; }
            pn = pn * 10 + (ch - '0');
            if (pn > 10000) { pn = 0; break; }
        }
        if (pn < 1) {
            return rsp_build_s3_error(c, S3_ERR_INVALID_ARGUMENT,
                                      c->req.path, NULL);
        }
        return handle_mpu_upload_part_begin(c, bucket, key,
                                             pn, upload_id_buf);
    }
    if (method_is(c, "DELETE") && has_upload_id) {
        return handle_mpu_abort(c, bucket, key, upload_id_buf);
    }

    if (method_is(c, "PUT")) {
        /* Server-side copy: PUT with x-amz-copy-source header. */
        if (hdr_get(c, "x-amz-copy-source")) {
            return handle_object_copy(c, bucket, key);
        }
        /* Streaming PUT: open writer, then accept body via on_body. */
        return handle_object_put_begin(c, bucket, key);
    }
    if (method_is(c, "GET"))    return handle_object_get(c, bucket, key, 0);
    if (method_is(c, "HEAD"))   return handle_object_get(c, bucket, key, 1);
    if (method_is(c, "DELETE")) return handle_object_delete(c, bucket, key);
    return rsp_build_s3_error(c, S3_ERR_METHOD_NOT_ALLOWED, c->req.path, NULL);
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
    if (c->delete_pending) {
        c->delete_pending = 0;
        return handle_bulk_delete_finish(c, c->delete_bucket);
    }
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
