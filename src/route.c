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
    /* TODO: ListAllMyBuckets. For now: 501. */
    return rsp_build_s3_error(c, S3_ERR_NOT_IMPLEMENTED, S3_STR_LIT("/"), NULL);
}

/* ===================================================================== */
/* Bucket-level (PATH = "/bucket" or "/bucket/")                          */
/* ===================================================================== */

static int handle_bucket(conn_t *c, s3_str_t bucket) {
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

    if (method_is(c, "GET")) {
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

static int handle_object_get(conn_t *c, s3_str_t bucket, s3_str_t key,
                             int head_only) {
    s3_reader_t *r;
    s3_obj_meta_t m;
    s3_err_t e = store_get_open(c->store, bucket, key, &r, &m);
    if (e != S3_OK) {
        return rsp_build_s3_error(c, e, c->req.path, NULL);
    }
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
    if (method_is(c, "PUT")) {
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
    }
    /* If no writer, body bytes are simply discarded (e.g. on a method
     * we'd already errored on; or a body sent on GET, which we ignore). */
    return 0;
}

int route_dispatch_complete(conn_t *c) {
    if (c->put_writer) {
        return handle_object_put_complete(c);
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
