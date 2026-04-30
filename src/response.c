/* src/response.c — HTTP response building helpers */

#include "response.h"
#include "log.h"
#include "xml_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ===================================================================== */
/* Time / etag formatting                                                */
/* ===================================================================== */

static const char *DAYS[]   = { "Sun","Mon","Tue","Wed","Thu","Fri","Sat" };
static const char *MONTHS[] = { "Jan","Feb","Mar","Apr","May","Jun",
                                "Jul","Aug","Sep","Oct","Nov","Dec" };

void rsp_format_rfc1123(uint64_t mtime_ms, char out[32]) {
    time_t t = (time_t)(mtime_ms / 1000);
    struct tm tm;
    gmtime_r(&t, &tm);
    int year = tm.tm_year + 1900;
    if (year < 0) year = 0;
    if (year > 9999) year = 9999;
    snprintf(out, 32, "%s, %02d %s %04d %02d:%02d:%02d GMT",
             DAYS[tm.tm_wday & 7], tm.tm_mday & 0x3F,
             MONTHS[tm.tm_mon & 0xF],
             year,
             tm.tm_hour & 0x1F, tm.tm_min & 0x3F, tm.tm_sec & 0x3F);
}

void rsp_format_iso8601(uint64_t mtime_ms, char out[32]) {
    time_t t = (time_t)(mtime_ms / 1000);
    unsigned ms = (unsigned)(mtime_ms % 1000);
    struct tm tm;
    gmtime_r(&t, &tm);
    int year = tm.tm_year + 1900;
    if (year < 0) year = 0;
    if (year > 9999) year = 9999;
    snprintf(out, 32, "%04d-%02d-%02dT%02d:%02d:%02d.%03uZ",
             year, (tm.tm_mon + 1) & 0xF, tm.tm_mday & 0x3F,
             tm.tm_hour & 0x1F, tm.tm_min & 0x3F, tm.tm_sec & 0x3F, ms);
}

void rsp_format_etag(const uint8_t etag[16], char out[35]) {
    static const char hex[] = "0123456789abcdef";
    out[0] = '"';
    for (int i = 0; i < 16; i++) {
        out[1 + i*2 + 0] = hex[etag[i] >> 4];
        out[1 + i*2 + 1] = hex[etag[i] & 0xF];
    }
    out[33] = '"';
    out[34] = '\0';
}

/* ===================================================================== */
/* S3 error code mapping                                                  */
/* ===================================================================== */

typedef struct {
    s3_err_t    err;
    int         http_status;
    const char *s3_code;
    const char *default_msg;
} err_entry_t;

static const err_entry_t ERR_TABLE[] = {
    { S3_OK,                            200, "OK",                       ""                                                  },
    { S3_ERR_NO_SUCH_BUCKET,            404, "NoSuchBucket",             "The specified bucket does not exist."              },
    { S3_ERR_NO_SUCH_KEY,               404, "NoSuchKey",                "The specified key does not exist."                 },
    { S3_ERR_NO_SUCH_UPLOAD,            404, "NoSuchUpload",             "The specified multipart upload does not exist."    },
    { S3_ERR_BUCKET_ALREADY_EXISTS,     409, "BucketAlreadyExists",      "The requested bucket name is already in use."      },
    { S3_ERR_BUCKET_NOT_EMPTY,          409, "BucketNotEmpty",           "The bucket you tried to delete is not empty."      },
    { S3_ERR_INVALID_ARGUMENT,          400, "InvalidArgument",          "Invalid argument."                                 },
    { S3_ERR_INVALID_BUCKET_NAME,       400, "InvalidBucketName",        "The specified bucket is not valid."                },
    { S3_ERR_INVALID_REQUEST,           400, "InvalidRequest",           "Invalid request."                                  },
    { S3_ERR_SIGNATURE_DOES_NOT_MATCH,  403, "SignatureDoesNotMatch",    "The request signature does not match."             },
    { S3_ERR_ACCESS_DENIED,             403, "AccessDenied",             "Access denied."                                    },
    { S3_ERR_REQUEST_TIME_TOO_SKEWED,   403, "RequestTimeTooSkewed",     "The difference between request time and server time is too large." },
    { S3_ERR_ENTITY_TOO_LARGE,          413, "EntityTooLarge",           "Your proposed upload exceeds the maximum allowed." },
    { S3_ERR_MISSING_CONTENT_LENGTH,    411, "MissingContentLength",     "Content-Length header is required."                },
    { S3_ERR_METHOD_NOT_ALLOWED,        405, "MethodNotAllowed",         "The specified method is not allowed."              },
    { S3_ERR_INTERNAL,                  500, "InternalError",            "We encountered an internal error."                 },
    { S3_ERR_NOT_IMPLEMENTED,           501, "NotImplemented",           "The requested functionality is not implemented."   },
};

static const err_entry_t *err_lookup(s3_err_t e) {
    for (size_t i = 0; i < sizeof(ERR_TABLE)/sizeof(ERR_TABLE[0]); i++) {
        if (ERR_TABLE[i].err == e) return &ERR_TABLE[i];
    }
    return &ERR_TABLE[0];
}

int rsp_status_for_err(s3_err_t err) { return err_lookup(err)->http_status; }
const char *rsp_code_for_err(s3_err_t err) { return err_lookup(err)->s3_code; }

/* ===================================================================== */
/* Status-only / headered responses                                       */
/* ===================================================================== */

int rsp_build_status(conn_t *c, int status, const char *reason) {
    return rsp_build_status_with_headers(c, status, reason, "");
}

int rsp_build_status_with_headers(conn_t *c, int status, const char *reason,
                                  const char *extra_headers) {
    int n = snprintf(c->wbuf, CONN_WBUF_SZ,
        "HTTP/1.1 %d %s\r\n"
        "Server: fs3/0.2\r\n"
        "Content-Length: 0\r\n"
        "Connection: %s\r\n"
        "%s"
        "\r\n",
        status, reason,
        c->req.keep_alive ? "keep-alive" : "close",
        extra_headers ? extra_headers : "");
    if (n < 0 || n >= CONN_WBUF_SZ) return -1;
    c->wlen = (size_t)n;
    c->wpos = 0;
    c->state = CST_WRITE_RESPONSE;
    return 0;
}

/* ===================================================================== */
/* GET/HEAD response head                                                 */
/* ===================================================================== */

int rsp_build_object_head(conn_t *c, const s3_obj_meta_t *m, int head_only) {
    char etag[35]; rsp_format_etag(m->etag, etag);
    char lm[32];   rsp_format_rfc1123(m->mtime_ms, lm);

    const char *ct = m->content_type[0] ? m->content_type : "application/octet-stream";

    int n = snprintf(c->wbuf, CONN_WBUF_SZ,
        "HTTP/1.1 200 OK\r\n"
        "Server: fs3/0.2\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %llu\r\n"
        "ETag: %s\r\n"
        "Last-Modified: %s\r\n"
        "Accept-Ranges: bytes\r\n"
        "Connection: %s\r\n"
        "\r\n",
        ct,
        (unsigned long long)m->size,
        etag,
        lm,
        c->req.keep_alive ? "keep-alive" : "close");
    (void)head_only;  /* HEAD path differs in body handling, not in headers */
    if (n < 0 || n >= CONN_WBUF_SZ) return -1;
    c->wlen = (size_t)n;
    c->wpos = 0;
    c->state = CST_WRITE_RESPONSE;
    return 0;
}

/* ===================================================================== */
/* XML helpers                                                            */
/* ===================================================================== */

/* Build an XMLNode child with text content. Returns NULL on OOM. */
static XMLNode *xml_text_child(XMLNode *parent, const char *name,
                               const char *value) {
    XMLNode *n = create_node(name);
    if (!n) return NULL;
    if (value && xml_set_content(n, value) < 0) { free_tree(n); return NULL; }
    if (add_child(parent, n) < 0) { free_tree(n); return NULL; }
    return n;
}

static XMLNode *xml_text_child_n(XMLNode *parent, const char *name,
                                 const char *value, size_t value_n) {
    XMLNode *n = create_node(name);
    if (!n) return NULL;
    if (value && xml_set_content_n(n, value, value_n) < 0) {
        free_tree(n); return NULL;
    }
    if (add_child(parent, n) < 0) { free_tree(n); return NULL; }
    return n;
}

/* Render XMLNode tree into a fresh malloc'd buffer with leading
 * <?xml ...?> declaration. *out_len is set; caller frees. */
static char *xml_render_with_decl(const XMLNode *root, size_t *out_len);

/* Growing buffer used by the callback below. */
struct rsp_grow_ctx { char *buf; size_t len, cap; };

static int rsp_xml_grow_cb(void *vctx, const char *data, size_t n) {
    struct rsp_grow_ctx *b = vctx;
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 256;
        while (nc < b->len + n + 1) nc *= 2;
        char *nb = realloc(b->buf, nc);
        if (!nb) return -1;
        b->buf = nb;
        b->cap = nc;
    }
    memcpy(b->buf + b->len, data, n);
    b->len += n;
    return 0;
}

static char *xml_render_with_decl(const XMLNode *root, size_t *out_len) {
    static const char decl[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    size_t dn = sizeof(decl) - 1;

    struct rsp_grow_ctx b = { malloc(256), 0, 256 };
    if (!b.buf) return NULL;
    memcpy(b.buf, decl, dn);
    b.len = dn;

    if (xml_serialize(root, rsp_xml_grow_cb, &b, 0) != 0) {
        free(b.buf); return NULL;
    }
    *out_len = b.len;
    return b.buf;
}

/* ===================================================================== */
/* Error response (S3 XML)                                                */
/* ===================================================================== */

int rsp_build_s3_error(conn_t *c, s3_err_t err, s3_str_t resource,
                       const char *request_id) {
    const err_entry_t *te = err_lookup(err);

    /* Build the XML body. */
    XMLNode *root = create_node("Error");
    if (!root) return -1;
    xml_text_child(root, "Code",      te->s3_code);
    xml_text_child(root, "Message",   te->default_msg);
    if (resource.n > 0) {
        xml_text_child_n(root, "Resource", resource.p, resource.n);
    }
    if (request_id) xml_text_child(root, "RequestId", request_id);

    size_t blen = 0;
    char *body = xml_render_with_decl(root, &blen);
    free_tree(root);
    if (!body) return -1;

    int keep = c->req.keep_alive && te->http_status < 500;

    int n = snprintf(c->wbuf, CONN_WBUF_SZ,
        "HTTP/1.1 %d %s\r\n"
        "Server: fs3/0.2\r\n"
        "Content-Type: application/xml\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "\r\n",
        te->http_status, te->s3_code,
        blen,
        keep ? "keep-alive" : "close");
    if (n < 0 || n >= CONN_WBUF_SZ) {
        free(body);
        return -1;
    }

    if ((size_t)n + blen <= CONN_WBUF_SZ) {
        memcpy(c->wbuf + n, body, blen);
        free(body);
        c->wlen = (size_t)n + blen;
    } else {
        c->wlen = (size_t)n;
        free(c->ext_body);
        c->ext_body = body;
        c->ext_body_len = blen;
        c->ext_body_pos = 0;
    }
    c->wpos = 0;
    c->req.keep_alive = keep;
    c->state = CST_WRITE_RESPONSE;
    return 0;
}

/* ===================================================================== */
/* ListBucketResult                                                       */
/* ===================================================================== */

int rsp_build_list_bucket(conn_t *c, s3_str_t bucket,
                          const s3_list_opts_t *opts, s3_lister_t *l) {
    XMLNode *root = create_node("ListBucketResult");
    if (!root) { store_list_close(l); return -1; }
    if (add_attr(root, "xmlns", "http://s3.amazonaws.com/doc/2006-03-01/") < 0) {
        free_tree(root); store_list_close(l); return -1;
    }

    xml_text_child_n(root, "Name", bucket.p, bucket.n);
    if (opts->prefix.n > 0) {
        xml_text_child_n(root, "Prefix", opts->prefix.p, opts->prefix.n);
    } else {
        xml_text_child(root, "Prefix", "");
    }
    if (opts->marker.n > 0) {
        xml_text_child_n(root, "Marker", opts->marker.p, opts->marker.n);
    }
    if (opts->delimiter.n > 0) {
        xml_text_child_n(root, "Delimiter",
                         opts->delimiter.p, opts->delimiter.n);
    }

    int max_keys = opts->max_keys > 0 ? opts->max_keys : 1000;
    char mkbuf[16]; snprintf(mkbuf, sizeof(mkbuf), "%d", max_keys);
    xml_text_child(root, "MaxKeys", mkbuf);

    /* Iterate the lister, appending Contents and CommonPrefixes nodes.
     * The lister enforces max_keys internally; we ask it whether
     * iteration stopped because of the cap (truncated) or because the
     * bucket was exhausted. */
    char last_key[1024]; size_t last_key_len = 0;

    for (;;) {
        s3_str_t k; s3_obj_meta_t m; int isp = 0;
        s3_err_t e = store_list_next(l, &k, &m, &isp);
        if (e != S3_OK) break;

        if (isp) {
            XMLNode *cp = create_node("CommonPrefixes");
            if (!cp || add_child(root, cp) < 0) {
                if (cp) free_tree(cp);
                free_tree(root); store_list_close(l); return -1;
            }
            xml_text_child_n(cp, "Prefix", k.p, k.n);
            if (k.n < sizeof(last_key)) {
                memcpy(last_key, k.p, k.n); last_key_len = k.n;
            }
        } else {
            XMLNode *contents = create_node("Contents");
            if (!contents || add_child(root, contents) < 0) {
                if (contents) free_tree(contents);
                free_tree(root); store_list_close(l); return -1;
            }
            xml_text_child_n(contents, "Key", k.p, k.n);

            char ts[32]; rsp_format_iso8601(m.mtime_ms, ts);
            xml_text_child(contents, "LastModified", ts);

            char etag[35]; rsp_format_etag(m.etag, etag);
            xml_text_child(contents, "ETag", etag);

            char szbuf[24]; snprintf(szbuf, sizeof(szbuf),
                                     "%llu", (unsigned long long)m.size);
            xml_text_child(contents, "Size", szbuf);

            xml_text_child(contents, "StorageClass", "STANDARD");

            if (k.n < sizeof(last_key)) {
                memcpy(last_key, k.p, k.n); last_key_len = k.n;
            }
        }
    }
    int truncated = store_list_truncated(l);
    store_list_close(l);

    xml_text_child(root, "IsTruncated", truncated ? "true" : "false");
    if (truncated && opts->delimiter.n > 0 && last_key_len > 0) {
        xml_text_child_n(root, "NextMarker", last_key, last_key_len);
    }

    /* Render. Small responses fit inline in wbuf; large responses spill
     * into c->ext_body which is drained by conn_on_writable after wbuf. */
    size_t blen = 0;
    char *body = xml_render_with_decl(root, &blen);
    free_tree(root);
    if (!body) return -1;

    int n = snprintf(c->wbuf, CONN_WBUF_SZ,
        "HTTP/1.1 200 OK\r\n"
        "Server: fs3/0.2\r\n"
        "Content-Type: application/xml\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "\r\n",
        blen,
        c->req.keep_alive ? "keep-alive" : "close");
    if (n < 0 || n >= CONN_WBUF_SZ) {
        free(body);
        return -1;
    }

    /* If body fits after the head, inline it. Otherwise hand it off
     * as ext_body and have wbuf carry only the head. */
    if ((size_t)n + blen <= CONN_WBUF_SZ) {
        memcpy(c->wbuf + n, body, blen);
        free(body);
        c->wlen = (size_t)n + blen;
    } else {
        c->wlen = (size_t)n;
        free(c->ext_body);
        c->ext_body = body;          /* takes ownership */
        c->ext_body_len = blen;
        c->ext_body_pos = 0;
    }
    c->wpos = 0;
    c->state = CST_WRITE_RESPONSE;
    return 0;
}
