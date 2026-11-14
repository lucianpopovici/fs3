/* src/response.c — HTTP response building helpers */

#include "response.h"
#include "checksum.h"
#include "log.h"
#include "metrics.h"
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

void rsp_format_etag_with_parts(const uint8_t etag[16], uint16_t part_count,
                                char out[41]) {
    static const char hex[] = "0123456789abcdef";
    out[0] = '"';
    for (int i = 0; i < 16; i++) {
        out[1 + i*2 + 0] = hex[etag[i] >> 4];
        out[1 + i*2 + 1] = hex[etag[i] & 0xF];
    }
    if (part_count == 0) {
        out[33] = '"';
        out[34] = '\0';
        return;
    }
    /* "<hex>-<count>" — count fits in 5 chars (0..65535). */
    int n = snprintf(out + 33, 41 - 33, "-%u\"", (unsigned)part_count);
    if (n < 0 || n >= 41 - 33) {
        /* Defensive fallback. */
        out[33] = '"';
        out[34] = '\0';
    }
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
    { S3_ERR_BAD_DIGEST,                 400, "XAmzContentSHA256Mismatch","The provided x-amz-content-sha256 header does not match the body." },
    { S3_ERR_INVALID_PART,               400, "InvalidPart",              "One or more of the specified parts could not be found." },
    { S3_ERR_MALFORMED_XML,              400, "MalformedXML",             "The XML you provided was not well-formed."         },
    { S3_ERR_CHECKSUM_MISMATCH,          400, "BadDigest",                "The checksum you specified did not match the calculated checksum." },
    { S3_ERR_INVALID_CHECKSUM,           400, "InvalidRequest",           "The checksum value or algorithm you specified is invalid." },
    { S3_ERR_AUTH_QUERY_PARAMS,          400, "AuthorizationQueryParametersError", "The presigned URL parameters are invalid or out of range." },
    { S3_ERR_PRESIGN_EXPIRED,            403, "AccessDenied",             "Request has expired" },
    { S3_ERR_CORS_FORBIDDEN,             403, "AccessForbidden",          "CORSResponse: This CORS request is not allowed." },
    { S3_ERR_NO_SUCH_CORS,               404, "NoSuchCORSConfiguration",  "The CORS configuration does not exist." },
    { S3_ERR_NO_SUCH_LIFECYCLE,          404, "NoSuchLifecycleConfiguration", "The lifecycle configuration does not exist." },
    { S3_ERR_NO_SUCH_WEBSITE,            404, "NoSuchWebsiteConfiguration", "The specified bucket does not have a website configuration." },
    { S3_ERR_NO_SUCH_POLICY,             404, "NoSuchBucketPolicy",       "The bucket policy does not exist." },
    { S3_ERR_NO_SUCH_OBJECT_LOCK,        404, "ObjectLockConfigurationNotFoundError", "Object Lock configuration does not exist for this bucket." },
    { S3_ERR_NO_SUCH_VERSION,            404, "NoSuchVersion",            "The specified version does not exist." },
    { S3_ERR_POLICY_DENIED,              403, "AccessDenied",             "Access denied by bucket policy." },
    { S3_ERR_LOCKED,                     403, "AccessDenied",             "Access denied: the object version is locked." },
    { S3_ERR_MALFORMED_POLICY,           400, "MalformedPolicy",          "Policies must be valid JSON within the supported grammar." },
    { S3_ERR_INSUFFICIENT_STORAGE,       507, "QuotaExceeded",            "There is insufficient storage available to complete the request." },
};

static const err_entry_t *err_lookup(s3_err_t e) {
    for (size_t i = 0; i < sizeof(ERR_TABLE)/sizeof(ERR_TABLE[0]); i++) {
        if (ERR_TABLE[i].err == e) return &ERR_TABLE[i];
    }
    return &ERR_TABLE[0];
}

/* Distinct label per enum value for metrics (several errors share an S3
 * code, e.g. AccessDenied). */
const char *s3_err_name(s3_err_t e) {
    switch (e) {
    case S3_ERR_PRESIGN_EXPIRED:   return "PresignExpired";
    case S3_ERR_INVALID_CHECKSUM:  return "InvalidChecksum";
    case S3_ERR_CHECKSUM_MISMATCH: return "ChecksumMismatch";
    case S3_ERR_BAD_DIGEST:        return "ContentSHA256Mismatch";
    case S3_ERR_POLICY_DENIED:     return "PolicyDenied";
    case S3_ERR_LOCKED:            return "LockDenied";
    default: return err_lookup(e)->s3_code;
    }
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
    return rsp_build_object_head_status(c, m, head_only, 200, "OK");
}

int rsp_build_object_head_status(conn_t *c, const s3_obj_meta_t *m,
                                 int head_only, int status, const char *reason) {
    char etag[41]; rsp_format_etag_with_parts(m->etag, m->part_count, etag);
    char lm[32];   rsp_format_rfc1123(m->mtime_ms, lm);

    const char *ct = m->content_type[0] ? m->content_type : "application/octet-stream";

    int n = snprintf(c->wbuf, CONN_WBUF_SZ,
        "HTTP/1.1 %d %s\r\n"
        "Server: fs3/0.2\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %llu\r\n"
        "ETag: %s\r\n"
        "Last-Modified: %s\r\n"
        "Accept-Ranges: bytes\r\n"
        "Connection: %s\r\n"
        "\r\n",
        status, reason, ct,
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
    metrics_error(c->metrics, err);

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

            char etag[41];
            rsp_format_etag_with_parts(m.etag, m.part_count, etag);
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

/* ===================================================================== */
/* Multipart upload responses                                             */
/* ===================================================================== */

/* Internal helper: ship a finished body as a 200 OK XML response,
 * spilling into ext_body if it doesn't fit in wbuf. Takes ownership of
 * `body` (frees on success or failure). */
static int ship_xml_200(conn_t *c, char *body, size_t blen) {
    int n = snprintf(c->wbuf, CONN_WBUF_SZ,
        "HTTP/1.1 200 OK\r\n"
        "Server: fs3/0.2\r\n"
        "Content-Type: application/xml\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "\r\n",
        blen,
        c->req.keep_alive ? "keep-alive" : "close");
    if (n < 0 || n >= CONN_WBUF_SZ) { free(body); return -1; }

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
    c->state = CST_WRITE_RESPONSE;
    return 0;
}

int rsp_build_raw(conn_t *c, int status, const char *reason,
                  const char *content_type, char *body, size_t blen) {
    int n = snprintf(c->wbuf, CONN_WBUF_SZ,
        "HTTP/1.1 %d %s\r\n"
        "Server: fs3/0.2\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "\r\n",
        status, reason, content_type, blen,
        c->req.keep_alive ? "keep-alive" : "close");
    if (n < 0 || n >= CONN_WBUF_SZ) { free(body); return -1; }
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
    c->state = CST_WRITE_RESPONSE;
    return 0;
}

int rsp_build_initiate_mpu(conn_t *c, s3_str_t bucket, s3_str_t key,
                           const char *upload_id) {
    XMLNode *root = create_node("InitiateMultipartUploadResult");
    if (!root) return -1;
    if (add_attr(root, "xmlns", "http://s3.amazonaws.com/doc/2006-03-01/") < 0) {
        free_tree(root); return -1;
    }
    xml_text_child_n(root, "Bucket",   bucket.p, bucket.n);
    xml_text_child_n(root, "Key",      key.p,    key.n);
    xml_text_child  (root, "UploadId", upload_id);

    size_t blen = 0;
    char *body = xml_render_with_decl(root, &blen);
    free_tree(root);
    if (!body) return -1;
    return ship_xml_200(c, body, blen);
}

int rsp_build_complete_mpu(conn_t *c, s3_str_t bucket, s3_str_t key,
                           const char *etag) {
    return rsp_build_complete_mpu2(c, bucket, key, etag, NULL);
}

void rsp_format_checksum(const s3_obj_meta_t *m, char out[64]) {
    size_t dn = cksum_digest_len(m->cksum_algo);
    size_t n = base64_encode(m->cksum, dn, out);
    if (m->cksum_type == S3_CKSUM_TYPE_COMPOSITE)
        snprintf(out + n, 64 - n, "-%u", (unsigned)m->cksum_parts);
}

int rsp_build_complete_mpu2(conn_t *c, s3_str_t bucket, s3_str_t key,
                            const char *etag, const s3_obj_meta_t *m) {
    XMLNode *root = create_node("CompleteMultipartUploadResult");
    if (!root) return -1;
    if (add_attr(root, "xmlns", "http://s3.amazonaws.com/doc/2006-03-01/") < 0) {
        free_tree(root); return -1;
    }
    /* AWS S3 also returns Location, but it's optional and most clients
     * just consume the ETag — keep it minimal for now. */
    xml_text_child_n(root, "Bucket", bucket.p, bucket.n);
    xml_text_child_n(root, "Key",    key.p,    key.n);
    /* ETag wrapped in quotes per convention. */
    char etag_q[64];
    snprintf(etag_q, sizeof(etag_q), "\"%s\"", etag);
    xml_text_child(root, "ETag", etag_q);
    if (m && m->cksum_algo) {
        char ck[64];
        rsp_format_checksum(m, ck);
        xml_text_child(root, cksum_xml_name(m->cksum_algo), ck);
        xml_text_child(root, "ChecksumType",
                       m->cksum_type == S3_CKSUM_TYPE_COMPOSITE ? "COMPOSITE"
                                                                : "FULL_OBJECT");
    }

    size_t blen = 0;
    char *body = xml_render_with_decl(root, &blen);
    free_tree(root);
    if (!body) return -1;
    return ship_xml_200(c, body, blen);
}

/* ===================================================================== */
/* Service-level: ListAllMyBuckets                                        */
/* ===================================================================== */

int rsp_build_list_all_my_buckets(conn_t *c,
                                   const s3_bucket_info_t *buckets,
                                   size_t n_buckets) {
    XMLNode *root = create_node("ListAllMyBucketsResult");
    if (!root) return -1;
    if (add_attr(root, "xmlns", "http://s3.amazonaws.com/doc/2006-03-01/") < 0) {
        free_tree(root); return -1;
    }

    /* AWS requires <Owner> with ID + DisplayName. fs3 has no identity
     * model, so we emit placeholder values that look plausible enough
     * for clients that parse the response. */
    XMLNode *owner = create_node("Owner");
    if (!owner || add_child(root, owner) < 0) {
        if (owner) free_tree(owner);
        free_tree(root); return -1;
    }
    xml_text_child(owner, "ID",          "fs3");
    xml_text_child(owner, "DisplayName", "fs3");

    XMLNode *list = create_node("Buckets");
    if (!list || add_child(root, list) < 0) {
        if (list) free_tree(list);
        free_tree(root); return -1;
    }
    for (size_t i = 0; i < n_buckets; i++) {
        XMLNode *b = create_node("Bucket");
        if (!b || add_child(list, b) < 0) {
            if (b) free_tree(b);
            free_tree(root); return -1;
        }
        xml_text_child(b, "Name", buckets[i].name);
        char ts[32];
        rsp_format_iso8601(buckets[i].ctime_ms, ts);
        xml_text_child(b, "CreationDate", ts);
    }

    size_t blen = 0;
    char *body = xml_render_with_decl(root, &blen);
    free_tree(root);
    if (!body) return -1;
    return ship_xml_200(c, body, blen);
}

/* ===================================================================== */
/* Health check: GET /_health                                             */
/* ===================================================================== */

int rsp_build_health(conn_t *c) {
    static const char body[] = "{\"status\":\"ok\"}\n";
    int n = snprintf(c->wbuf, CONN_WBUF_SZ,
        "HTTP/1.1 200 OK\r\n"
        "Server: fs3/0.2\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "Connection: %s\r\n"
        "\r\n"
        "%s",
        sizeof(body) - 1,
        c->req.keep_alive ? "keep-alive" : "close",
        body);
    if (n < 0 || n >= CONN_WBUF_SZ) return -1;
    c->wlen = (size_t)n;
    c->wpos = 0;
    c->state = CST_WRITE_RESPONSE;
    return 0;
}

/* ===================================================================== */
/* Object copy: CopyObjectResult                                          */
/* ===================================================================== */

int rsp_build_copy_object(conn_t *c, const s3_obj_meta_t *m) {
    char etag[41]; rsp_format_etag_with_parts(m->etag, m->part_count, etag);
    char ts[32];   rsp_format_iso8601(m->mtime_ms, ts);

    XMLNode *root = create_node("CopyObjectResult");
    if (!root) return -1;
    if (!xml_text_child(root, "LastModified", ts)
        || !xml_text_child(root, "ETag", etag)) {
        free_tree(root); return -1;
    }
    size_t blen = 0;
    char *body = xml_render_with_decl(root, &blen);
    free_tree(root);
    if (!body) return -1;
    return ship_xml_200(c, body, blen);
}

/* ===================================================================== */
/* ACL stub: AccessControlPolicy                                          */
/* ===================================================================== */

int rsp_build_acl(conn_t *c) {
    /* fs3 has no real ACL model — always return a single FULL_CONTROL
     * grant to the "fs3" canonical user. The xsi: namespace on Grantee
     * is required by AWS clients. We build it as a literal string to
     * sidestep XML library concerns about colon-containing attribute names. */
    static const char acl_xml[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
        "<Owner><ID>fs3</ID><DisplayName>fs3</DisplayName></Owner>"
        "<AccessControlList><Grant>"
        "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
        " xsi:type=\"CanonicalUser\">"
        "<ID>fs3</ID><DisplayName>fs3</DisplayName></Grantee>"
        "<Permission>FULL_CONTROL</Permission>"
        "</Grant></AccessControlList>"
        "</AccessControlPolicy>";
    size_t blen = sizeof(acl_xml) - 1;
    char *body = malloc(blen);
    if (!body) return -1;
    memcpy(body, acl_xml, blen);
    return ship_xml_200(c, body, blen);
}

/* ===================================================================== */
/* Range responses (206 / 416)                                            */
/* ===================================================================== */

int rsp_build_object_range(conn_t *c, const s3_obj_meta_t *m,
                           uint64_t first, uint64_t last, int head_only) {
    char etag[41]; rsp_format_etag_with_parts(m->etag, m->part_count, etag);
    char lm[32];   rsp_format_rfc1123(m->mtime_ms, lm);
    const char *ct = m->content_type[0] ? m->content_type
                                        : "application/octet-stream";
    uint64_t range_len = last - first + 1;

    int n = snprintf(c->wbuf, CONN_WBUF_SZ,
        "HTTP/1.1 206 Partial Content\r\n"
        "Server: fs3/0.2\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %llu\r\n"
        "Content-Range: bytes %llu-%llu/%llu\r\n"
        "ETag: %s\r\n"
        "Last-Modified: %s\r\n"
        "Accept-Ranges: bytes\r\n"
        "Connection: %s\r\n"
        "\r\n",
        ct,
        (unsigned long long)range_len,
        (unsigned long long)first,
        (unsigned long long)last,
        (unsigned long long)m->size,
        etag, lm,
        c->req.keep_alive ? "keep-alive" : "close");
    (void)head_only;
    if (n < 0 || n >= CONN_WBUF_SZ) return -1;
    c->wlen = (size_t)n;
    c->wpos = 0;
    c->state = CST_WRITE_RESPONSE;
    return 0;
}

int rsp_build_range_not_satisfiable(conn_t *c, uint64_t obj_size) {
    char cr[64];
    snprintf(cr, sizeof(cr), "Content-Range: bytes */%llu\r\n",
             (unsigned long long)obj_size);
    return rsp_build_status_with_headers(c, 416, "Range Not Satisfiable", cr);
}

/* ===================================================================== */
/* Bulk delete: DeleteResult                                              */
/* ===================================================================== */

int rsp_build_delete_objects(conn_t *c,
                              const char **deleted_keys, size_t n_deleted,
                              const char **error_keys,   size_t n_errors) {
    XMLNode *root = create_node("DeleteResult");
    if (!root) return -1;
    if (add_attr(root, "xmlns", "http://s3.amazonaws.com/doc/2006-03-01/") < 0) {
        free_tree(root); return -1;
    }
    for (size_t i = 0; i < n_deleted; i++) {
        XMLNode *d = create_node("Deleted");
        if (!d || add_child(root, d) < 0) {
            if (d) free_tree(d);
            free_tree(root); return -1;
        }
        if (!xml_text_child(d, "Key", deleted_keys[i])) {
            free_tree(root); return -1;
        }
    }
    for (size_t i = 0; i < n_errors; i++) {
        XMLNode *e = create_node("Error");
        if (!e || add_child(root, e) < 0) {
            if (e) free_tree(e);
            free_tree(root); return -1;
        }
        if (!xml_text_child(e, "Key", error_keys[i])
            || !xml_text_child(e, "Code", "InternalError")
            || !xml_text_child(e, "Message", "An internal error occurred.")) {
            free_tree(root); return -1;
        }
    }
    size_t blen = 0;
    char *body = xml_render_with_decl(root, &blen);
    free_tree(root);
    if (!body) return -1;
    return ship_xml_200(c, body, blen);
}

/* ===================================================================== */
/* Bucket subresources: location + versioning                             */
/* ===================================================================== */

int rsp_build_bucket_location(conn_t *c) {
    XMLNode *root = create_node("LocationConstraint");
    if (!root) return -1;
    if (add_attr(root, "xmlns", "http://s3.amazonaws.com/doc/2006-03-01/") < 0) {
        free_tree(root); return -1;
    }
    /* Empty content = us-east-1 (the S3 classic region). */
    size_t blen = 0;
    char *body = xml_render_with_decl(root, &blen);
    free_tree(root);
    if (!body) return -1;
    return ship_xml_200(c, body, blen);
}

int rsp_build_bucket_versioning(conn_t *c) {
    return rsp_build_bucket_versioning_state(c, 0);
}

int rsp_build_bucket_versioning_state(conn_t *c, int state) {
    XMLNode *root = create_node("VersioningConfiguration");
    if (!root) return -1;
    if (add_attr(root, "xmlns", "http://s3.amazonaws.com/doc/2006-03-01/") < 0) {
        free_tree(root); return -1;
    }
    /* No Status child = versioning never configured. */
    if (state == S3_VERSIONING_ENABLED) xml_text_child(root, "Status", "Enabled");
    else if (state == S3_VERSIONING_SUSPENDED) xml_text_child(root, "Status", "Suspended");
    size_t blen = 0;
    char *body = xml_render_with_decl(root, &blen);
    free_tree(root);
    if (!body) return -1;
    return ship_xml_200(c, body, blen);
}

/* ===================================================================== */
/* Bucket-level: ListMultipartUploads                                     */
/* ===================================================================== */

int rsp_build_list_mpu_uploads(conn_t *c, s3_str_t bucket, s3_str_t prefix,
                                const s3_mpu_info_t *uploads,
                                size_t n_uploads) {
    XMLNode *root = create_node("ListMultipartUploadsResult");
    if (!root) return -1;
    if (add_attr(root, "xmlns", "http://s3.amazonaws.com/doc/2006-03-01/") < 0) {
        free_tree(root); return -1;
    }
    xml_text_child_n(root, "Bucket", bucket.p, bucket.n);
    if (prefix.n > 0) {
        xml_text_child_n(root, "Prefix", prefix.p, prefix.n);
    } else {
        /* AWS always emits <Prefix/> even when empty. */
        XMLNode *p = create_node("Prefix");
        if (p) add_child(root, p);
    }
    /* fs3 doesn't paginate this listing yet — IsTruncated is always
     * false. If you have >1000 in-flight uploads that's a separate
     * problem. */
    xml_text_child(root, "IsTruncated", "false");

    for (size_t i = 0; i < n_uploads; i++) {
        XMLNode *u = create_node("Upload");
        if (!u || add_child(root, u) < 0) {
            if (u) free_tree(u);
            free_tree(root); return -1;
        }
        xml_text_child(u, "Key",      uploads[i].key);
        xml_text_child(u, "UploadId", uploads[i].upload_id);
        char ts[32];
        rsp_format_iso8601(uploads[i].ctime_ms, ts);
        xml_text_child(u, "Initiated", ts);
        /* Real S3 also emits <Owner>, <Initiator>, <StorageClass>;
         * AWS clients tolerate their absence. */
    }

    size_t blen = 0;
    char *body = xml_render_with_decl(root, &blen);
    free_tree(root);
    if (!body) return -1;
    return ship_xml_200(c, body, blen);
}

int rsp_build_list_versions(conn_t *c, s3_str_t bucket,
                            const s3_version_list_opts_t *o,
                            const s3_version_info_t *v, size_t n,
                            int truncated, const char *next_key,
                            const char *next_vid) {
    XMLNode *root = create_node("ListVersionsResult");
    if (!root) return -1;
    if (add_attr(root, "xmlns", "http://s3.amazonaws.com/doc/2006-03-01/") < 0) {
        free_tree(root); return -1;
    }
    xml_text_child_n(root, "Name", bucket.p, bucket.n);
    xml_text_child_n(root, "Prefix", o->prefix.p ? o->prefix.p : "", o->prefix.n);
    xml_text_child_n(root, "KeyMarker", o->key_marker.p ? o->key_marker.p : "", o->key_marker.n);
    xml_text_child_n(root, "VersionIdMarker", o->version_id_marker.p ? o->version_id_marker.p : "",
                     o->version_id_marker.n);
    char mk[16];
    snprintf(mk, sizeof(mk), "%d", o->max_keys > 0 && o->max_keys <= 1000 ? o->max_keys : 1000);
    xml_text_child(root, "MaxKeys", mk);
    if (o->delimiter.n) xml_text_child_n(root, "Delimiter", o->delimiter.p, o->delimiter.n);
    xml_text_child(root, "IsTruncated", truncated ? "true" : "false");
    if (truncated && next_key) {
        xml_text_child(root, "NextKeyMarker", next_key);
        if (next_vid && next_vid[0]) xml_text_child(root, "NextVersionIdMarker", next_vid);
    }
    for (size_t i = 0; i < n; i++) {
        if (v[i].prefix) {
            XMLNode *cp = create_node("CommonPrefixes");
            if (!cp || add_child(root, cp) < 0) { free_tree(cp); free_tree(root); return -1; }
            xml_text_child(cp, "Prefix", v[i].prefix);
            continue;
        }
        int marker = (v[i].meta.flags & S3_OBJF_DELETE_MARKER) != 0;
        XMLNode *e = create_node(marker ? "DeleteMarker" : "Version");
        if (!e || add_child(root, e) < 0) { free_tree(e); free_tree(root); return -1; }
        xml_text_child(e, "Key", v[i].key);
        xml_text_child(e, "VersionId", v[i].version_id);
        xml_text_child(e, "IsLatest", v[i].is_latest ? "true" : "false");
        char ts[32];
        rsp_format_iso8601(v[i].meta.mtime_ms, ts);
        xml_text_child(e, "LastModified", ts);
        if (!marker) {
            char etag[41];
            rsp_format_etag_with_parts(v[i].meta.etag, v[i].meta.part_count, etag);
            xml_text_child(e, "ETag", etag);
            char sz[24];
            snprintf(sz, sizeof(sz), "%llu", (unsigned long long)v[i].meta.size);
            xml_text_child(e, "Size", sz);
            xml_text_child(e, "StorageClass", "STANDARD");
        }
    }
    size_t blen = 0;
    char *body = xml_render_with_decl(root, &blen);
    free_tree(root);
    if (!body) return -1;
    return ship_xml_200(c, body, blen);
}
