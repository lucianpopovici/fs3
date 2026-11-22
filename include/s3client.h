/* include/s3client.h — minimal outbound S3 client (replication).
 *
 * Blocking HTTP/1.1 over TCP, or TLS in FS3_TLS builds, with SigV4 signing
 * (sigv4_sign, the same canonicalisation the server verifies with). Meant
 * to run on iopool worker threads, never on the event loop. One s3c_t is
 * one keep-alive connection to one endpoint; it is not thread-safe.
 *
 * Every call returns 0 when an HTTP response was received (look at
 * resp->status) and -1 on a transport failure (DNS, connect, TLS, timeout,
 * malformed response); err() then describes it. Transport failures are
 * always retryable; HTTP 5xx/408/429 usually are, other 4xx are not
 * (s3c_retryable()).
 */
#ifndef FS3_S3CLIENT_H
#define FS3_S3CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct {
    int      https;               /* 1 = TLS (needs an FS3_TLS build) */
    char     host[256];           /* DNS name or IP literal */
    int      port;                /* 0 = 443/80 */
    char     region[64];          /* signing region, e.g. "us-east-1" */
    char     access_key[129];
    char     secret_key[257];
    int      virtual_host;        /* 1 = <bucket>.<host>/<key>; 0 = path-style */
    int      verify_tls;          /* 1 = verify certificate and host name */
    char     ca_file[512];        /* extra CA bundle (PEM); "" = system default */
    int      timeout_s;           /* connect/read/write timeout; 0 = 30 */
} s3c_endpoint_t;

typedef struct {
    int      status;              /* HTTP status, 0 if none */
    char     etag[80];            /* without quotes */
    uint64_t content_length;      /* of the response (HEAD: of the object) */
    char     code[64];            /* S3 <Code> from an error body */
    char     upload_id[256];      /* CreateMultipartUpload */
    char     version_id[80];      /* x-amz-version-id, if any */
    char     src_etag[80];        /* x-amz-meta-fs3-source-etag (replication) */
} s3c_resp_t;

typedef struct s3c s3c_t;

/* Parse "https://host[:port]" (no path, query or userinfo). 0 ok. */
int s3c_parse_endpoint(const char *url, s3c_endpoint_t *ep, char *err, size_t errcap);

s3c_t *s3c_new(const s3c_endpoint_t *ep);
void   s3c_free(s3c_t *c);
const char *s3c_err(const s3c_t *c);
/* Connections opened so far (keep-alive reuse keeps this at 1). */
unsigned s3c_connects(const s3c_t *c);
/* While *flag is non-zero, transfers stop at the next 64 KiB and the
 * call fails as a transport error (used at shutdown). */
void   s3c_set_cancel(s3c_t *c, const int *flag);
/* 1 if the outcome (rc, resp) is worth retrying. */
int    s3c_retryable(int rc, const s3c_resp_t *resp);

/* Extra headers for PUT / CreateMultipartUpload: lowercase names. */
typedef struct { const char *name, *value; } s3c_hdr_t;

typedef struct {
    const char      *content_type;   /* NULL = application/octet-stream */
    const s3c_hdr_t *headers;        /* x-amz-meta-*, cache-control, x-amz-checksum-* … */
    size_t           n_headers;
} s3c_put_opts_t;

/* PUT the `len` bytes of `fd` starting at `off`. */
int s3c_put_object(s3c_t *c, const char *bucket, const char *key, int fd, off_t off,
                   uint64_t len, const s3c_put_opts_t *o, s3c_resp_t *resp);
int s3c_head_object(s3c_t *c, const char *bucket, const char *key, s3c_resp_t *resp);
/* GET into out_fd (at its current offset). Fails if the body exceeds max_bytes. */
int s3c_get_object(s3c_t *c, const char *bucket, const char *key, int out_fd,
                   uint64_t max_bytes, s3c_resp_t *resp);
int s3c_delete_object(s3c_t *c, const char *bucket, const char *key, s3c_resp_t *resp);

/* Multipart. Part numbers 1..10000; ETags without quotes. */
int s3c_mpu_create(s3c_t *c, const char *bucket, const char *key, const s3c_put_opts_t *o,
                   s3c_resp_t *resp);
int s3c_mpu_upload_part(s3c_t *c, const char *bucket, const char *key, const char *upload_id,
                        int part_no, int fd, off_t off, uint64_t len, s3c_resp_t *resp);
int s3c_mpu_complete(s3c_t *c, const char *bucket, const char *key, const char *upload_id,
                     char (*etags)[80], int n_parts, s3c_resp_t *resp);
int s3c_mpu_abort(s3c_t *c, const char *bucket, const char *key, const char *upload_id,
                  s3c_resp_t *resp);

/* Test seam: fixed signing time (unix seconds), 0 = real clock. */
void s3c_set_clock(int64_t fixed_now);

#endif
