/* fs3 — single-node S3-compatible object store
 *
 * include/s3.h — shared types used across all modules
 */
#ifndef FS3_S3_H
#define FS3_S3_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ---- Error codes (1:1 with S3 wire-protocol error codes) ---------------- */

typedef enum {
    S3_OK = 0,
    S3_ERR_NO_SUCH_BUCKET,
    S3_ERR_NO_SUCH_KEY,
    S3_ERR_NO_SUCH_UPLOAD,
    S3_ERR_BUCKET_ALREADY_EXISTS,
    S3_ERR_BUCKET_NOT_EMPTY,
    S3_ERR_INVALID_ARGUMENT,
    S3_ERR_INVALID_BUCKET_NAME,
    S3_ERR_INVALID_REQUEST,
    S3_ERR_SIGNATURE_DOES_NOT_MATCH,
    S3_ERR_ACCESS_DENIED,
    S3_ERR_INVALID_AUTH_HEADER,
    S3_ERR_REQUEST_TIME_TOO_SKEWED,
    S3_ERR_ENTITY_TOO_LARGE,
    S3_ERR_MISSING_CONTENT_LENGTH,
    S3_ERR_METHOD_NOT_ALLOWED,
    S3_ERR_INTERNAL,
    S3_ERR_NOT_IMPLEMENTED,
    S3_ERR_MAX
} s3_err_t;

/* ---- Bounded string view (NOT null-terminated) -------------------------- */

typedef struct {
    const char *p;
    size_t      n;
} s3_str_t;

#define S3_STR_LIT(s)  ((s3_str_t){ (s), sizeof(s) - 1 })
#define S3_STR_NULL    ((s3_str_t){ NULL, 0 })
#define S3_STR_FMT     "%.*s"
#define S3_STR_ARG(s)  (int)(s).n, (s).p

static inline int s3_str_eq(s3_str_t a, s3_str_t b) {
    return a.n == b.n && (a.n == 0 || memcmp(a.p, b.p, a.n) == 0);
}

static inline int s3_str_eq_lit(s3_str_t a, const char *lit) {
    size_t n = 0;
    while (lit[n]) n++;
    return a.n == n && memcmp(a.p, lit, n) == 0;
}

#endif /* FS3_S3_H */
