/* include/cors.h — bucket CORS configuration (item 4)
 *
 * PUT/GET/DELETE /bucket?cors store the raw CORSConfiguration XML in
 * buckets/<b>/cors.xml after validating it with cors_parse(). The parsed
 * form is cached per bucket id (store_sidecar_get) and used for
 * preflights (OPTIONS, unauthenticated) and for decorating actual
 * responses that carry an Origin header.
 */
#ifndef FS3_CORS_H
#define FS3_CORS_H

#include <stddef.h>

#include "s3.h"

#define CORS_MAX_RULES    100
#define CORS_MAX_BYTES    (64 * 1024)

enum { CORS_GET = 1, CORS_PUT = 2, CORS_POST = 4, CORS_DELETE = 8, CORS_HEAD = 16 };

typedef struct {
    char  **origins;   size_t n_origins;
    char  **headers;   size_t n_headers;    /* AllowedHeader (globs) */
    char  **expose;    size_t n_expose;
    int     methods;                        /* CORS_* bits */
    long    max_age;                        /* -1 = not set */
} cors_rule_t;

typedef struct {
    cors_rule_t *rules;
    size_t       n_rules;
} cors_config_t;

/* Parse + validate. Returns a heap config or NULL; *err_out names the
 * S3 error (S3_ERR_MALFORMED_XML or S3_ERR_INVALID_REQUEST). */
cors_config_t *cors_parse(const char *xml, size_t n, s3_err_t *err_out);
void           cors_free(cors_config_t *c);

/* Adapters for store_sidecar_get. */
void *cors_parse_cb(const char *xml, size_t n);
void  cors_free_cb(void *obj);

/* "GET" → CORS_GET; 0 if not a CORS method. */
int cors_method_bit(s3_str_t method);

/* First rule matching origin + method (+ every header in the
 * comma-separated `req_headers`, may be empty). NULL if none. */
const cors_rule_t *cors_match(const cors_config_t *c, s3_str_t origin,
                              int method_bit, s3_str_t req_headers);

/* Single-'*' glob match, case-sensitive or not. Linear time. */
int cors_glob(const char *pat, s3_str_t s, int icase);

#endif
