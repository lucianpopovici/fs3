/* include/sigv4.h — AWS Signature V4 verification (header mode)
 *
 * Verifies the `Authorization: AWS4-HMAC-SHA256 ...` header that AWS
 * SDKs and the AWS CLI attach to S3 requests. This is the
 * non-streaming form: the client either signs an empty body, or
 * commits to the body's SHA-256 via `x-amz-content-sha256` (or the
 * literal `UNSIGNED-PAYLOAD`). Streaming chunked SigV4 (the
 * `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` form) is a separate concern
 * handled outside this module.
 *
 * The verifier is stateless w.r.t. requests; it carries only the
 * credential records and an optional clock override for tests.
 * sigv4_verify is a pure function of (verifier, parsed request).
 */
#ifndef FS3_SIGV4_H
#define FS3_SIGV4_H

#include <stdint.h>

#include "conn.h"
#include "s3.h"

typedef struct sigv4_verifier sigv4_verifier_t;

/* Build an empty verifier. Use sigv4_add_cred to populate. */
sigv4_verifier_t *sigv4_create(void);

/* Add one credential record. The verifier copies both strings. Returns
 * 0 on success, -1 on OOM or duplicate access key. */
int               sigv4_add_cred(sigv4_verifier_t *v,
                                 const char *access_key,
                                 const char *secret_key);

void              sigv4_destroy(sigv4_verifier_t *v);

/* Override the clock used for x-amz-date skew checks. 0 = real time. */
void              sigv4_set_clock(sigv4_verifier_t *v, int64_t fixed_now);

/* Verify a request. The conn's req fields supply the wire-form method,
 * raw path, raw query, and lowercased headers. Returns:
 *   S3_OK                            verified
 *   S3_ERR_ACCESS_DENIED             missing Authorization header,
 *                                    unknown access key, or a signed
 *                                    header that isn't actually present
 *   S3_ERR_INVALID_AUTH_HEADER       Authorization header malformed
 *   S3_ERR_REQUEST_TIME_TOO_SKEWED   x-amz-date > 15 min from now
 *   S3_ERR_SIGNATURE_DOES_NOT_MATCH  signature mismatch
 * No state is mutated on non-OK return.
 *
 * The body hash is NOT verified here; this function trusts the
 * client-supplied x-amz-content-sha256 verbatim. (See CLAUDE.md
 * "Body hash for non-streaming PUT" — a follow-up phase.) */
s3_err_t          sigv4_verify(const sigv4_verifier_t *v, const conn_t *c);

/* ------------------------------------------------------------------ */
/* Lower-level helpers, exposed for unit tests against the AWS test    */
/* vectors. Production code calls sigv4_verify only.                   */
/* ------------------------------------------------------------------ */

/* SHA-256 of `in` into `out` (32 raw bytes). */
void sigv4_sha256(const void *in, size_t n, uint8_t out[32]);

/* HMAC-SHA256(key, msg) → out (32 raw bytes). */
void sigv4_hmac_sha256(const void *key, size_t key_n,
                       const void *msg, size_t msg_n,
                       uint8_t out[32]);

/* Hex-encode 32 bytes into 64 lowercase chars (no NUL terminator). */
void sigv4_hex32(const uint8_t in[32], char out[64]);

/* Derive the per-request signing key.
 *   k = HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")
 * `date` is the YYYYMMDD prefix (8 bytes).
 * `out` receives the 32-byte signing key. */
void sigv4_signing_key(const char *secret, size_t secret_n,
                       const char *date,   /* 8 bytes */
                       const char *region, size_t region_n,
                       const char *service, size_t service_n,
                       uint8_t out[32]);

/* Normalize a S3 request path per the SigV4 S3 rules: collapse `//`
 * runs to `/`, leave the leading `/`, and re-decode any percent escapes
 * that decode to RFC 3986 unreserved characters. Other percent escapes
 * are left as-is. Returns the new length, or -1 if it doesn't fit. */
int  sigv4_canon_path(const char *in, size_t in_n,
                      char *out, size_t cap);

/* Normalize a query string per SigV4: split on `&`, decode each
 * key/value, sort by (key, value), re-encode each with strict RFC 3986
 * encoding, rejoin as k=v&k=v. An empty input yields an empty output.
 * Returns the new length, or -1 on overflow / malformed input. */
int  sigv4_canon_query(const char *in, size_t in_n,
                       char *out, size_t cap);

/* Normalize a header value: trim leading/trailing OWS and collapse runs
 * of internal ASCII whitespace to a single space (outside of double
 * quotes). Returns the new length. `out` may equal `in`. */
int  sigv4_canon_header_value(const char *in, size_t in_n,
                              char *out, size_t cap);

#endif /* FS3_SIGV4_H */
