/* include/sigv4.h — AWS Signature V4 verification
 *
 * Verifies the Authorization header on incoming requests against a
 * configured set of (access_key, secret_key) credentials.
 *
 * Lifecycle:
 *   sigv4_verifier_t *v = sigv4_create();
 *   sigv4_add_cred(v, "AKIA...", "secret...");
 *   ...
 *   s3_err_t e = sigv4_verify(v, c);
 *   ...
 *   sigv4_destroy(v);
 *
 * The verifier struct is intended to live for the life of the server
 * and be shared (read-only after construction) across all connections.
 *
 * Phase 1 scope: header-mode SigV4 only. The body hash declared in
 * x-amz-content-sha256 is used verbatim in the canonical request; we
 * do NOT independently hash the body to verify it matches. That's a
 * Phase 2 add-on.
 */
#ifndef FS3_SIGV4_H
#define FS3_SIGV4_H

#include <stdint.h>

#include "s3.h"

struct conn;
typedef struct sigv4_verifier sigv4_verifier_t;

/* Create an empty verifier. */
sigv4_verifier_t *sigv4_create(void);

/* Add a credential. Strings are copied. Returns 0 on success, -1 on OOM
 * or if the access_key is already present. */
int sigv4_add_cred(sigv4_verifier_t *v,
                   const char *access_key,
                   const char *secret_key);

/* Free the verifier and its credentials. */
void sigv4_destroy(sigv4_verifier_t *v);

/* Override "now" for deterministic testing. fixed_now is Unix epoch
 * seconds; pass 0 to use the real wall clock. */
void sigv4_set_clock(sigv4_verifier_t *v, int64_t fixed_now);

/* Configure the maximum allowed clock skew between client and server,
 * in seconds. Default is 900 (15 minutes). */
void sigv4_set_max_skew(sigv4_verifier_t *v, int max_skew_seconds);

/* Verify the signature on a parsed request.
 *
 * Returns:
 *   S3_OK                            — verified
 *   S3_ERR_ACCESS_DENIED             — missing/malformed Authorization,
 *                                       missing x-amz-date, missing host,
 *                                       unknown access key
 *   S3_ERR_REQUEST_TIME_TOO_SKEWED   — x-amz-date out of allowed window
 *   S3_ERR_SIGNATURE_DOES_NOT_MATCH  — signature mismatch
 *   S3_ERR_NOT_IMPLEMENTED           — chunked SigV4 trailer variants
 *
 * On non-OK return, no state on `c` is modified. */
s3_err_t sigv4_verify(const sigv4_verifier_t *v, const struct conn *c);

/* Detect whether the request uses streaming chunked SigV4
 * (x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD). Call
 * after sigv4_verify returned S3_OK. Returns 1 if chunked, 0 otherwise. */
int sigv4_is_chunked(const struct conn *c);

/* ===================================================================== */
/* Body-hash verification                                                 */
/* ===================================================================== */

/* These four functions wrap a streaming SHA-256 computation against
 * the request body. Used after sigv4_verify succeeds, when the client
 * declared a real hex hash via x-amz-content-sha256 (vs UNSIGNED-PAYLOAD).
 *
 * Lifecycle:
 *   ctx = sigv4_body_hash_begin();    // at headers-complete
 *   sigv4_body_hash_update(ctx, ...); // for each on_body chunk
 *   ok = sigv4_body_hash_verify(ctx, expected);  // at message-complete
 *   sigv4_body_hash_free(ctx);
 *
 * The ctx is opaque (an EVP_MD_CTX under the hood) so callers don't
 * need to include OpenSSL headers. */
void *sigv4_body_hash_begin(void);
void  sigv4_body_hash_update(void *ctx, const void *data, size_t n);

/* Finalize and compare with `expected_hex` (64 lowercase hex chars).
 * Returns 1 if matched, 0 otherwise. The ctx is consumed (must be
 * freed by sigv4_body_hash_free regardless of return value). */
int   sigv4_body_hash_verify(void *ctx, const char expected_hex[64]);
void  sigv4_body_hash_free(void *ctx);

/* ===================================================================== */
/* Streaming chunked SigV4 (aws-chunked)                                  */
/* ===================================================================== */

/* Decoder for the aws-chunked body framing used when
 * x-amz-content-sha256 = STREAMING-AWS4-HMAC-SHA256-PAYLOAD.
 *
 * Wire format per chunk:
 *     <hex-chunk-size>;chunk-signature=<64-hex-sig>\r\n
 *     <chunk-size bytes of data>\r\n
 * Terminated by a zero-length chunk:
 *     0;chunk-signature=<64-hex-sig>\r\n\r\n
 *
 * Each chunk-signature is HMAC(signing_key, string-to-sign) where
 *   string-to-sign:
 *     AWS4-HMAC-SHA256-PAYLOAD\n
 *     <amz-date>\n
 *     <credential-scope>\n
 *     <previous-signature>\n        (seed for first, prev chunk-sig for next)
 *     SHA256("")\n                  (constant — empty-string hash)
 *     SHA256(chunk-data)            (data hash; "" for terminator)
 *
 * Caller (conn.c) feeds raw HTTP body bytes via decode(). The decoder
 * extracts chunk-data bytes and forwards them via the on_data callback,
 * verifying each chunk's signature as it goes. After all bytes have
 * been fed, the caller calls finish() to verify the terminator chunk. */
typedef struct sigv4_chunk_decoder sigv4_chunk_decoder_t;

/* Callback invoked for each verified chunk's data bytes. May be called
 * multiple times per chunk if the bytes spread across feed() calls.
 * Return 0 to continue, -1 to abort the decode. */
typedef int (*sigv4_chunk_data_cb)(void *user, const char *data, size_t len);

/* Create a decoder. The decoder takes a snapshot of the signing key,
 * scope, amz_date, and seed_signature from the verifier — these come
 * from sigv4_verify having succeeded for the seed (header-mode)
 * signature. Returns NULL on OOM.
 *
 * The expected total data length (sum of all chunk-data sizes, NOT
 * the total wire-format length) is taken from x-amz-decoded-content-length;
 * passing 0 disables the length check. */
sigv4_chunk_decoder_t *sigv4_chunk_begin(const sigv4_verifier_t *v,
                                         const struct conn *c,
                                         uint64_t expected_decoded_length,
                                         sigv4_chunk_data_cb on_data,
                                         void *user_data);

/* Feed `len` bytes of raw HTTP body. Returns 0 on success, -1 on
 * malformed framing or signature mismatch (request should be rejected
 * with SignatureDoesNotMatch / InvalidRequest). */
int sigv4_chunk_feed(sigv4_chunk_decoder_t *d, const char *data, size_t len);

/* Verify that we received the terminator chunk and the total decoded
 * length matched (if a non-zero expected length was given). Returns
 * 0 on success, -1 if the stream ended improperly. */
int sigv4_chunk_finish(sigv4_chunk_decoder_t *d);

/* Free the decoder. Safe to call after either success or failure. */
void sigv4_chunk_free(sigv4_chunk_decoder_t *d);

#endif /* FS3_SIGV4_H */
