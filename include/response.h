/* include/response.h — HTTP response building helpers
 *
 * The handlers below all need to format response headers (with ETag,
 * Last-Modified, Content-Type, Content-Length) and S3 XML bodies.
 * This header centralises that formatting so handlers stay short.
 *
 * Lifecycle: handlers fill c->wbuf with response headers and possibly
 * a small body, then transition c->state to CST_WRITE_RESPONSE. For
 * GETs that need to stream a large body, the handler additionally
 * stashes a reader on the connection (see body_reader fields in
 * conn_t) so that conn_on_writable can call sendfile after the
 * headers are flushed.
 */
#ifndef FS3_RESPONSE_H
#define FS3_RESPONSE_H

#include "conn.h"
#include "s3.h"
#include "store.h"

#include <stddef.h>
#include <stdint.h>

/* Format an RFC 1123 date (used in Date / Last-Modified headers).
 * Buffer must hold at least 32 bytes. */
void rsp_format_rfc1123(uint64_t mtime_ms, char out[32]);

/* Format an ISO-8601 timestamp with millisecond precision and Z suffix
 * (used in S3 XML bodies). Buffer must hold at least 32 bytes. */
void rsp_format_iso8601(uint64_t mtime_ms, char out[32]);

/* Format an ETag as 32 lowercase hex chars surrounded by literal
 * double quotes ("abc..."). Buffer must hold at least 35 bytes. */
void rsp_format_etag(const uint8_t etag[16], char out[35]);

/* Format a possibly-multipart ETag. If part_count is 0, behaves like
 * rsp_format_etag. If non-zero, formats as `"<hex>-<part_count>"`.
 * Buffer must hold at least 41 bytes. */
void rsp_format_etag_with_parts(const uint8_t etag[16], uint16_t part_count,
                                char out[41]);

/* Same, but appends "-N" before the closing quote when part_count > 0,
 * to render the AWS multipart-style ETag ("abc...-3"). Buffer must
 * hold at least 41 bytes. part_count == 0 produces the same output as
 * rsp_format_etag (in the first 35 bytes). */
void rsp_format_etag_with_parts(const uint8_t etag[16], uint16_t part_count,
                                char out[41]);

/* Build a complete HTTP response into c->wbuf with status + headers,
 * no body. Used for HEAD, DELETE, and bucket create. Returns 0 ok. */
int rsp_build_status(conn_t *c, int status, const char *reason);

/* Same, but with a Content-Length 0 explicit body and any extra
 * headers given as a single block of "K: V\r\nK: V\r\n" text. */
int rsp_build_status_with_headers(conn_t *c, int status, const char *reason,
                                  const char *extra_headers);

/* Build a full GET-response head: 200 OK, Content-Length, Content-Type,
 * ETag, Last-Modified. The caller is responsible for streaming the
 * body afterwards via the writable callback path.
 *
 * If `head_only` is non-zero, no body will follow and Content-Length
 * is still reported as the object size (HEAD semantics). */
int rsp_build_object_head(conn_t *c, const s3_obj_meta_t *m, int head_only);

/* Build an S3 XML error response with the given S3 error enum,
 * resource path, and request id. Sets Content-Type: application/xml
 * and forces Connection: close on 5xx. */
int rsp_build_s3_error(conn_t *c, s3_err_t err,
                       s3_str_t resource, const char *request_id);

/* Build a ListBucketResult XML body for the given bucket and listing
 * options. The lister is consumed (closed by this function). */
int rsp_build_list_bucket(conn_t *c, s3_str_t bucket,
                          const s3_list_opts_t *opts, s3_lister_t *l);

/* Build an InitiateMultipartUploadResult XML body, 200 OK. */
int rsp_build_initiate_mpu(conn_t *c, s3_str_t bucket, s3_str_t key,
                           const char *upload_id);

/* Build a CompleteMultipartUploadResult XML body, 200 OK.
 * etag is the multipart-style ETag returned by store_mpu_complete
 * (e.g. "abc...-3"); we wrap it in quotes per S3 convention. */
int rsp_build_complete_mpu(conn_t *c, s3_str_t bucket, s3_str_t key,
                           const char *etag);

/* Build a ListAllMyBucketsResult XML body, 200 OK. */
int rsp_build_list_all_my_buckets(conn_t *c,
                                   const s3_bucket_info_t *buckets,
                                   size_t n_buckets);

/* Build a ListMultipartUploadsResult XML body, 200 OK. */
int rsp_build_list_mpu_uploads(conn_t *c, s3_str_t bucket, s3_str_t prefix,
                                const s3_mpu_info_t *uploads,
                                size_t n_uploads);

/* Build a 200 OK health-check response for GET /_health.
 * Returns {"status":"ok"} as application/json. */
int rsp_build_health(conn_t *c);

/* Build a CopyObjectResult XML body (200 OK) for server-side object copy.
 * `m` is the metadata of the newly written destination object. */
int rsp_build_copy_object(conn_t *c, const s3_obj_meta_t *m);

/* Build an AccessControlPolicy XML body (200 OK). fs3 has no real ACL
 * model; always returns a single FULL_CONTROL grant to the "fs3" owner. */
int rsp_build_acl(conn_t *c);

/* Build a 206 Partial Content response for a byte-range GET.
 * `first` and `last` are 0-based, inclusive indices into the object body.
 * The caller is responsible for seeking the reader to `first` before the
 * writable callback starts streaming. */
int rsp_build_object_range(conn_t *c, const s3_obj_meta_t *m,
                           uint64_t first, uint64_t last, int head_only);

/* Build a 416 Range Not Satisfiable response with a Content-Range: bytes
 * "star/total" header and no body. */
int rsp_build_range_not_satisfiable(conn_t *c, uint64_t obj_size);

/* Build a DeleteResult XML body, 200 OK.
 * `deleted_keys` / `n_deleted` — keys that were successfully deleted (or
 *   already absent — S3 DELETE is idempotent).
 * `error_keys`   / `n_errors`  — keys for which an internal error occurred.
 * In Quiet mode the caller passes n_deleted == 0; only errors are emitted. */
int rsp_build_delete_objects(conn_t *c,
                              const char **deleted_keys, size_t n_deleted,
                              const char **error_keys,   size_t n_errors);

/* Build a GetBucketLocation XML response. Empty LocationConstraint = us-east-1. */
int rsp_build_bucket_location(conn_t *c);

/* Build a GetBucketVersioning XML response (versioning never enabled). */
int rsp_build_bucket_versioning(conn_t *c);

/* Map an s3_err_t to an HTTP status code. */
int rsp_status_for_err(s3_err_t err);

/* Map an s3_err_t to an S3 error code string (e.g. "NoSuchBucket"). */
const char *rsp_code_for_err(s3_err_t err);

#endif
