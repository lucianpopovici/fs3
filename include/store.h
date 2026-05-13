/* include/store.h — storage backend interface
 *
 * Object lifecycle:
 *   PUT: store_put_begin → store_put_write* → store_put_commit
 *        (or store_put_abort to discard a partial upload)
 *   GET: store_get_open → store_get_read* (or sendfile) → store_get_close
 *
 * The streaming begin/write/commit pattern matches llhttp's on_body
 * callback delivery: bytes arrive in arbitrary chunks, we want to
 * land them on disk as they come without buffering the whole body.
 *
 * Atomicity: store_put_commit performs an atomic rename of a fully
 * written, fsync'd temp file into the final location. Readers see
 * either the old version of an object or the new version, never a
 * partial state. Crashes during PUT leave the temp file behind for
 * later GC; the live tree is never corrupted.
 *
 * Concurrency: not thread-safe yet. Phase 2.x will add a per-bucket
 * RWLock around the (eventual) index. For now, single-threaded use.
 */
#ifndef FS3_STORE_H
#define FS3_STORE_H

#include "s3.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef struct s3_store  s3_store_t;
typedef struct s3_writer s3_writer_t;
typedef struct s3_reader s3_reader_t;
typedef struct s3_lister s3_lister_t;

typedef struct {
    uint64_t size;             /* body size in bytes */
    uint64_t mtime_ms;         /* ms since Unix epoch */
    uint8_t  etag[16];         /* raw MD5 of body (single-PUT) or
                                  multipart-of-MD5s (multipart upload) */
    uint16_t part_count;       /* 0 for single-PUT, >0 for multipart;
                                  formatters render as "hex-N" if >0 */
    char     content_type[128];/* NUL-terminated; "" if not set */
} s3_obj_meta_t;

/* ---- Lifecycle ---- */

s3_err_t store_open(s3_store_t **out, const char *root);
void     store_close(s3_store_t *s);

/* Set a minimum free-space threshold: store_put_begin and
 * store_mpu_part_begin will return S3_ERR_INSUFFICIENT_STORAGE when
 * the filesystem has fewer than `min_free_bytes` available. Pass 0 to
 * disable the check (the default). */
void     store_set_min_free_bytes(s3_store_t *s, uint64_t min_free_bytes);

/* ---- Buckets ---- */

s3_err_t store_bucket_create(s3_store_t *s, s3_str_t name);
s3_err_t store_bucket_delete(s3_store_t *s, s3_str_t name); /* empty buckets only */
int      store_bucket_exists(s3_store_t *s, s3_str_t name);

/* ---- Streaming PUT ----
 *
 * begin() validates the bucket exists and opens a temp file. write()
 * appends bytes (may be called any number of times). commit() finalizes
 * — fsyncs, atomically renames, computes ETag, fills meta_out — and
 * frees the writer. abort() discards the temp file and frees the writer.
 *
 * On any error from begin/write/commit, the writer is freed; do NOT
 * call abort afterwards. */
s3_err_t store_put_begin(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                         const char *content_type,
                         s3_writer_t **out);
s3_err_t store_put_write(s3_writer_t *w, const void *buf, size_t n);
s3_err_t store_put_commit(s3_writer_t *w, s3_obj_meta_t *meta_out);
void     store_put_abort(s3_writer_t *w);

/* ---- Streaming GET ---- */

s3_err_t store_get_open(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                        s3_reader_t **out, s3_obj_meta_t *meta_out);
ssize_t  store_get_read(s3_reader_t *r, void *buf, size_t n);
/* Send up to `max` body bytes from the object file directly to out_fd
 * via sendfile(2). Returns bytes sent (0 = EOF), or -1 on error. */
ssize_t  store_get_sendfile(s3_reader_t *r, int out_fd, size_t max);
/* Restrict the reader to a byte range [first, last] (0-based, inclusive).
 * Must be called before the first read/sendfile. Returns S3_ERR_INVALID_ARGUMENT
 * if the range falls outside the object body. */
s3_err_t store_get_seek(s3_reader_t *r, uint64_t first, uint64_t last);
void     store_get_close(s3_reader_t *r);

/* ---- HEAD / DELETE ---- */

s3_err_t store_head(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                    s3_obj_meta_t *meta_out);
s3_err_t store_delete(s3_store_t *s, s3_str_t bucket, s3_str_t key);

/* ---- Multipart upload ----
 *
 * Lifecycle:
 *   create() — generate a unique upload_id, allocate a staging dir
 *              (data/<bucket>/_uploads/<upload_id>/) plus a small meta
 *              file describing the target key + content-type.
 *   part_begin/write/commit — exactly like single-PUT but lands the part
 *              file under the staging dir as part-NNNNN with the part's
 *              MD5 as the part's ETag.
 *   complete() — given a list of (part_number, etag) pairs in lex order,
 *              verifies all the parts are on disk and their etags match,
 *              then concatenates them into a single object file in the
 *              live tree, computes the multipart ETag (MD5 over the
 *              concatenation of part-MD5s, suffixed with "-N"), and
 *              cleans up the staging dir.
 *   abort()  — wipes the staging dir and forgets the upload.
 *
 * Concurrent part uploads to the same upload_id are allowed (each part
 * lands as its own file). The staging dir is per-upload, so different
 * uploads to the same key don't collide.
 *
 * Part numbering: 1..10000 (S3 limit; we enforce). Part size is
 * unrestricted from the store's POV; clients should respect S3's 5 MiB
 * minimum (except for the last part). */

#define S3_MULTIPART_UPLOAD_ID_LEN 32   /* hex chars, NUL-terminated → 33 */

typedef struct {
    int      part_number;         /* 1..10000 */
    char     etag_hex[33];        /* 32 hex chars + NUL — MD5 of the part body */
} s3_part_ref_t;

/* Generate a fresh upload_id and stage it. Writes the upload_id (NUL-
 * terminated, S3_MULTIPART_UPLOAD_ID_LEN+1 bytes including NUL) into
 * `upload_id_out`. */
s3_err_t store_mpu_create(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                          const char *content_type,
                          char upload_id_out[S3_MULTIPART_UPLOAD_ID_LEN + 1]);

/* Streaming part upload — same shape as the single-PUT writer. */
s3_err_t store_mpu_part_begin(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                              const char *upload_id, int part_number,
                              s3_writer_t **out);
s3_err_t store_mpu_part_write(s3_writer_t *w, const void *buf, size_t n);
/* On success, fills *etag_hex_out with 32 hex chars (NUL-terminated). */
s3_err_t store_mpu_part_commit(s3_writer_t *w, char etag_hex_out[33]);
void     store_mpu_part_abort(s3_writer_t *w);

/* Complete the upload by assembling the listed parts (in part-number
 * order). Verifies each etag matches what we have on disk. On success,
 * writes the multipart-style ETag ("hex-N") into etag_out and the
 * final object metadata into meta_out. */
s3_err_t store_mpu_complete(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                            const char *upload_id,
                            const s3_part_ref_t *parts, size_t n_parts,
                            char etag_out[40], s3_obj_meta_t *meta_out);

/* Abort: remove the staging dir and all part files. */
s3_err_t store_mpu_abort(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                         const char *upload_id);

/* ---- List ----
 *
 * Phase 2.1 implementation walks the filesystem; OK for homelab scale
 * (~tens of thousands of objects per bucket). Phase 2.2 replaces this
 * with an LMDB-backed index for O(log N) range scans. The interface
 * stays the same. */
typedef struct {
    s3_str_t prefix;     /* may be empty */
    s3_str_t marker;     /* return keys lexicographically AFTER this; may be empty */
    s3_str_t delimiter;  /* may be empty; if set, common prefixes are rolled up */
    int      max_keys;   /* 0 → default 1000 */
} s3_list_opts_t;

s3_err_t store_list_begin(s3_store_t *s, s3_str_t bucket,
                          const s3_list_opts_t *opts, s3_lister_t **out);
/* Returns S3_OK with one of:
 *   - a real key:    *is_prefix_out = 0, *meta_out filled
 *   - a common prefix: *is_prefix_out = 1, meta_out unset
 * Returns S3_ERR_NO_SUCH_KEY when iteration is exhausted.
 * key_out points into lister-owned storage; valid until the next call. */
s3_err_t store_list_next(s3_lister_t *l, s3_str_t *key_out,
                         s3_obj_meta_t *meta_out, int *is_prefix_out);
/* Returns 1 if the previous iteration stopped because max_keys was
 * reached and more matching keys remain. 0 otherwise. Should be called
 * after a store_list_next that returned S3_ERR_NO_SUCH_KEY, to decide
 * whether to set IsTruncated in the response. */
int      store_list_truncated(const s3_lister_t *l);
void     store_list_close(s3_lister_t *l);

/* ---- Service-level listing ----
 *
 * store_list_buckets enumerates all buckets under <root>/buckets/.
 * Result is a heap-allocated array of s3_bucket_info_t records; caller
 * frees with store_buckets_free. Order is filesystem-readdir order,
 * which is fine — S3 itself doesn't guarantee ordering for
 * ListAllMyBuckets. */
typedef struct {
    char    *name;          /* NUL-terminated, owned */
    uint64_t ctime_ms;      /* bucket creation time */
} s3_bucket_info_t;

s3_err_t store_list_buckets(s3_store_t *s,
                            s3_bucket_info_t **out, size_t *n_out);
void     store_buckets_free(s3_bucket_info_t *list, size_t n);

/* ---- In-flight multipart uploads ----
 *
 * Enumerate active multipart uploads in a bucket. Reads each
 * <root>/mpu/<bucket>/<upload_id>/meta to extract key + ctime.
 * Filters by key_prefix (may be S3_STR_NULL to list all).
 * Caller frees with store_mpu_uploads_free. */
typedef struct {
    char    *key;                                       /* owned */
    char     upload_id[S3_MULTIPART_UPLOAD_ID_LEN + 1]; /* fixed */
    uint64_t ctime_ms;
} s3_mpu_info_t;

s3_err_t store_list_mpu_uploads(s3_store_t *s, s3_str_t bucket,
                                s3_str_t key_prefix,
                                s3_mpu_info_t **out, size_t *n_out);
void     store_mpu_uploads_free(s3_mpu_info_t *list, size_t n);

/* ---- Multipart GC ----
 *
 * Sweep the MPU staging area and remove any upload whose ctime_ms is
 * older than (now_ms - max_age_ms). Returns the number of uploads
 * removed (0 if none, -errno on internal error). Safe to call on a
 * live system; uses the same rm_rf machinery as store_mpu_abort.
 *
 * Suggested cadence: call once every few minutes from the event loop,
 * with max_age_ms = 86_400_000 (24 hours). Real S3 defaults to 7
 * days but it's an admin policy, not a protocol requirement. */
int      store_mpu_gc(s3_store_t *s, uint64_t now_ms, uint64_t max_age_ms);

#endif

