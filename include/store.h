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
    uint8_t  etag[16];         /* raw MD5 of body (single-PUT) */
    char     content_type[128];/* NUL-terminated; "" if not set */
} s3_obj_meta_t;

/* ---- Lifecycle ---- */

s3_err_t store_open(s3_store_t **out, const char *root);
void     store_close(s3_store_t *s);

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
void     store_get_close(s3_reader_t *r);

/* ---- HEAD / DELETE ---- */

s3_err_t store_head(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                    s3_obj_meta_t *meta_out);
s3_err_t store_delete(s3_store_t *s, s3_str_t bucket, s3_str_t key);

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

#endif
