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

/* Additional (x-amz-checksum-*) checksum algorithms. Values are stored
 * on disk: never renumber. */
typedef enum {
    S3_CKSUM_NONE      = 0,
    S3_CKSUM_CRC32     = 1,
    S3_CKSUM_CRC32C    = 2,
    S3_CKSUM_SHA1      = 3,
    S3_CKSUM_SHA256    = 4,
    S3_CKSUM_CRC64NVME = 5,
    S3_CKSUM_MAX
} s3_cksum_algo_t;

#define S3_CKSUM_TYPE_FULL_OBJECT 0
#define S3_CKSUM_TYPE_COMPOSITE   1

/* Object flags (schema-3 header). */
#define S3_OBJF_DELETE_MARKER (1u << 0)

typedef struct {
    uint64_t size;             /* body size in bytes */
    uint64_t mtime_ms;         /* ms since Unix epoch */
    uint8_t  etag[16];         /* raw MD5 of body (single-PUT) or
                                  multipart-of-MD5s (multipart upload) */
    uint16_t part_count;       /* 0 for single-PUT, >0 for multipart;
                                  formatters render as "hex-N" if >0 */
    char     content_type[128];/* NUL-terminated; "" if not set */

    /* Schema 3 fields; zero for objects written by schema 2. */
    uint8_t  version_id[16];   /* all-zero = null version */
    uint32_t flags;            /* S3_OBJF_* */
    uint8_t  cksum_algo;       /* s3_cksum_algo_t, 0 = none stored */
    uint8_t  cksum_type;       /* S3_CKSUM_TYPE_* */
    uint16_t cksum_parts;      /* composite: number of parts */
    uint8_t  cksum[32];        /* raw digest, left-aligned */
} s3_obj_meta_t;

/* Options for store_put_begin_opts. Zero-initialise and set what you
 * need. */
typedef struct {
    const char *content_type;  /* NULL/"" = none */
    /* Checksum to store with the object. If cksum_algo is set and
     * have_cksum is 0, the caller must provide it before commit with
     * store_put_set_checksum (the conn layer computes it while the body
     * streams and verifies it against the client's value). */
    uint8_t     cksum_algo;
    uint8_t     cksum_type;
    uint16_t    cksum_parts;
    int         have_cksum;
    uint8_t     cksum[32];
} store_put_opts_t;

/* ---- Lifecycle ---- */

s3_err_t store_open(s3_store_t **out, const char *root);
void     store_close(s3_store_t *s);

/* Set a minimum free-space threshold: store_put_begin and
 * store_mpu_part_begin will return S3_ERR_INSUFFICIENT_STORAGE when
 * the filesystem has fewer than `min_free_bytes` available. Pass 0 to
 * disable the check (the default). */
void     store_set_min_free_bytes(s3_store_t *s, uint64_t min_free_bytes);

/* Point-in-time stats for the metrics endpoint: bucket count, in-flight
 * multipart uploads, and data-volume usage from statvfs. Cheap (two
 * shallow readdir passes + one statvfs) but not free — call per scrape,
 * not per request. */
typedef struct {
    uint64_t buckets;
    uint64_t mpu_inflight;
    uint64_t volume_used_bytes;
    uint64_t volume_free_bytes;
} s3_admin_stats_t;
void     store_admin_stats(s3_store_t *s, s3_admin_stats_t *out);

/* Per-bucket stats for the admin /buckets endpoint: object count and
 * total logical (body) bytes. Walks the bucket's data shards reading
 * one header per object — O(objects) opens, so call per scrape or
 * page load, not per request. */
typedef struct {
    uint64_t objects;
    uint64_t bytes;
} s3_bucket_stats_t;
s3_err_t store_bucket_stats(s3_store_t *s, s3_str_t bucket,
                            s3_bucket_stats_t *out);

/* Test seams. Tests may point these at wrappers that inject I/O failures
 * (e.g. ENOSPC after N bytes) to exercise disk-full handling without a
 * real full filesystem. Leave NULL (the default) in production: the store
 * then calls write()/fsync() directly. */
extern ssize_t (*s3_store_write_hook)(int fd, const void *buf, size_t n);
extern int     (*s3_store_fsync_hook)(int fd);

/* ---- Buckets ---- */

s3_err_t store_bucket_create(s3_store_t *s, s3_str_t name);   /* ownerless */

/* ---- Bucket ownership ----
 *
 * Each bucket records the identity that owns it and a random id that
 * distinguishes it from any earlier bucket of the same name. Buckets
 * from before ownership existed read as ownerless with an empty id. */
typedef struct {
    char owner[129];   /* "" = ownerless */
    char id[33];       /* 32 hex, or "" for a pre-ownership bucket */
} s3_bucket_meta_t;

/* Create a bucket owned by `owner` (NULL/"" = ownerless). Returns
 * S3_ERR_BUCKET_ALREADY_EXISTS if the name is taken, whoever owns it. */
s3_err_t store_bucket_create_owned(s3_store_t *s, s3_str_t name,
                                   const char *owner);
/* S3_ERR_NO_SUCH_BUCKET if absent. */
s3_err_t store_bucket_meta(s3_store_t *s, s3_str_t name,
                           s3_bucket_meta_t *out);
/* Replace a bucket's owner (keeps its id; gives a pre-ownership bucket one). */
s3_err_t store_bucket_set_owner(s3_store_t *s, s3_str_t name,
                                const char *owner);
/* Give every ownerless bucket to `owner`. Returns how many, or -1. */
int      store_assign_legacy_owner(s3_store_t *s, const char *owner);
s3_err_t store_bucket_delete(s3_store_t *s, s3_str_t name); /* empty buckets only */

/* ---- Bucket config sidecars ----
 *
 * Small per-bucket files under buckets/<b>/ (grants, cors.xml,
 * lifecycle.xml, website.xml, policy.json, ...). Writes are atomic
 * (tmp + fsync + rename + fsync(dir)). `name` is a fixed identifier
 * chosen by the caller, never user input. */
s3_err_t store_bucket_sidecar_write(s3_store_t *s, s3_str_t bucket,
                                    const char *name,
                                    const void *data, size_t n);
/* Heap copy of the file (NUL-terminated; *n_out excludes the NUL).
 * S3_ERR_NO_SUCH_KEY if absent; S3_ERR_ENTITY_TOO_LARGE if > max. */
s3_err_t store_bucket_sidecar_read(s3_store_t *s, s3_str_t bucket,
                                   const char *name, size_t max,
                                   char **out, size_t *n_out);
s3_err_t store_bucket_sidecar_delete(s3_store_t *s, s3_str_t bucket,
                                     const char *name);

/* Parsed-config cache, keyed by bucket *id* + sidecar name and validated
 * against the file's inode/mtime/size on every lookup. `parse` turns the
 * file bytes into an object (NULL = unparseable, treated as absent);
 * `release` frees it. store_sidecar_get returns a counted reference
 * (NULL if the bucket or file is absent); drop it with store_sidecar_put.
 * Thread-safe. */
typedef struct store_cfg_ref store_cfg_ref_t;
typedef void *(*store_cfg_parse_fn)(const char *data, size_t n);
typedef void  (*store_cfg_free_fn)(void *obj);
store_cfg_ref_t *store_sidecar_get(s3_store_t *s, s3_str_t bucket,
                                   const char *name, size_t max,
                                   store_cfg_parse_fn parse,
                                   store_cfg_free_fn release);
void            *store_cfg_obj(const store_cfg_ref_t *r);
void             store_sidecar_put(s3_store_t *s, store_cfg_ref_t *r);

/* ---- Per-user bucket grants (item 3) ----
 *
 * buckets/<b>/grants: one "user:perms" line each, perms ⊆ "rwo"
 * (read, write, owner/config). Written tmp + fsync + rename + dirfsync.
 * Reads go through an in-memory cache keyed by bucket id and validated
 * against the file's mtime/size, so edits take effect immediately and a
 * re-created bucket never inherits an old bucket's grants. */
#define S3_GRANT_R 1
#define S3_GRANT_W 2
#define S3_GRANT_O 4

typedef struct {
    char user[129];
    int  perms;     /* S3_GRANT_* bits */
} s3_grant_t;

/* Permission bits `user` holds on `bucket` (0 = none). */
int      store_bucket_grant_perms(s3_store_t *s, s3_str_t bucket,
                                  const char *user);
/* All grants (heap array, caller frees). */
s3_err_t store_bucket_grants_get(s3_store_t *s, s3_str_t bucket,
                                 s3_grant_t **out, size_t *n_out);
/* Set `user`'s perms (0 removes the grant). User must pass
 * s3_valid_ident_strict. */
s3_err_t store_bucket_grant_set(s3_store_t *s, s3_str_t bucket,
                                const char *user, int perms);
/* "rw" → bits; -1 if invalid. */
int      store_grant_parse_perms(const char *p, size_t n);
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
s3_err_t store_put_begin_opts(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                              const store_put_opts_t *opts,
                              s3_writer_t **out);
/* Record the object's additional checksum (raw digest, `n` ≤ 32 bytes).
 * Must be called before commit. */
s3_err_t store_put_set_checksum(s3_writer_t *w, uint8_t algo, uint8_t type,
                                uint16_t parts, const uint8_t *digest,
                                size_t n);
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
    uint8_t  cksum_n;             /* client-listed part checksum length, 0 = none */
    uint8_t  cksum[32];           /* raw digest from <ChecksumXXX> */
} s3_part_ref_t;

/* Generate a fresh upload_id and stage it. Writes the upload_id (NUL-
 * terminated, S3_MULTIPART_UPLOAD_ID_LEN+1 bytes including NUL) into
 * `upload_id_out`. */
s3_err_t store_mpu_create(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                          const char *content_type,
                          char upload_id_out[S3_MULTIPART_UPLOAD_ID_LEN + 1]);

/* Like store_mpu_create, recording the upload's checksum algorithm and
 * type (S3_CKSUM_TYPE_*) from x-amz-checksum-algorithm / -type. With an
 * algorithm set, every part must carry a verified checksum of that
 * algorithm (part commit refuses otherwise), and complete stores the
 * object's checksum: COMPOSITE = algo(concat(part digests)) "-N", or
 * FULL_OBJECT = algo over the assembled bytes. */
s3_err_t store_mpu_create_opts(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                               const char *content_type,
                               uint8_t cksum_algo, uint8_t cksum_type,
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

/* store_mpu_complete with checksum handling. Parts listing a checksum
 * must match the stored part checksum (else S3_ERR_INVALID_PART). If
 * full_expect is non-NULL (an x-amz-checksum-<algo> header on Complete,
 * FULL_OBJECT uploads), the assembled object must match it (else
 * S3_ERR_CHECKSUM_MISMATCH). */
s3_err_t store_mpu_complete2(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                             const char *upload_id,
                             const s3_part_ref_t *parts, size_t n_parts,
                             const uint8_t *full_expect, size_t full_n,
                             char etag_out[40], s3_obj_meta_t *meta_out);

/* The checksum algorithm/type an upload was created with (0 = none). */
s3_err_t store_mpu_checksum_info(s3_store_t *s, s3_str_t bucket,
                                 const char *upload_id,
                                 uint8_t *algo, uint8_t *type);

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
    char     owner[129];    /* "" = ownerless */
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

