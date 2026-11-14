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

/* Object flags (schema-3/4 header). */
#define S3_OBJF_DELETE_MARKER (1u << 0)
#define S3_OBJF_PAYLOAD_CRC   (1u << 1)   /* payload_crc64 is valid */
#define S3_OBJF_SSEC          (1u << 2)   /* payload is SSE-C sealed */
#define S3_OBJF_ZSTD          (1u << 3)   /* payload is zstd-compressed */

/* Schema-4 TLV record types ([u16 type][u32 len][bytes], LE). Values are
 * stored on disk: never renumber. Unknown types are preserved on copy. */
enum {
    S3_TLV_USER_META      = 1,   /* repeated [u16 nlen][u16 vlen][name][value] */
    S3_TLV_STD_HEADERS    = 2,   /* repeated [u8 id][u16 len][value] */
    S3_TLV_CONTENT_SHA256 = 3,   /* 32 raw bytes */
    S3_TLV_PART_TABLE     = 4,
    S3_TLV_SSEC           = 5,
    S3_TLV_ZSTD_SEEK      = 6,
};

typedef struct {
    uint64_t size;             /* body size in bytes */
    uint64_t mtime_ms;         /* ms since Unix epoch */
    uint8_t  etag[16];         /* raw MD5 of body (single-PUT) or
                                  multipart-of-MD5s (multipart upload) */
    uint16_t part_count;       /* 0 for single-PUT, >0 for multipart;
                                  formatters render as "hex-N" if >0 */
    char     content_type[1025];/* NUL-terminated; "" if not set */

    /* Schema 3 fields; zero for objects written by schema 2. */
    uint8_t  version_id[16];   /* all-zero = null version */
    uint32_t flags;            /* S3_OBJF_* */
    uint8_t  cksum_algo;       /* s3_cksum_algo_t, 0 = none stored */
    uint8_t  cksum_type;       /* S3_CKSUM_TYPE_* */
    uint16_t cksum_parts;      /* composite: number of parts */
    uint8_t  cksum[32];        /* raw digest, left-aligned */

    /* Schema 4; zero for older objects (stored_size = size). */
    uint64_t stored_size;      /* payload bytes on disk */
    uint8_t  payload_crc64[8]; /* valid iff flags & S3_OBJF_PAYLOAD_CRC */
    uint32_t header_size;      /* data offset in the object file */
    uint32_t tlv_off, tlv_len; /* TLV area (read with store_reader_tlv) */
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
    /* Schema-4 TLV area to store with the object (pre-built records,
     * validated; ≤ 64 KiB). Copied at begin. */
    const uint8_t *tlv;
    size_t      tlv_len;
    int         no_dedup;      /* never pool this object (SSE-C) */
    uint64_t    size_hint;     /* declared body length, 0 = unknown */
} store_put_opts_t;

/* ---- Lifecycle ---- */

s3_err_t store_open(s3_store_t **out, const char *root);
void     store_close(s3_store_t *s);

/* Set a minimum free-space threshold: store_put_begin and
 * store_mpu_part_begin will return S3_ERR_INSUFFICIENT_STORAGE when
 * the filesystem has fewer than `min_free_bytes` available. Pass 0 to
 * disable the check (the default). */
void     store_set_min_free_bytes(s3_store_t *s, uint64_t min_free_bytes);

/* Pad object headers to 4096 so payloads are block-aligned (set at
 * store_open when the filesystem supports reflinks; tests may force it).
 * Returns the previous setting. */
int      store_set_header_pad(s3_store_t *s, int on);
/* 1 if store_open found the filesystem reflink-capable. */
int      store_reflink_capable(const s3_store_t *s);
/* Turn the reflink fast paths off (0) or back on if the filesystem
 * supports them (1). Returns the previous setting. Tests use it to run
 * the pure-copy paths on Btrfs. */
int      store_set_reflink(s3_store_t *s, int on);
/* Filesystem compression (item 7a): FS_COMPR_FL on new object/part
 * files. AUTO skips already-compressed content types / suffixes and
 * objects under 4 KiB. Returns -1 (and stays off) if the filesystem
 * refuses the flag. */
enum { STORE_COMPRESS_OFF = 0, STORE_COMPRESS_AUTO = 1, STORE_COMPRESS_ALL = 2 };
int      store_set_fs_compress(s3_store_t *s, int mode);
/* Whole-object dedup (item 6b, needs reflink): objects of at least
 * min_size share extents through <root>/cas/<scope>/…; scope is per
 * bucket owner (STORE_DEDUP_OWNER) or global. verify byte-compares on a
 * hit. Counters are atomic. */
enum { STORE_DEDUP_OFF = 0, STORE_DEDUP_OWNER = 1, STORE_DEDUP_GLOBAL = 2 };
void     store_set_dedup(s3_store_t *s, int mode, uint64_t min_size, int verify);
extern uint64_t g_store_dedup_hits, g_store_dedup_misses;
/* Pool GC: drop entries not in the sorted digest array `keep` and older
 * than `older_than`. Returns the number removed. */
int      store_dedup_gc(s3_store_t *s, const uint8_t *keep, size_t n_keep, time_t older_than);
/* An object file's CONTENT_SHA256 TLV (1 found, 0 none). */
int      store_object_content_sha256(const char *path, uint8_t out[32]);
/* Number of extent clones done since start (atomic; tests, metrics). */
extern uint64_t g_store_clone_count;
/* Reflink copy of the reader's remaining payload into the writer (both
 * schema-4 padded or a part file); the bytes are still read once for the
 * writer's hashes and `extra`. S3_ERR_NOT_IMPLEMENTED: copy instead. */
s3_err_t store_writer_clone(s3_writer_t *w, s3_reader_t *r,
                            void (*extra)(void *ctx, const void *p, size_t n), void *ctx);

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
    uint64_t objects;          /* current objects (delete markers excluded) */
    uint64_t bytes;
    uint64_t versions;         /* noncurrent versions + delete markers */
    uint64_t version_bytes;
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
#define S3_VERSIONING_UNSET     0
#define S3_VERSIONING_ENABLED   1
#define S3_VERSIONING_SUSPENDED 2

typedef struct {
    char owner[129];   /* "" = ownerless */
    char id[33];       /* 32 hex, or "" for a pre-ownership bucket */
    int  versioning;   /* S3_VERSIONING_* (item 8) */
    int  object_lock;  /* object lock enabled at creation (item 10) */
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
/* Versioning state (item 8). Once Enabled, a bucket can never go back to
 * Unset: S3_VERSIONING_UNSET is refused after that. Buckets with object
 * lock stay Enabled. */
s3_err_t store_bucket_set_versioning(s3_store_t *s, s3_str_t name, int state);
/* "Unset" / "Enabled" / "Suspended" ("" if no such bucket). */
const char *store_bucket_versioning(s3_store_t *s, s3_str_t name);
int      store_bucket_object_lock(s3_store_t *s, s3_str_t name);
/* Create with object lock enabled (forces versioning Enabled). */
s3_err_t store_bucket_create_locked(s3_store_t *s, s3_str_t name,
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
/* Like store_sidecar_get, but an entry (including "no such bucket/file")
 * validated within the last ttl_ms is returned without touching disk.
 * For unauthenticated paths (CORS preflight, website) so they cannot
 * drive per-request disk I/O or tell missing buckets from missing
 * config apart by timing. */
store_cfg_ref_t *store_sidecar_get_ttl(s3_store_t *s, s3_str_t bucket,
                                       const char *name, size_t max,
                                       store_cfg_parse_fn parse,
                                       store_cfg_free_fn release,
                                       unsigned ttl_ms);
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
/* S3 bucket-name rules (3-63 chars, lowercase, digits, '.', '-'). */
int      store_valid_bucket_name(s3_str_t name);

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
/* The object's schema-4 TLV area (malloc'd copy, re-validated; NULL/0 if
 * none). Caller frees. */
s3_err_t store_reader_tlv(const s3_reader_t *r, uint8_t **out, size_t *n_out);
/* For zero-copy senders (SSL_sendfile): the file, the absolute offset of
 * the next body byte and how many remain. store_get_advance consumes n. */
void     store_get_raw(const s3_reader_t *r, int *fd, off_t *off, uint64_t *remaining);
void     store_get_advance(s3_reader_t *r, uint64_t n);

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

/* store_mpu_create_opts plus a schema-4 TLV area (user metadata and
 * standard headers, item 1e) recorded in the upload's meta and written
 * into the object at Complete. */
s3_err_t store_mpu_create_tlv(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                              const char *content_type,
                              uint8_t cksum_algo, uint8_t cksum_type,
                              const uint8_t *tlv, size_t tlv_n,
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

/* S3's rule: every part but the last must be at least this many bytes
 * (Complete answers S3_ERR_ENTITY_TOO_SMALL). 0 = no minimum. */
void     store_set_mpu_min_part_size(s3_store_t *s, uint64_t n);

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

/* ListParts: parts of one upload with number > marker, sorted, at most
 * max (cap 1000). Reads the part records; *truncated set when more
 * remain. The key must match the upload's (NoSuchUpload otherwise).
 * algo/type report the upload's checksum algorithm. Caller free()s. */
typedef struct {
    uint32_t part_number;
    uint64_t size;
    uint64_t mtime_ms;
    char     etag[33];                 /* lowercase hex MD5, NUL */
    uint8_t  ck_algo, ck_n;
    uint8_t  ck[32];
} s3_part_info_t;
s3_err_t store_mpu_list_parts(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                              const char *upload_id, uint32_t marker, size_t max,
                              s3_part_info_t **out, size_t *n_out, int *truncated,
                              uint8_t *algo_out, uint8_t *type_out);

/* ---- Quotas (round 2, item 2) ----
 *
 * Hard limits on logical bytes and object count per bucket (sidecar
 * buckets/<b>/quota) and per user (sum over the buckets they own; file
 * users/<hex(user)>.quota). 0 = unlimited. Without a bucket sidecar the
 * --default-bucket-quota applies; without a user file the
 * --default-user-quota. Writes over a limit fail with
 * S3_ERR_QUOTA_EXCEEDED before bytes reach disk. Lowering a limit below
 * current usage blocks new writes and never deletes data. */
typedef struct {
    uint64_t bytes, objects, reserved;
    uint64_t max_bytes, max_objects;   /* effective limits */
    int      has_cfg;                  /* explicit (not default) limit */
    char     owner[129];
} s3_quota_usage_t;
void     store_set_default_quotas(s3_store_t *s, uint64_t bucket_bytes, uint64_t user_bytes);
s3_err_t store_bucket_quota_set(s3_store_t *s, s3_str_t bucket,
                                uint64_t max_bytes, uint64_t max_objects);
s3_err_t store_bucket_quota_clear(s3_store_t *s, s3_str_t bucket);
s3_err_t store_bucket_usage(s3_store_t *s, s3_str_t bucket, s3_quota_usage_t *out);
s3_err_t store_user_quota_set(s3_store_t *s, const char *user,
                              uint64_t max_bytes, uint64_t max_objects);
s3_err_t store_user_quota_clear(s3_store_t *s, const char *user);
s3_err_t store_user_usage(s3_store_t *s, const char *user, s3_quota_usage_t *out);
uint64_t store_quota_rejections(s3_store_t *s);
/* Recompute a bucket's usage from disk (scrub); *drift = old - new.
 * S3_ERR_SLOW_DOWN: the bucket was written during the walk, nothing
 * changed (try again on the next pass). */
s3_err_t store_quota_recount(s3_store_t *s, s3_str_t bucket, int64_t *drift_bytes);
/* Reserve quota for a body of n bytes (declared length) before it
 * streams; writes past it reserve as they go. */
s3_err_t store_put_expect(s3_writer_t *w, uint64_t n);
int      store_valid_identity(const char *u);

/* ---- Integrity scrub (round 2, item 3) ----
 *
 * store_scrub_file verifies one file without any lock (object files are
 * immutable once renamed in; a vanished file is SCRUB_GONE, never
 * corruption). Pass lock_hex (the key's path hash) to re-confirm a
 * failure under the key's stripe lock. Objects: header, size, then the
 * payload CRC64, else the MD5 ETag (single-part, untransformed), else a
 * full-object checksum, else unverifiable. Parts: against their record. */
enum { SCRUB_OK = 0, SCRUB_UNVERIFIABLE, SCRUB_CORRUPT, SCRUB_GONE };
enum { STORE_SCRUB_OBJECT = 0, STORE_SCRUB_PART = 1, STORE_SCRUB_LOCK = 2 };
typedef struct {
    int      verdict;
    uint64_t bytes_read, logical_size, mtime_ms;
    uint64_t dev, ino, nlink;
    uint8_t  version_id[16];
    char     key[1025];
    char     reason[64];
    char     expected[40], actual[40];
} store_scrub_result_t;
s3_err_t store_scrub_file(s3_store_t *s, const char *path, int kind, const char *lock_hex,
                          void (*throttle)(void *ctx, uint64_t bytes), void *tctx,
                          store_scrub_result_t *r);
/* --scrub-fail-reads: GET of a marked version answers InternalError. */
void     store_scrub_fail_reads(int on);
void     store_scrub_mark_corrupt(uint64_t dev, uint64_t ino, uint64_t mtime_ms);
const char *store_root(const s3_store_t *s);

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

/* Per-bucket override for the global MPU GC (item 5): if set, uploads
 * for which filter(user, bucket, key) returns 1 are governed by a bucket
 * lifecycle rule and skipped by store_mpu_gc. */
void     store_set_mpu_gc_filter(s3_store_t *s,
                                 int (*filter)(void *user, s3_str_t bucket,
                                               s3_str_t key),
                                 void *user);

/* ---- Versioning (item 8) ----
 *
 * The current version stays where unversioned objects live (data/...), so
 * unversioned GET/list are as fast as before. Superseded versions move to
 *   versions/<b>/xx/yy/<hex>/<inv_ts>-<vid>
 * with inv_ts = UINT64_MAX - mtime_ms (16 hex, so readdir order sorted is
 * newest first) and vid = 32 hex (all zeros = the null version). They are
 * moved aside with link(2) before the new current is renamed in, all under
 * the key's stripe lock: a crash in between leaves a version entry that
 * shares the current file's inode, removed at startup.
 *
 * Version ids on the wire: 32 lowercase hex, or "null". */
#define S3_VID_HEX_LEN 32

/* "null" for the all-zero id, else 32 hex. out: 33 bytes. */
void     store_vid_format(const uint8_t vid[16], char out[33]);
/* Parse a wire version id ("null" or exactly 32 hex — validated before
 * any path is built, security review S5). 0 ok, -1 invalid. */
int      store_vid_parse(s3_str_t s, uint8_t vid[16]);

/* Open a specific version (vid NULL = current). The current version being
 * a delete marker yields S3_ERR_NO_SUCH_KEY with meta_out filled (flags
 * has S3_OBJF_DELETE_MARKER). Opening a delete marker by version id gives
 * S3_ERR_METHOD_NOT_ALLOWED with meta_out filled. */
s3_err_t store_get_open_version(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                                const uint8_t *vid,
                                s3_reader_t **out, s3_obj_meta_t *meta_out);

typedef struct {
    int     delete_marker;      /* a marker was created / removed */
    int     versioned;          /* bucket versioning not Unset */
    char    version_id[33];     /* created marker's, or deleted version's */
} store_delete_result_t;

/* DELETE with versioning semantics. vid NULL: Unset → unlink; Enabled →
 * new delete marker (old current moved aside); Suspended → null delete
 * marker. vid given: permanently remove that version (current → newest
 * noncurrent is promoted; removing a delete marker "undeletes"). The
 * version-delete guard (object lock) can veto with S3_ERR_ACCESS_DENIED. */
s3_err_t store_delete_ex(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                         const uint8_t *vid, store_delete_result_t *res);

/* Veto hook for permanently removing a version (item 10). Return S3_OK to
 * allow. Called with the key's stripe lock held: must not call back into
 * mutating store functions. */
typedef s3_err_t (*store_version_guard_fn)(void *user, s3_str_t bucket,
                                           s3_str_t key, const s3_obj_meta_t *m,
                                           int bypass);
void     store_set_version_guard(s3_store_t *s, store_version_guard_fn fn,
                                 void *user);
/* Per-thread "bypass governance retention" flag consulted by the guard
 * for the next store_delete_ex on this thread (cleared after use). */
void     store_set_guard_bypass(int bypass);

typedef struct {
    char         *key;           /* owned; NULL for a common prefix entry */
    char         *prefix;        /* owned; common prefix (delimiter) */
    char          version_id[33];
    int           is_latest;
    s3_obj_meta_t meta;
} s3_version_info_t;

typedef struct {
    s3_str_t prefix, delimiter, key_marker, version_id_marker;
    int      max_keys;           /* 0 → 1000 */
} s3_version_list_opts_t;

/* ListObjectVersions: keys in order, versions newest first. *truncated
 * and next markers are set when max_keys stopped the listing. */
s3_err_t store_list_versions(s3_store_t *s, s3_str_t bucket,
                             const s3_version_list_opts_t *o,
                             s3_version_info_t **out, size_t *n_out,
                             int *truncated, char **next_key,
                             char next_vid[33]);
void     store_versions_free(s3_version_info_t *v, size_t n);

/* Noncurrent versions of one key, newest first (lifecycle). noncurrent_
 * since_ms = mtime of the next newer version. */
typedef struct {
    uint8_t       vid[16];
    s3_obj_meta_t meta;
    uint64_t      noncurrent_since_ms;
} s3_noncurrent_t;
s3_err_t store_list_noncurrent(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                               s3_noncurrent_t **out, size_t *n_out);

/* ---- Object lock state (item 10) ----
 *
 * Per-version sidecar locks/<b>/xx/yy/<hex>/<vid hex> (retention can be
 * extended after write without rewriting data). */
#define S3_LOCK_NONE        0
#define S3_LOCK_GOVERNANCE  1
#define S3_LOCK_COMPLIANCE  2

typedef struct {
    int      mode;           /* S3_LOCK_* */
    uint64_t until_ms;       /* retain-until, 0 = none */
    int      legal_hold;
} s3_lock_t;

/* 0 = sidecar present and parsed, 1 = absent, -1 = unreadable/corrupt. */
int      store_lock_read(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                         const uint8_t vid[16], s3_lock_t *out);
s3_err_t store_lock_write(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                          const uint8_t vid[16], const s3_lock_t *l);

/* ---- Object walk (lifecycle sweeper, scrub) ----
 *
 * Calls cb for every current object in `bucket` (unsorted, no key
 * buffering — O(1) memory). Return non-zero from cb to stop early.
 * Unreadable files are skipped. */
typedef int (*store_walk_cb)(void *user, s3_str_t key, const s3_obj_meta_t *m);
s3_err_t store_walk_objects(s3_store_t *s, s3_str_t bucket,
                            store_walk_cb cb, void *user);

/* Lifecycle expiry: delete `key` only if its current object still has
 * mtime_ms — re-checked under the key's stripe lock, so a PUT that lands
 * during a sweep is never deleted. S3_ERR_INVALID_REQUEST = changed,
 * skipped. Goes through the normal delete path. */
s3_err_t store_expire_if_unchanged(s3_store_t *s, s3_str_t bucket,
                                   s3_str_t key, uint64_t mtime_ms);

#endif

