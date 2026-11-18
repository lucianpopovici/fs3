/* src/store_fs.c — filesystem-backed object store.
 *
 * On-disk layout under ROOT:
 *
 *   buckets/<name>/                   -- bucket existence marker dir
 *   data/<bucket>/<xx>/<yy>/<hex>     -- one file per object
 *   tmp/                              -- staging files for atomic writes
 *
 * <hex> is the SHA-256 of "bucket\0key" rendered as 64 hex chars; <xx>
 * and <yy> are the first two bytes of <hex>. The two-level prefix keeps
 * fan-out under any directory below a few thousand at homelab scale.
 *
 * Each object file is self-contained:
 *
 *   [obj_header_t (52 bytes)][content_type (var)][key (var)][data (var)]
 *
 * Header has magic, schema version, sizes, mtime, raw MD5 etag, plus
 * lengths for content_type and key. Reading the file means reading the
 * header, skipping past header bytes, then streaming data. Writing means
 * reserving header space, appending data while accumulating MD5 + size,
 * then pwrite-ing the finalized header back at offset 0 before the
 * atomic rename.
 *
 * Crash safety: every write goes through a temp file, fsync, rename,
 * fsync(parent_dir). Concurrent writers to the same key serialize at
 * the rename — last writer wins. Readers see one consistent version.
 */

/* The on-disk header is intentionally packed for a deterministic layout.
 * GCC -O2 with -Wstringop-overread incorrectly treats the address of a
 * packed struct whose first field is a small array as a pointer to that
 * array only, generating false-positive warnings on full-struct
 * read/write/pread calls. We silence that single diagnostic locally. */
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ >= 11
#pragma GCC diagnostic ignored "-Wstringop-overread"
#endif

#include "store.h"
#include "checksum.h"
#include "ssec.h"
#include "log.h"

#include <dirent.h>
#include <ftw.h>
#include <linux/fs.h>
#include <linux/types.h>
/* Kernel 3.10 headers (the DSM 7 toolchain for the DS1515+) predate the
 * generic clone ioctls (4.5). Their numbers and argument layout are
 * Btrfs's BTRFS_IOC_CLONE / BTRFS_IOC_CLONE_RANGE, which 3.10 Btrfs
 * implements, so define them here when the headers don't. */
#ifndef FICLONE
#define FICLONE _IOW(0x94, 9, int)
#endif
#ifndef FICLONERANGE
struct file_clone_range {
    __s64 src_fd;
    __u64 src_offset;
    __u64 src_length;
    __u64 dest_offset;
};
#define FICLONERANGE _IOW(0x94, 13, struct file_clone_range)
#endif
#include <sys/ioctl.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/sendfile.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

/* ===================================================================== */
/* On-disk format                                                        */
/* ===================================================================== */

#define OBJ_MAGIC    "YS3OBJ\0"
#define OBJ_MAGIC_LEN 8         /* "YS3OBJ\0\0" — 6 chars + 2 NUL */
#define OBJ_SCHEMA_V2 2u        /* v2 added part_count */
#define OBJ_SCHEMA_V3 3u        /* v3 added obj_ext_v3_t (checksum, version id, flags) */
#define OBJ_SCHEMA   4u         /* v4 added obj_ext_v4_t + TLV area + padding */

typedef struct __attribute__((packed)) {
    char     magic[OBJ_MAGIC_LEN];   /* "YS3OBJ\0\0" */
    uint32_t schema;                 /* OBJ_SCHEMA */
    uint32_t header_size;            /* sizeof(this) + ct_len + key_len */
    uint64_t data_size;
    uint64_t mtime_ms;
    uint8_t  etag[16];
    uint16_t ct_len;
    uint16_t key_len;
    uint16_t part_count;             /* 0 = single PUT; >0 = multipart, ETag is "hex-N" */
    uint8_t  reserved[6];            /* keep struct 8-byte aligned, room to grow */
} obj_header_t;

_Static_assert(sizeof(obj_header_t) == 60, "obj_header_t layout");

/* Schema 3: an extension block between the fixed header and the
 * content-type/key bytes. v2 files have no extension (read as zeroes).
 * header_size always covers everything before the data, so the data
 * offset stays header-driven. One-way migration: a pre-v3 binary
 * refuses v3 objects. */
typedef struct __attribute__((packed)) {
    uint8_t  version_id[16];   /* all-zero = "null" version */
    uint32_t flags;            /* S3_OBJF_* */
    uint8_t  cksum_algo;       /* s3_cksum_algo_t */
    uint8_t  cksum_type;       /* 0 FULL_OBJECT, 1 COMPOSITE */
    uint16_t cksum_parts;      /* composite part count */
    uint8_t  cksum[32];        /* raw digest, left-aligned */
    uint8_t  reserved[8];
} obj_ext_v3_t;

_Static_assert(sizeof(obj_ext_v3_t) == 64, "obj_ext_v3_t layout");

/* Schema 4 (the last fixed migration): a second extension block and a
 * TLV area, then optional zero padding so header_size can be a multiple
 * of 4096 (block-aligned payloads make extent cloning possible):
 *
 *   [obj_header_t][obj_ext_v3_t][obj_ext_v4_t][ct][key][TLV...][pad][data]
 *
 * TLV records are [u16 type][u32 len][bytes] (little endian); unknown
 * types are skipped on read and preserved on copy. */
typedef struct __attribute__((packed)) {
    uint64_t stored_size;      /* payload bytes on disk (== data_size unless
                                  compressed or encrypted) */
    uint8_t  payload_crc64[8]; /* CRC64NVME over the on-disk payload, BE */
    uint32_t tlv_len;
    uint32_t pad_len;
    uint8_t  reserved[8];
} obj_ext_v4_t;

_Static_assert(sizeof(obj_ext_v4_t) == 32, "obj_ext_v4_t layout");

#define OBJ_MAX_TLV  (64 * 1024)
#define OBJ_MAX_PAD  4095

/* Upper bound on content-type bytes we write. */
#define OBJ_MAX_CT_LEN 1024

/* ===================================================================== */
/* Path computation and small helpers                                    */
/* ===================================================================== */

struct s3_store {
    char    *root;           /* absolute path, no trailing slash */
    char    *data_dir;       /* ROOT/data */
    char    *tmp_dir;        /* ROOT/tmp */
    char    *buckets_dir;    /* ROOT/buckets */
    char    *mpu_dir;        /* ROOT/mpu — multipart upload staging */
    char    *versions_dir;   /* ROOT/versions — noncurrent versions (item 8) */
    char    *locks_dir;      /* ROOT/locks — object lock sidecars (item 10) */
    store_version_guard_fn vguard;   /* object-lock veto (item 10) */
    void    *vguard_user;
    uint64_t min_free_bytes; /* 0 = no quota check */
    /* Namespace lock. Commits run on iopool worker threads while the
     * event loop keeps serving other requests, so the short steps that
     * create or remove entries in the live tree — bucket-exists check +
     * mkdir_p + rename, and rm_rf of bucket/upload dirs — are serialized
     * here. Never held across data writes or fsync of object bytes. */
    pthread_mutex_t ns_mu;

    /* Striped per-object locks (security review S4), indexed by the
     * first byte of the object's path hash. Held across every multi-step
     * mutation of one key — PUT/MPU publish, delete, lifecycle expiry
     * (re-check + unlink), versioning's link-aside + rename — so racing
     * sequences on the same key serialize. Order: key lock before ns_mu;
     * never two key locks at once. */
    pthread_mutex_t key_mu[256];

    int  pad_headers;        /* schema-4 headers padded to 4096 */
    uint64_t mpu_min_part;   /* minimum size of non-final parts (0 = none) */
    int  reflink;            /* filesystem supports FICLONE (probed) */
    /* Whole-object dedup (round 2, item 6b). */
    int      dedup_mode;     /* STORE_DEDUP_* */
    uint64_t dedup_min;
    int      dedup_verify;
    int      fs_compress;    /* STORE_COMPRESS_*; 0 if the probe failed */
    /* Before a version file is unlinked (item 9: fs3-lockd clears an
     * immutable flag only if retention allows). 0 = go ahead. */
    int    (*vunlink_hook)(void *user, const char *path);
    void    *vunlink_user;

    int  (*mpu_gc_filter)(void *user, s3_str_t bucket, s3_str_t key);
    void  *mpu_gc_filter_user;

    /* Quotas (round 2, item 2). q_mu is a leaf lock: nothing else is
     * taken while it is held. */
    pthread_mutex_t   q_mu;
    struct q_bucket  *qb;
    size_t            qb_n, qb_cap;
    struct q_user    *qu;
    size_t            qu_n, qu_cap;
    uint64_t          q_def_bucket, q_def_user;
    uint64_t          q_rejections;
    int               q_ready;

    /* Parsed bucket-config cache (store_sidecar_get). */
    pthread_mutex_t cfg_mu;
    struct store_cfg_ref *cfg_head;
    size_t           cfg_count;
};

static char *xstrdup_join(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    char *r = malloc(la + 1 + lb + 1);
    if (!r) return NULL;
    memcpy(r, a, la);
    r[la] = '/';
    memcpy(r + la + 1, b, lb);
    r[la + 1 + lb] = '\0';
    return r;
}

/* mkdir(path), but tolerate EEXIST. Returns 0 ok, -1 errno. */
static int mkdir_idempotent(const char *p, mode_t mode) {
    if (mkdir(p, mode) == 0) return 0;
    if (errno == EEXIST) return 0;
    return -1;
}

/* mkdir -p semantics. Walks the path, creating components. */
static int mkdir_p(const char *path, mode_t mode) {
    char buf[4096];
    size_t n = strlen(path);
    if (n + 1 > sizeof(buf)) { errno = ENAMETOOLONG; return -1; }
    memcpy(buf, path, n + 1);

    /* Skip leading '/' if absolute */
    char *p = buf[0] == '/' ? buf + 1 : buf;
    for (;;) {
        char *slash = strchr(p, '/');
        if (slash) *slash = '\0';
        if (mkdir_idempotent(buf, mode) < 0) return -1;
        if (!slash) break;
        *slash = '/';
        p = slash + 1;
    }
    return 0;
}

/* Test seams: tests override these to inject I/O failures (e.g. ENOSPC)
 * without needing a real full filesystem. NULL = use the real syscall. */
ssize_t (*s3_store_write_hook)(int fd, const void *buf, size_t n) = NULL;
int     (*s3_store_fsync_hook)(int fd) = NULL;

static ssize_t xwrite(int fd, const void *buf, size_t n) {
    return s3_store_write_hook ? s3_store_write_hook(fd, buf, n)
                               : write(fd, buf, n);
}

static int xfsync(int fd) {
    return s3_store_fsync_hook ? s3_store_fsync_hook(fd) : fsync(fd);
}

/* ENOSPC and EDQUOT both mean "the volume can't hold this" and must
 * surface as the storage error, not a generic 500. Note ENOSPC from a
 * buffered write may only appear at fsync/rename time (delayed
 * allocation), so every step of the durable sequence maps through here. */
static s3_err_t map_io_err(int err) {
    return (err == ENOSPC || err == EDQUOT) ? S3_ERR_INSUFFICIENT_STORAGE
                                            : S3_ERR_INTERNAL;
}

/* Open `dir` and fsync it. Used after rename to durably commit the dirent. */
static int fsync_dir(const char *dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return -1;
    int rc = fsync(fd);
    int e = errno;
    close(fd);
    if (rc < 0) { errno = e; return -1; }
    return 0;
}

/* SHA-256 over "bucket\0key" → hex. out must hold 65 bytes. */
static void hash_bucket_key(s3_str_t bucket, s3_str_t key, char out[65]) {
    EVP_MD_CTX *c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_sha256(), NULL);
    EVP_DigestUpdate(c, bucket.p, bucket.n);
    static const uint8_t z = 0;
    EVP_DigestUpdate(c, &z, 1);
    EVP_DigestUpdate(c, key.p, key.n);
    uint8_t raw[32];
    unsigned int rl = 32;
    EVP_DigestFinal_ex(c, raw, &rl);
    EVP_MD_CTX_free(c);

    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i*2 + 0] = hex[raw[i] >> 4];
        out[i*2 + 1] = hex[raw[i] & 0xF];
    }
    out[64] = '\0';
}

static int hexnib(char ch) {
    return ch >= 'a' ? ch - 'a' + 10 : ch - '0';
}

/* The stripe lock guarding object `hex` (S4). */
static pthread_mutex_t *key_lock(s3_store_t *s, const char hex[65]) {
    return &s->key_mu[(hexnib(hex[0]) << 4) | hexnib(hex[1])];
}

/* Build object directory path: ROOT/data/<bucket>/<xx>/<yy>
 * Returns 0 ok. out must hold at least 4096 bytes. */
static int obj_dir(const s3_store_t *s, s3_str_t bucket, const char hex[65],
                   char *out, size_t cap) {
    int n = snprintf(out, cap, "%s/" S3_STR_FMT "/%c%c/%c%c",
                     s->data_dir, S3_STR_ARG(bucket),
                     hex[0], hex[1], hex[2], hex[3]);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

static int obj_path(const s3_store_t *s, s3_str_t bucket, const char hex[65],
                    char *out, size_t cap) {
    int n = snprintf(out, cap, "%s/" S3_STR_FMT "/%c%c/%c%c/%s",
                     s->data_dir, S3_STR_ARG(bucket),
                     hex[0], hex[1], hex[2], hex[3], hex);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

/* Validate bucket name per S3 rules (subset).
 * - 3..63 chars
 * - lowercase letters, digits, hyphen, dot
 * - must begin/end with letter or digit
 * - no consecutive dots
 * - no '..' (already caught by no consecutive dots)
 * - no IP-address form (we skip this check; cheap to add later)
 */
static int valid_bucket_name(s3_str_t n) {
    if (n.n < 3 || n.n > 63) return 0;
    char prev = 0;
    for (size_t i = 0; i < n.n; i++) {
        char c = n.p[i];
        int is_lower = (c >= 'a' && c <= 'z');
        int is_digit = (c >= '0' && c <= '9');
        int is_dash  = (c == '-');
        int is_dot   = (c == '.');
        if (!(is_lower || is_digit || is_dash || is_dot)) return 0;
        if (i == 0 && !(is_lower || is_digit)) return 0;
        if (i == n.n - 1 && !(is_lower || is_digit)) return 0;
        if (is_dot && prev == '.') return 0;
        prev = c;
    }
    return 1;
}

/* Validate key per S3 rules (very permissive).
 * - 1..1024 bytes (we cap at 1024)
 * - any UTF-8 byte except NUL
 * - reject "" and reject keys containing NUL
 */
static int valid_key(s3_str_t k) {
    if (k.n == 0 || k.n > 1024) return 0;
    if (memchr(k.p, '\0', k.n)) return 0;
    return 1;
}

/* Build path ROOT/buckets/<name>. */
static int bucket_path(const s3_store_t *s, s3_str_t name,
                       char *out, size_t cap) {
    int n = snprintf(out, cap, "%s/" S3_STR_FMT, s->buckets_dir,
                     S3_STR_ARG(name));
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

/* Generate a temp file path under ROOT/tmp using mkstemp.
 * Returns fd on success (with the path written to out_path), -1 on error. */
static int tmp_open(const s3_store_t *s, char *out_path, size_t cap) {
    int n = snprintf(out_path, cap, "%s/fs3.XXXXXX", s->tmp_dir);
    if (n <= 0 || (size_t)n >= cap) { errno = ENAMETOOLONG; return -1; }
    int fd = mkstemp(out_path);
    if (fd < 0) return -1;
    /* mkstemp creates with 0600 by default; that's fine. */
    return fd;
}

/* ===================================================================== */
/* Lifecycle                                                              */
/* ===================================================================== */

/* Crash recovery: clear ROOT/tmp/. Every file there is by definition an
 * uncommitted write — commits rename *out* of tmp — so after an unclean
 * shutdown they are orphans that can never be part of a live object.
 * Unconditional and safe. The data/ tree is deliberately NOT scanned:
 * committed objects are atomic by construction (fsync-before-rename),
 * so there is nothing to verify there. MPU staging dirs are NOT touched
 * either — a fresh upload may be actively resumed by a client; the
 * periodic GC reaps them by TTL.
 *
 * Runs from store_open, before the server accepts connections, so it
 * cannot race a live writer. */
static int rm_rf(const char *path);

static void recover_tmp_dir(const s3_store_t *s) {
    DIR *d = opendir(s->tmp_dir);
    if (!d) return;
    int n = 0;
    uint64_t bytes = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char p[4096];
        if (snprintf(p, sizeof(p), "%s/%s", s->tmp_dir, e->d_name)
            >= (int)sizeof(p)) continue;
        struct stat st;
        if (lstat(p, &st) == 0 && S_ISDIR(st.st_mode)) {
            /* A bucket being assembled (store_bucket_create_owned). */
            if (rm_rf(p) == 0) n++;
            else LOG_W("recover: rm_rf %s: %s", p, strerror(errno));
            continue;
        }
        if (S_ISREG(st.st_mode)) bytes += (uint64_t)st.st_size;
        if (unlink(p) == 0) n++;
        else LOG_W("recover: unlink %s: %s", p, strerror(errno));
    }
    closedir(d);
    if (n > 0) {
        LOG_I("recovered %d orphaned temp file(s) (%llu bytes) from %s",
              n, (unsigned long long)bytes, s->tmp_dir);
    }
}

static void cfg_cache_clear(s3_store_t *s);
static void q_load(s3_store_t *s);
static void q_save(s3_store_t *s);
static void q_bucket_added(s3_store_t *s, s3_str_t name, const char *owner);
static void q_bucket_removed(s3_store_t *s, s3_str_t name);
static int  fd_is_known_corrupt(int fd, uint64_t mtime_ms);
static int  lock_parse_file(const char *path, s3_lock_t *out);
static int  bucket_layout(s3_store_t *s, s3_str_t bucket);
static s3_err_t l2_publish(s3_store_t *s, s3_str_t bucket, const char hex[65],
                           const char *tmp_file, uint64_t mtime_ms, const uint8_t vid[16]);
static void dedup_commit(s3_writer_t *w, const uint8_t dg[32]);
static void hex_name(const char *in, char *out, size_t cap);
static void hex16(const uint8_t *b, size_t n, char *out);
static void recover_version_links(const s3_store_t *s);
static void recover_mpu_orphans(const s3_store_t *s);
static int probe_reflink(const s3_store_t *s);

/* Startup: half-written object-lock sidecars (locks/.../<vid>.tmp.XXXXXX). */
static int lock_tmp_cb(const char *path, const struct stat *st, int type,
                       struct FTW *ftw) {
    (void)st; (void)ftw;
    const char *base = strrchr(path, '/');
    if (type == FTW_F && strstr(base ? base : path, ".tmp.")) unlink(path);
    return 0;
}
static void recover_lock_tmp(const s3_store_t *s) {
    nftw(s->locks_dir, lock_tmp_cb, 16, FTW_PHYS);
}
static int bucket_versioning(s3_store_t *s, s3_str_t bucket);
static int random_vid(uint8_t vid[16]);
static s3_err_t link_aside_locked(s3_store_t *s, s3_str_t bucket,
                                  const char hex[65], const char *path,
                                  int versioning);
static s3_err_t delete_locked(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                              const char hex[65], const uint8_t *vid,
                              uint64_t expect_mtime, store_delete_result_t *res);

/* Startup: remove half-written sidecars (buckets/<b>/<name>.tmp.XXXXXX
 * and meta.tmp) left by a crash between write and rename. */
static void recover_sidecar_tmp(const s3_store_t *s) {
    DIR *d = opendir(s->buckets_dir);
    if (!d) return;
    struct dirent *e;
    int n = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char bdir[4200];
        snprintf(bdir, sizeof(bdir), "%s/%s", s->buckets_dir, e->d_name);
        DIR *b = opendir(bdir);
        if (!b) continue;
        struct dirent *f;
        while ((f = readdir(b)) != NULL) {
            if (strstr(f->d_name, ".tmp.") || strcmp(f->d_name, "meta.tmp") == 0) {
                char p[4500];
                snprintf(p, sizeof(p), "%s/%s", bdir, f->d_name);
                if (unlink(p) == 0) n++;
            }
        }
        closedir(b);
    }
    closedir(d);
    if (n) LOG_I("recovery: removed %d orphaned bucket sidecar temp file(s)", n);
}

s3_err_t store_open(s3_store_t **out, const char *root) {
    if (!out || !root) return S3_ERR_INVALID_ARGUMENT;

    s3_store_t *s = calloc(1, sizeof(*s));
    if (!s) return S3_ERR_INTERNAL;
    pthread_mutex_init(&s->ns_mu, NULL);
    pthread_mutex_init(&s->cfg_mu, NULL);
    pthread_mutex_init(&s->q_mu, NULL);
    for (int i = 0; i < 256; i++) pthread_mutex_init(&s->key_mu[i], NULL);

    s->root        = strdup(root);
    s->data_dir    = xstrdup_join(root, "data");
    s->tmp_dir     = xstrdup_join(root, "tmp");
    s->buckets_dir = xstrdup_join(root, "buckets");
    s->mpu_dir     = xstrdup_join(root, "mpu");
    s->versions_dir = xstrdup_join(root, "versions");
    s->locks_dir   = xstrdup_join(root, "locks");
    if (!s->root || !s->data_dir || !s->tmp_dir || !s->buckets_dir || !s->mpu_dir
        || !s->versions_dir || !s->locks_dir) {
        store_close(s);
        return S3_ERR_INTERNAL;
    }

    if (mkdir_p(s->root, 0700) < 0
        || mkdir_p(s->data_dir, 0700) < 0
        || mkdir_p(s->tmp_dir, 0700) < 0
        || mkdir_p(s->buckets_dir, 0700) < 0
        || mkdir_p(s->mpu_dir, 0700) < 0
        || mkdir_p(s->versions_dir, 0700) < 0
        || mkdir_p(s->locks_dir, 0700) < 0) {
        LOG_E("store_open: mkdir failed under %s: %s", root, strerror(errno));
        store_close(s);
        return S3_ERR_INTERNAL;
    }

    recover_tmp_dir(s);
    recover_sidecar_tmp(s);
    recover_version_links(s);
    recover_lock_tmp(s);
    recover_mpu_orphans(s);
    s->reflink = probe_reflink(s);
    s->pad_headers = s->reflink;
    q_load(s);
    LOG_I("store: reflink %s", s->reflink ? "supported (headers padded to 4 KiB)"
                                          : "not supported (plain copies)");

    *out = s;
    return S3_OK;
}

void store_close(s3_store_t *s) {
    if (!s) return;
    q_save(s);
    free(s->qb);
    free(s->qu);
    pthread_mutex_destroy(&s->q_mu);
    free(s->root);
    free(s->data_dir);
    free(s->tmp_dir);
    free(s->buckets_dir);
    free(s->mpu_dir);
    free(s->versions_dir);
    free(s->locks_dir);
    pthread_mutex_destroy(&s->ns_mu);
    cfg_cache_clear(s);
    pthread_mutex_destroy(&s->cfg_mu);
    for (int i = 0; i < 256; i++) pthread_mutex_destroy(&s->key_mu[i]);
    free(s);
}

void store_set_min_free_bytes(s3_store_t *s, uint64_t min_free_bytes) {
    if (s) s->min_free_bytes = min_free_bytes;
}

/* Count non-hidden entries in a directory. Returns 0 if it can't open. */
static uint64_t count_dir_entries(const char *path) {
    DIR *d = opendir(path);
    if (!d) return 0;
    uint64_t n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] != '.') n++;
    }
    closedir(d);
    return n;
}

void store_admin_stats(s3_store_t *s, s3_admin_stats_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!s) return;

    out->buckets = count_dir_entries(s->buckets_dir);

    /* In-flight MPUs: one dir per upload under mpu/<bucket>/. */
    DIR *d = opendir(s->mpu_dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (e->d_name[0] == '.') continue;
            char p[4096];
            if (snprintf(p, sizeof(p), "%s/%s", s->mpu_dir, e->d_name)
                < (int)sizeof(p)) {
                out->mpu_inflight += count_dir_entries(p);
            }
        }
        closedir(d);
    }

    struct statvfs st;
    if (statvfs(s->root, &st) == 0) {
        uint64_t total = (uint64_t)st.f_frsize * st.f_blocks;
        uint64_t avail = (uint64_t)st.f_frsize * st.f_bavail;
        out->volume_free_bytes = avail;
        out->volume_used_bytes = total > avail ? total - avail : 0;
    }
}

/* Check disk quota. Returns S3_ERR_INSUFFICIENT_STORAGE if the filesystem
 * hosting the store root has fewer than s->min_free_bytes available.
 * Returns S3_OK if the quota is not set or if there is enough space.
 * Fails open (returns S3_OK) if statvfs itself fails. */
static s3_err_t quota_check(const s3_store_t *s) {
    if (!s || s->min_free_bytes == 0) return S3_OK;
    struct statvfs st;
    if (statvfs(s->root, &st) < 0) return S3_OK;
    uint64_t free_bytes = (uint64_t)st.f_bavail * (uint64_t)st.f_bsize;
    if (free_bytes < s->min_free_bytes) return S3_ERR_INSUFFICIENT_STORAGE;
    return S3_OK;
}

/* ===================================================================== */
/* Bucket ops                                                             */
/* ===================================================================== */

/* ---- Bucket metadata: buckets/<bucket>/meta ------------------------
 *
 *   id=<32 hex>       random per creation: a bucket deleted and re-created
 *                     under the same name is a different bucket
 *   owner=<user>      identity that owns it; empty = ownerless
 *
 * Buckets from before per-user isolation have no meta file: ownerless,
 * with an empty id. */

static int random_hex_id(char *out, size_t out_n);

/* Write `owner`/`id` as dir/meta, atomically (tmp + fsync + rename). */
static s3_err_t write_bucket_meta_full(const char *dir,
                                       const s3_bucket_meta_t *m) {
    char tmp[4200], final[4200];
    snprintf(tmp, sizeof(tmp), "%s/meta.tmp", dir);
    snprintf(final, sizeof(final), "%s/meta", dir);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return map_io_err(errno);
    char buf[512];
    int n = snprintf(buf, sizeof(buf), "id=%s\nowner=%s\n", m->id, m->owner);
    if (m->versioning && n > 0 && (size_t)n < sizeof(buf))
        n += snprintf(buf + n, sizeof(buf) - (size_t)n, "versioning=%s\n",
                      m->versioning == S3_VERSIONING_ENABLED ? "Enabled" : "Suspended");
    if (m->object_lock && n > 0 && (size_t)n < sizeof(buf))
        n += snprintf(buf + n, sizeof(buf) - (size_t)n, "object_lock=1\n");
    if (m->layout == 2 && n > 0 && (size_t)n < sizeof(buf))
        n += snprintf(buf + n, sizeof(buf) - (size_t)n, "layout=2\n");
    if (n < 0 || (size_t)n >= sizeof(buf)
        || xwrite(fd, buf, (size_t)n) != n || xfsync(fd) < 0) {
        s3_err_t e = (n < 0 || (size_t)n >= sizeof(buf))
                     ? S3_ERR_INTERNAL : map_io_err(errno);
        close(fd); unlink(tmp);
        return e;
    }
    close(fd);
    if (rename(tmp, final) < 0) {
        s3_err_t e = map_io_err(errno);
        unlink(tmp);
        return e;
    }
    fsync_dir(dir);
    return S3_OK;
}

/* Read <bucket_dir>/meta into out (fields "" if absent). */
static void read_bucket_meta(const char *bucket_dir, s3_bucket_meta_t *out) {
    memset(out, 0, sizeof(*out));
    char mp[4200];
    snprintf(mp, sizeof(mp), "%s/meta", bucket_dir);
    FILE *fp = fopen(mp, "re");
    if (!fp) return;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "id=", 3) == 0)
            snprintf(out->id, sizeof(out->id), "%.32s", line + 3);
        else if (strncmp(line, "owner=", 6) == 0)
            snprintf(out->owner, sizeof(out->owner), "%.128s", line + 6);
        else if (strcmp(line, "versioning=Enabled") == 0)
            out->versioning = S3_VERSIONING_ENABLED;
        else if (strcmp(line, "versioning=Suspended") == 0)
            out->versioning = S3_VERSIONING_SUSPENDED;
        else if (strcmp(line, "object_lock=1") == 0)
            out->object_lock = 1;
        else if (strcmp(line, "layout=2") == 0)
            out->layout = 2;
    }
    fclose(fp);
    /* Lock implies versioning, whatever the file says (fail safe). */
    if (out->object_lock) out->versioning = S3_VERSIONING_ENABLED;
}

s3_err_t store_bucket_create(s3_store_t *s, s3_str_t name) {
    return store_bucket_create_owned(s, name, NULL);
}

/* The bucket dir and its meta are assembled under tmp/ and renamed into
 * buckets/ in one step, so a bucket never exists without its owner
 * (a crash leaves only a tmp/ dir, swept at startup). */
static s3_err_t bucket_create(s3_store_t *s, s3_str_t name,
                              const char *owner, int locked);

s3_err_t store_bucket_create_owned(s3_store_t *s, s3_str_t name,
                                   const char *owner) {
    return bucket_create(s, name, owner, 0);
}

s3_err_t store_bucket_create_locked(s3_store_t *s, s3_str_t name,
                                    const char *owner) {
    return bucket_create(s, name, owner, 1);
}

s3_err_t store_bucket_set_versioning(s3_store_t *s, s3_str_t name, int state) {
    if (!s || state < 0 || state > 2) return S3_ERR_INVALID_ARGUMENT;
    char bp[4096];
    if (bucket_path(s, name, bp, sizeof(bp)) < 0) return S3_ERR_INTERNAL;
    pthread_mutex_lock(&s->ns_mu);
    s3_err_t e = S3_ERR_NO_SUCH_BUCKET;
    if (store_bucket_exists(s, name)) {
        s3_bucket_meta_t m;
        read_bucket_meta(bp, &m);
        if ((m.versioning && state == S3_VERSIONING_UNSET)
            || (m.object_lock && state != S3_VERSIONING_ENABLED)) {
            e = S3_ERR_INVALID_REQUEST;
        } else {
            if (!m.id[0]) random_hex_id(m.id, sizeof(m.id));
            m.versioning = state;
            e = write_bucket_meta_full(bp, &m);
        }
    }
    pthread_mutex_unlock(&s->ns_mu);
    return e;
}

const char *store_bucket_versioning(s3_store_t *s, s3_str_t name) {
    s3_bucket_meta_t m;
    if (store_bucket_meta(s, name, &m) != S3_OK) return "";
    return m.versioning == S3_VERSIONING_ENABLED ? "Enabled"
         : m.versioning == S3_VERSIONING_SUSPENDED ? "Suspended" : "Unset";
}

int store_bucket_object_lock(s3_store_t *s, s3_str_t name) {
    s3_bucket_meta_t m;
    return store_bucket_meta(s, name, &m) == S3_OK && m.object_lock;
}

static s3_err_t bucket_create(s3_store_t *s, s3_str_t name,
                              const char *owner, int locked) {
    if (!s) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(name)) return S3_ERR_INVALID_BUCKET_NAME;

    char bp[4096];
    if (bucket_path(s, name, bp, sizeof(bp)) < 0) return S3_ERR_INTERNAL;

    char stage[4096], id[33];
    snprintf(stage, sizeof(stage), "%s/bucket.XXXXXX", s->tmp_dir);
    if (random_hex_id(id, sizeof(id)) < 0) return S3_ERR_INTERNAL;
    if (!mkdtemp(stage)) return map_io_err(errno);
    s3_bucket_meta_t nm;
    memset(&nm, 0, sizeof(nm));
    snprintf(nm.id, sizeof(nm.id), "%s", id);
    snprintf(nm.owner, sizeof(nm.owner), "%s", owner ? owner : "");
    /* Object-lock buckets get layout 2 (item 9): every version, the
     * current one too, lives in versions/; data/ holds symlinks, so no
     * write ever links or renames a (possibly immutable) version inode. */
    if (locked) { nm.object_lock = 1; nm.versioning = S3_VERSIONING_ENABLED; nm.layout = 2; }
    s3_err_t e = write_bucket_meta_full(stage, &nm);
    if (e != S3_OK) { rm_rf(stage); return e; }

    /* ns_mu: the exists check and the rename are one step. rename() would
     * also replace an *empty* dir — a pre-isolation bucket marker — so
     * the explicit check is what keeps an existing bucket from being
     * taken over. */
    pthread_mutex_lock(&s->ns_mu);
    if (store_bucket_exists(s, name)) {
        e = S3_ERR_BUCKET_ALREADY_EXISTS;
    } else if (rename(stage, bp) < 0) {
        LOG_W("bucket_create %s: %s", bp, strerror(errno));
        e = map_io_err(errno);
    } else {
        /* Pre-create the per-bucket data subtree to avoid races later. */
        char dp[4096];
        snprintf(dp, sizeof(dp), "%s/" S3_STR_FMT, s->data_dir,
                 S3_STR_ARG(name));
        (void)mkdir(dp, 0700);
    }
    pthread_mutex_unlock(&s->ns_mu);
    if (e != S3_OK) { rm_rf(stage); return e; }
    fsync_dir(s->buckets_dir);
    q_bucket_added(s, name, nm.owner);
    return S3_OK;
}

s3_err_t store_bucket_meta(s3_store_t *s, s3_str_t name,
                           s3_bucket_meta_t *out) {
    if (!s || !out) return S3_ERR_INVALID_ARGUMENT;
    char bp[4096];
    if (bucket_path(s, name, bp, sizeof(bp)) < 0) return S3_ERR_INTERNAL;
    if (!store_bucket_exists(s, name)) return S3_ERR_NO_SUCH_BUCKET;
    read_bucket_meta(bp, out);
    return S3_OK;
}

s3_err_t store_bucket_set_owner(s3_store_t *s, s3_str_t name,
                                const char *owner) {
    if (!s || !owner) return S3_ERR_INVALID_ARGUMENT;
    char bp[4096];
    if (bucket_path(s, name, bp, sizeof(bp)) < 0) return S3_ERR_INTERNAL;
    pthread_mutex_lock(&s->ns_mu);
    s3_err_t e = S3_ERR_NO_SUCH_BUCKET;
    if (store_bucket_exists(s, name)) {
        s3_bucket_meta_t m;
        read_bucket_meta(bp, &m);
        /* A pre-isolation bucket gets its id now; any upload still
         * streaming into it (captured id "") will then fail its commit
         * rather than land in a bucket that changed hands. */
        if (!m.id[0] && random_hex_id(m.id, sizeof(m.id)) < 0) {
            e = S3_ERR_INTERNAL;
        } else {
            snprintf(m.owner, sizeof(m.owner), "%s", owner);
            e = write_bucket_meta_full(bp, &m);
        }
    }
    pthread_mutex_unlock(&s->ns_mu);
    if (e == S3_OK) q_bucket_added(s, name, owner);   /* updates the owner */
    return e;
}

int store_assign_legacy_owner(s3_store_t *s, const char *owner) {
    s3_bucket_info_t *list = NULL;
    size_t n = 0;
    if (store_list_buckets(s, &list, &n) != S3_OK) return -1;
    int assigned = 0;
    for (size_t i = 0; i < n; i++) {
        if (list[i].owner[0]) continue;
        s3_str_t name = { list[i].name, strlen(list[i].name) };
        if (store_bucket_set_owner(s, name, owner) == S3_OK) {
            assigned++;
        } else {
            LOG_W("legacy owner: could not assign %s", list[i].name);
        }
    }
    store_buckets_free(list, n);
    return assigned;
}

int store_bucket_exists(s3_store_t *s, s3_str_t name) {
    char bp[4096];
    if (bucket_path(s, name, bp, sizeof(bp)) < 0) return 0;
    struct stat st;
    return stat(bp, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Recursively check whether a directory tree contains any regular files. */
static int dir_has_files(const char *path) {
    DIR *d = opendir(path);
    if (!d) return 0;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' || (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;
        char child[4096];
        snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
        struct stat st;
        if (lstat(child, &st) < 0) continue;
        if (S_ISREG(st.st_mode)) { found = 1; break; }
        if (S_ISDIR(st.st_mode)) {
            if (dir_has_files(child)) { found = 1; break; }
        }
    }
    closedir(d);
    return found;
}

static int rm_rf(const char *path);   /* defined with the MPU helpers */

/* Recursively rmdir a tree of empty directories. */
static int rmdir_tree(const char *path) {
    DIR *d = opendir(path);
    if (!d) return -1;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' &&
            (e->d_name[1] == '\0' || (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;
        char child[4096];
        snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
        struct stat st;
        if (lstat(child, &st) < 0) continue;
        if (S_ISDIR(st.st_mode)) rmdir_tree(child);
        /* We never delete files here; caller has ensured none exist. */
    }
    closedir(d);
    return rmdir(path);
}

static s3_err_t bucket_delete_locked(s3_store_t *s, s3_str_t name) {
    if (!store_bucket_exists(s, name)) return S3_ERR_NO_SUCH_BUCKET;

    char dp[4096];
    snprintf(dp, sizeof(dp), "%s/" S3_STR_FMT, s->data_dir, S3_STR_ARG(name));
    if (dir_has_files(dp)) return S3_ERR_BUCKET_NOT_EMPTY;
    /* Versioning: noncurrent versions and delete markers count too. */
    char vp[4096];
    snprintf(vp, sizeof(vp), "%s/" S3_STR_FMT, s->versions_dir, S3_STR_ARG(name));
    if (dir_has_files(vp)) return S3_ERR_BUCKET_NOT_EMPTY;
    rm_rf(vp);
    snprintf(vp, sizeof(vp), "%s/" S3_STR_FMT, s->locks_dir, S3_STR_ARG(name));
    rm_rf(vp);

    /* Drop any in-flight multipart uploads first. Left behind, they could
     * be completed into a later bucket of the same name. */
    char mp[4096];
    snprintf(mp, sizeof(mp), "%s/" S3_STR_FMT, s->mpu_dir, S3_STR_ARG(name));
    if (rm_rf(mp) < 0) {
        LOG_W("bucket_delete rm_rf %s: %s", mp, strerror(errno));
        return S3_ERR_INTERNAL;
    }

    /* Remove empty subtree under data/<bucket>/, then bucket marker dir. */
    rmdir_tree(dp);

    char bp[4096];
    if (bucket_path(s, name, bp, sizeof(bp)) < 0) return S3_ERR_INTERNAL;
    /* The marker dir holds meta plus config sidecars (grants, cors.xml,
     * ...). Move it out of buckets/ in one rename, so the bucket vanishes
     * atomically (never ownerless-but-present after a crash), then remove
     * it; a crash in between leaves only a tmp/bucket.* dir, swept at
     * startup. */
    char gone[4096];
    snprintf(gone, sizeof(gone), "%s/bucket.XXXXXX", s->tmp_dir);
    if (!mkdtemp(gone) || rename(bp, gone) < 0) {
        LOG_W("bucket_delete move %s: %s", bp, strerror(errno));
        rmdir(gone);
        return S3_ERR_INTERNAL;
    }
    fsync_dir(s->buckets_dir);
    rm_rf(gone);
    return S3_OK;
}

/* Under ns_mu, so a commit on a worker thread lands either before (the
 * bucket is non-empty) or after (NoSuchBucket), never in between. */
s3_err_t store_bucket_delete(s3_store_t *s, s3_str_t name) {
    if (!s) return S3_ERR_INVALID_ARGUMENT;
    pthread_mutex_lock(&s->ns_mu);
    s3_err_t e = bucket_delete_locked(s, name);
    pthread_mutex_unlock(&s->ns_mu);
    if (e == S3_OK) q_bucket_removed(s, name);
    return e;
}

/* ===================================================================== */
/* Header padding / reflink probe (schema 4)                              */
/* ===================================================================== */

static uint32_t obj_pad_for(const s3_store_t *s, size_t base) {
    if (!s || !s->pad_headers) return 0;
    return (uint32_t)((4096 - base % 4096) % 4096);
}

int store_set_header_pad(s3_store_t *s, int on) {
    int old = s->pad_headers;
    s->pad_headers = on ? 1 : 0;
    return old;
}

int store_reflink_capable(const s3_store_t *s) { return s->reflink; }

/* Try FICLONE between two temp files: Btrfs/XFS say yes, ext4 no. */
static int probe_reflink(const s3_store_t *s) {
    char a[4200], b[4200];
    snprintf(a, sizeof(a), "%s/probe.XXXXXX", s->tmp_dir);
    snprintf(b, sizeof(b), "%s/probe.XXXXXX", s->tmp_dir);
    int fa = mkstemp(a);
    if (fa < 0) return 0;
    int fb = mkstemp(b);
    if (fb < 0) { close(fa); unlink(a); return 0; }
    static char blk[4096];
    int ok = write(fa, blk, sizeof(blk)) == (ssize_t)sizeof(blk)
             && ioctl(fb, FICLONE, fa) == 0;
    close(fa); close(fb);
    unlink(a); unlink(b);
    return ok;
}

/* Reflink fast paths (round 2, item 6a). Btrfs/XFS clone ioctls need a
 * block-aligned source offset, destination offset and length; the
 * length may be unaligned only when it runs to the source's EOF. */
#define CLONE_BLK 4096u

/* Filesystem compression (round 2, item 7a): FS_COMPR_FL on the temp
 * file before the first write; Btrfs then compresses extents itself, so
 * sendfile, Range, reflinks and the on-disk format are untouched. */
static int set_compr_flag(int fd) {
    int fl = 0;
    if (ioctl(fd, FS_IOC_GETFLAGS, &fl) < 0) return -1;
    fl |= FS_COMPR_FL;
    return ioctl(fd, FS_IOC_SETFLAGS, &fl);
}

int store_set_fs_compress(s3_store_t *s, int mode) {
    if (mode == STORE_COMPRESS_OFF) { s->fs_compress = 0; return 0; }
    char p[4200];
    snprintf(p, sizeof(p), "%s/compr.XXXXXX", s->tmp_dir);
    int fd = mkstemp(p);
    int ok = fd >= 0 && set_compr_flag(fd) == 0;
    if (fd >= 0) { close(fd); unlink(p); }
    s->fs_compress = ok ? mode : 0;
    return ok ? 0 : -1;
}

/* auto: skip what is already compressed, and tiny objects. */
static int compress_worth_it(const s3_store_t *s, const char *ct, const char *key, size_t key_n,
                             uint64_t size_hint) {
    if (s->fs_compress == STORE_COMPRESS_ALL) return 1;
    if (s->fs_compress != STORE_COMPRESS_AUTO) return 0;
    if (size_hint && size_hint < 4096) return 0;
    static const char *ct_skip[] = { "image/jpeg", "image/png", "image/gif", "image/webp",
        "image/avif", "image/heic", "video/", "audio/", "application/zip", "application/gzip",
        "application/x-gzip", "application/zstd", "application/x-7z", "application/x-xz",
        "application/x-bzip2", "application/x-rar", "application/pdf", NULL };
    for (int i = 0; ct && ct_skip[i]; i++)
        if (!strncasecmp(ct, ct_skip[i], strlen(ct_skip[i]))) return 0;
    static const char *sfx[] = { ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".avif",
        ".mp4", ".mkv", ".mov", ".avi", ".mp3", ".aac", ".flac", ".ogg", ".opus", ".zip", ".gz",
        ".tgz", ".zst", ".xz", ".bz2", ".7z", ".rar", ".pdf", ".jar", ".apk", NULL };
    for (int i = 0; key && sfx[i]; i++) {
        size_t n = strlen(sfx[i]);
        if (key_n >= n && !strncasecmp(key + key_n - n, sfx[i], n)) return 0;
    }
    return 1;
}

/* Tests force the clone paths off (pure copy) or keep the probe result. */
int store_set_reflink(s3_store_t *s, int on) {
    int old = s->reflink;
    s->reflink = on ? s->reflink || probe_reflink(s) : 0;
    return old;
}

uint64_t g_store_clone_count;      /* clones done (tests / metrics), atomic */

/* 0 cloned, -1 not possible here (caller copies instead). */
static int clone_range(int dst, uint64_t doff, int src, uint64_t soff, uint64_t len) {
#ifdef FICLONERANGE
    if (len == 0) return 0;
    struct stat st;
    if (fstat(src, &st) < 0) return -1;
    int to_eof = soff + len == (uint64_t)st.st_size;
    if (doff % CLONE_BLK || soff % CLONE_BLK || (len % CLONE_BLK && !to_eof)) return -1;
    struct file_clone_range r = { .src_fd = src, .src_offset = soff,
                                  .src_length = to_eof ? 0 : len,   /* 0 = to EOF */
                                  .dest_offset = doff };
    if (ioctl(dst, FICLONERANGE, &r) < 0) return -1;
    __atomic_fetch_add(&g_store_clone_count, 1, __ATOMIC_RELAXED);
    return 0;
#else
    (void)dst; (void)doff; (void)src; (void)soff; (void)len;
    return -1;
#endif
}

/* ===================================================================== */
/* Bucket config sidecars + parsed-config cache                           */
/* ===================================================================== */

struct store_cfg_ref {
    char      key[33 + 1 + 64 + 1 + 32];  /* "<id or :name or ?name>/<sidecar>" */
    char      bname[64];      /* bucket name, for TTL lookups */
    char      sname[32];      /* sidecar name */
    uint64_t  checked_ms;     /* last validation (monotonic) */
    dev_t     dev;
    ino_t     ino;
    int64_t   mtime_ns;
    off_t     size;
    void     *obj;
    store_cfg_free_fn release;
    int       refs;           /* holders, plus 1 while cached */
    int       cached;
    struct store_cfg_ref *next;
};

static int sidecar_path(s3_store_t *s, s3_str_t bucket, const char *name,
                        char *out, size_t cap) {
    if (!valid_bucket_name(bucket)) return -1;
    int n = snprintf(out, cap, "%s/" S3_STR_FMT "/%s", s->buckets_dir,
                     S3_STR_ARG(bucket), name);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

s3_err_t store_bucket_sidecar_write(s3_store_t *s, s3_str_t bucket,
                                    const char *name,
                                    const void *data, size_t n) {
    char final[4200], tmp[4300], dir[4200];
    if (!s || sidecar_path(s, bucket, name, final, sizeof(final)) < 0)
        return S3_ERR_INVALID_ARGUMENT;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;
    snprintf(dir, sizeof(dir), "%s/" S3_STR_FMT, s->buckets_dir, S3_STR_ARG(bucket));
    snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", final);
    int fd = mkstemp(tmp);
    if (fd < 0) return map_io_err(errno);
    if ((n && xwrite(fd, data, n) != (ssize_t)n) || xfsync(fd) < 0) {
        s3_err_t e = map_io_err(errno);
        close(fd); unlink(tmp);
        return e;
    }
    close(fd);
    pthread_mutex_lock(&s->ns_mu);
    int rc = store_bucket_exists(s, bucket) ? rename(tmp, final) : -1;
    int err = errno;
    pthread_mutex_unlock(&s->ns_mu);
    if (rc < 0) {
        unlink(tmp);
        return store_bucket_exists(s, bucket) ? map_io_err(err)
                                              : S3_ERR_NO_SUCH_BUCKET;
    }
    fsync_dir(dir);
    return S3_OK;
}

s3_err_t store_bucket_sidecar_read(s3_store_t *s, s3_str_t bucket,
                                   const char *name, size_t max,
                                   char **out, size_t *n_out) {
    char path[4200];
    if (!s || sidecar_path(s, bucket, name, path, sizeof(path)) < 0)
        return S3_ERR_INVALID_ARGUMENT;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? S3_ERR_NO_SUCH_KEY : S3_ERR_INTERNAL;
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) { close(fd); return S3_ERR_INTERNAL; }
    if ((uint64_t)st.st_size > max) { close(fd); return S3_ERR_ENTITY_TOO_LARGE; }
    char *b = malloc((size_t)st.st_size + 1);
    if (!b) { close(fd); return S3_ERR_INTERNAL; }
    ssize_t got = pread(fd, b, (size_t)st.st_size, 0);
    close(fd);
    if (got != st.st_size) { free(b); return S3_ERR_INTERNAL; }
    b[got] = '\0';
    *out = b;
    *n_out = (size_t)got;
    return S3_OK;
}

s3_err_t store_bucket_sidecar_delete(s3_store_t *s, s3_str_t bucket,
                                     const char *name) {
    char path[4200], dir[4200];
    if (!s || sidecar_path(s, bucket, name, path, sizeof(path)) < 0)
        return S3_ERR_INVALID_ARGUMENT;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;
    if (unlink(path) < 0 && errno != ENOENT) return map_io_err(errno);
    snprintf(dir, sizeof(dir), "%s/" S3_STR_FMT, s->buckets_dir, S3_STR_ARG(bucket));
    fsync_dir(dir);
    return S3_OK;
}

static void cfg_unref_locked(struct store_cfg_ref *r) {
    if (--r->refs == 0) {
        if (r->obj) r->release(r->obj);
        free(r);
    }
}

void *store_cfg_obj(const store_cfg_ref_t *r) { return r ? r->obj : NULL; }

static void cfg_cache_clear(s3_store_t *s) {
    while (s->cfg_head) {
        struct store_cfg_ref *n = s->cfg_head->next;
        s->cfg_head->cached = 0;
        cfg_unref_locked(s->cfg_head);
        s->cfg_head = n;
    }
    s->cfg_count = 0;
}

void store_sidecar_put(s3_store_t *s, store_cfg_ref_t *r) {
    if (!s || !r) return;
    pthread_mutex_lock(&s->cfg_mu);
    cfg_unref_locked(r);
    pthread_mutex_unlock(&s->cfg_mu);
}

/* Drop a cache entry (caller holds cfg_mu). */
static void cfg_evict_locked(s3_store_t *s, struct store_cfg_ref **pp) {
    struct store_cfg_ref *r = *pp;
    *pp = r->next;
    r->cached = 0;
    s->cfg_count--;
    cfg_unref_locked(r);
}

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* Insert r at the head, first evicting entries for the same bucket name +
 * sidecar (stale positives, negatives) and bounding the cache. */
static void cfg_insert_locked(s3_store_t *s, struct store_cfg_ref *r) {
    struct store_cfg_ref **q = &s->cfg_head;
    while (*q) {
        if (strcmp((*q)->bname, r->bname) == 0 && strcmp((*q)->sname, r->sname) == 0)
            cfg_evict_locked(s, q);
        else
            q = &(*q)->next;
    }
    if (s->cfg_count >= 1024) {
        q = &s->cfg_head;
        size_t i = 0;
        while (*q && i < 512) { q = &(*q)->next; i++; }
        while (*q) cfg_evict_locked(s, q);
    }
    r->next = s->cfg_head;
    s->cfg_head = r;
    s->cfg_count++;
}

store_cfg_ref_t *store_sidecar_get(s3_store_t *s, s3_str_t bucket,
                                   const char *name, size_t max,
                                   store_cfg_parse_fn parse,
                                   store_cfg_free_fn release) {
    return store_sidecar_get_ttl(s, bucket, name, max, parse, release, 0);
}

store_cfg_ref_t *store_sidecar_get_ttl(s3_store_t *s, s3_str_t bucket,
                                       const char *name, size_t max,
                                       store_cfg_parse_fn parse,
                                       store_cfg_free_fn release,
                                       unsigned ttl_ms) {
    char path[4200];
    if (!s || bucket.n >= 64 || strlen(name) >= 32
        || sidecar_path(s, bucket, name, path, sizeof(path)) < 0) return NULL;
    char bname[64];
    memcpy(bname, bucket.p, bucket.n);
    bname[bucket.n] = '\0';
    uint64_t now = mono_ms();

    if (ttl_ms) {
        /* Recently validated (positive or negative): no disk access. */
        pthread_mutex_lock(&s->cfg_mu);
        for (struct store_cfg_ref *r = s->cfg_head; r; r = r->next) {
            if (strcmp(r->bname, bname) || strcmp(r->sname, name)) continue;
            if (now - r->checked_ms >= ttl_ms) break;
            if (!r->obj) { pthread_mutex_unlock(&s->cfg_mu); return NULL; }
            r->refs++;
            pthread_mutex_unlock(&s->cfg_mu);
            return r;
        }
        pthread_mutex_unlock(&s->cfg_mu);
    }

    s3_bucket_meta_t bm;
    int have_bucket = store_bucket_meta(s, bucket, &bm) == S3_OK;
    char key[sizeof(((struct store_cfg_ref *)0)->key)];
    if (!have_bucket)
        snprintf(key, sizeof(key), "?%s/%s", bname, name);
    else if (bm.id[0])
        snprintf(key, sizeof(key), "%s/%s", bm.id, name);
    else
        snprintf(key, sizeof(key), ":%s/%s", bname, name);

    struct stat st;
    int have = have_bucket && stat(path, &st) == 0 && S_ISREG(st.st_mode);
    int64_t mns = have ? (int64_t)st.st_mtim.tv_sec * 1000000000LL + st.st_mtim.tv_nsec : 0;

    pthread_mutex_lock(&s->cfg_mu);
    for (struct store_cfg_ref *r = s->cfg_head; r; r = r->next) {
        if (strcmp(r->key, key) != 0) continue;
        if (have && r->obj && r->dev == st.st_dev && r->ino == st.st_ino
            && r->mtime_ns == mns && r->size == st.st_size) {
            r->refs++;
            r->checked_ms = now;
            pthread_mutex_unlock(&s->cfg_mu);
            return r;
        }
        break;
    }
    if (!have) {
        /* Remember the absence only when asked to (TTL lookups). */
        if (ttl_ms) {
            struct store_cfg_ref *neg = calloc(1, sizeof(*neg));
            if (neg) {
                snprintf(neg->key, sizeof(neg->key), "%s", key);
                snprintf(neg->bname, sizeof(neg->bname), "%s", bname);
                snprintf(neg->sname, sizeof(neg->sname), "%s", name);
                neg->release = release;
                neg->refs = 1;
                neg->cached = 1;
                neg->checked_ms = now;
                cfg_insert_locked(s, neg);
            }
        }
        pthread_mutex_unlock(&s->cfg_mu);
        return NULL;
    }
    pthread_mutex_unlock(&s->cfg_mu);

    /* Parse outside the lock. */
    char *data = NULL;
    size_t n = 0;
    if (store_bucket_sidecar_read(s, bucket, name, max, &data, &n) != S3_OK)
        return NULL;
    void *obj = parse(data, n);
    free(data);
    struct store_cfg_ref *r = calloc(1, sizeof(*r));
    if (!r) { if (obj) release(obj); return NULL; }
    snprintf(r->key, sizeof(r->key), "%s", key);
    snprintf(r->bname, sizeof(r->bname), "%s", bname);
    snprintf(r->sname, sizeof(r->sname), "%s", name);
    r->dev = st.st_dev; r->ino = st.st_ino; r->mtime_ns = mns; r->size = st.st_size;
    r->obj = obj;
    r->release = release;
    r->refs = obj ? 2 : 1;     /* cache (+ caller) */
    r->cached = 1;
    r->checked_ms = now;
    pthread_mutex_lock(&s->cfg_mu);
    cfg_insert_locked(s, r);
    pthread_mutex_unlock(&s->cfg_mu);
    return obj ? r : NULL;
}

/* ---- Grants ---------------------------------------------------------- */

#define GRANTS_MAX_BYTES (64 * 1024)

typedef struct { size_t n; s3_grant_t *g; } grant_list_t;

int store_grant_parse_perms(const char *p, size_t n) {
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        int b = p[i] == 'r' ? S3_GRANT_R : p[i] == 'w' ? S3_GRANT_W
              : p[i] == 'o' ? S3_GRANT_O : -1;
        if (b < 0 || (bits & b)) return -1;
        bits |= b;
    }
    return bits;
}

static void grants_free(void *o) {
    grant_list_t *l = o;
    if (l) { free(l->g); free(l); }
}

/* Lines "user:perms". Malformed lines are skipped (logged once per parse):
 * a bad line must never be read as a broader grant. */
static void *grants_parse(const char *d, size_t n) {
    grant_list_t *l = calloc(1, sizeof(*l));
    if (!l) return NULL;
    size_t cap = 0, i = 0;
    while (i < n) {
        size_t st = i;
        while (i < n && d[i] != '\n') i++;
        size_t e = i;
        if (i < n) i++;
        if (e == st || d[st] == '#') continue;
        const char *colon = memchr(d + st, ':', e - st);
        if (!colon) continue;
        size_t un = (size_t)(colon - (d + st));
        char user[129];
        if (un == 0 || un > 128) continue;
        memcpy(user, d + st, un);
        user[un] = '\0';
        int perms = store_grant_parse_perms(colon + 1, e - (size_t)(colon - d) - 1);
        if (!s3_valid_ident_strict(user) || perms <= 0) {
            LOG_W("grants: ignoring malformed line");
            continue;
        }
        if (l->n == cap) {
            size_t nc = cap ? cap * 2 : 8;
            s3_grant_t *ng = realloc(l->g, nc * sizeof(*ng));
            if (!ng) { grants_free(l); return NULL; }
            l->g = ng; cap = nc;
        }
        snprintf(l->g[l->n].user, sizeof(l->g[l->n].user), "%s", user);
        l->g[l->n].perms = perms;
        l->n++;
    }
    return l;
}

int store_bucket_grant_perms(s3_store_t *s, s3_str_t bucket, const char *user) {
    store_cfg_ref_t *r = store_sidecar_get(s, bucket, "grants", GRANTS_MAX_BYTES,
                                           grants_parse, grants_free);
    if (!r) return 0;
    const grant_list_t *l = store_cfg_obj(r);
    int perms = 0;
    for (size_t i = 0; i < l->n; i++)
        if (strcmp(l->g[i].user, user) == 0) perms |= l->g[i].perms;
    store_sidecar_put(s, r);
    return perms;
}

s3_err_t store_bucket_grants_get(s3_store_t *s, s3_str_t bucket,
                                 s3_grant_t **out, size_t *n_out) {
    *out = NULL;
    *n_out = 0;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;
    store_cfg_ref_t *r = store_sidecar_get(s, bucket, "grants", GRANTS_MAX_BYTES,
                                           grants_parse, grants_free);
    if (!r) return S3_OK;
    const grant_list_t *l = store_cfg_obj(r);
    if (l->n) {
        *out = malloc(l->n * sizeof(**out));
        if (!*out) { store_sidecar_put(s, r); return S3_ERR_INTERNAL; }
        memcpy(*out, l->g, l->n * sizeof(**out));
        *n_out = l->n;
    }
    store_sidecar_put(s, r);
    return S3_OK;
}

s3_err_t store_bucket_grant_set(s3_store_t *s, s3_str_t bucket,
                                const char *user, int perms) {
    if (!user || !s3_valid_ident_strict(user) || perms < 0 || perms > 7)
        return S3_ERR_INVALID_ARGUMENT;
    s3_grant_t *g = NULL;
    size_t n = 0;
    s3_err_t e = store_bucket_grants_get(s, bucket, &g, &n);
    if (e != S3_OK) return e;
    size_t cap = (n + 1) * (128 + 8) + 1;
    char *buf = malloc(cap);
    if (!buf) { free(g); return S3_ERR_INTERNAL; }
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(g[i].user, user) == 0) continue;
        o += (size_t)snprintf(buf + o, cap - o, "%s:%s%s%s\n", g[i].user,
                              g[i].perms & S3_GRANT_R ? "r" : "",
                              g[i].perms & S3_GRANT_W ? "w" : "",
                              g[i].perms & S3_GRANT_O ? "o" : "");
    }
    if (perms)
        o += (size_t)snprintf(buf + o, cap - o, "%s:%s%s%s\n", user,
                              perms & S3_GRANT_R ? "r" : "",
                              perms & S3_GRANT_W ? "w" : "",
                              perms & S3_GRANT_O ? "o" : "");
    free(g);
    e = store_bucket_sidecar_write(s, bucket, "grants", buf, o);
    free(buf);
    return e;
}

/* ===================================================================== */
/* Streaming PUT                                                          */
/* ===================================================================== */

/* Padding that makes `base` a multiple of 4096, when the store pads
 * headers (reflink-capable filesystem); 0 otherwise. */
static uint32_t obj_pad_for(const s3_store_t *s, size_t base);

/* Write the complete object prefix (fixed blocks, ct, key, TLV, zero pad)
 * at the current file position; fills h->header_size and x4 lengths. */
static int obj_write_prefix(const s3_store_t *s, int fd, obj_header_t *h,
                            obj_ext_v3_t *x3, obj_ext_v4_t *x4,
                            const char *ct, size_t ct_n,
                            const char *key, size_t key_n,
                            const uint8_t *tlv, size_t tlv_n) {
    if (ct_n > OBJ_MAX_CT_LEN || key_n > UINT16_MAX || tlv_n > OBJ_MAX_TLV) {
        errno = EINVAL;
        return -1;
    }
    size_t base = sizeof(*h) + sizeof(*x3) + sizeof(*x4) + ct_n + key_n + tlv_n;
    uint32_t pad = obj_pad_for(s, base);
    memcpy(h->magic, OBJ_MAGIC, OBJ_MAGIC_LEN);
    h->schema = OBJ_SCHEMA;
    h->ct_len = (uint16_t)ct_n;
    h->key_len = (uint16_t)key_n;
    h->header_size = (uint32_t)(base + pad);
    x4->tlv_len = (uint32_t)tlv_n;
    x4->pad_len = pad;
    static const char zeros[4096];
    if (xwrite(fd, h, sizeof(*h)) != (ssize_t)sizeof(*h)
        || xwrite(fd, x3, sizeof(*x3)) != (ssize_t)sizeof(*x3)
        || xwrite(fd, x4, sizeof(*x4)) != (ssize_t)sizeof(*x4)
        || (ct_n && xwrite(fd, ct, ct_n) != (ssize_t)ct_n)
        || (key_n && xwrite(fd, key, key_n) != (ssize_t)key_n)
        || (tlv_n && xwrite(fd, tlv, tlv_n) != (ssize_t)tlv_n)
        || (pad && xwrite(fd, zeros, pad) != (ssize_t)pad))
        return -1;
    return 0;
}

/* Rewrite the three fixed blocks in place (commit time). */
static int obj_rewrite_fixed(int fd, const obj_header_t *h,
                             const obj_ext_v3_t *x3, const obj_ext_v4_t *x4) {
    return (pwrite(fd, h, sizeof(*h), 0) == (ssize_t)sizeof(*h)
            && pwrite(fd, x3, sizeof(*x3), sizeof(*h)) == (ssize_t)sizeof(*x3)
            && pwrite(fd, x4, sizeof(*x4), sizeof(*h) + sizeof(*x3))
               == (ssize_t)sizeof(*x4)) ? 0 : -1;
}

static int tlv_validate(const uint8_t *t, size_t n);

struct s3_writer {
    s3_store_t *store;
    int         fd;                  /* tmp file fd */
    char        tmp_path[4096];      /* tmp file path */
    uint64_t    data_written;        /* bytes written to data region so far */
    EVP_MD_CTX *md5_ctx;             /* running MD5 */
    obj_header_t hdr;                /* accumulated header (filled in begin) */
    obj_ext_v3_t ext;                /* schema-3 extension (checksum, ...) */
    obj_ext_v4_t ext4;               /* schema-4 extension (payload CRC, ...) */
    cksum_ctx_t  pcrc;               /* CRC64NVME over the payload */
    char       *bucket_dup;
    char       *key_dup;             /* NOT NUL-terminated; key_len in hdr.key_len */
    char       *content_type_dup;    /* NUL-terminated */
    int         finalized;           /* 1 once commit/abort run */

    /* Multipart part mode. When non-empty, this writer is uploading a
     * single part of a multipart upload. We skip the obj_header_t prefix
     * and write only data; the part's MD5 ETag is what callers care
     * about. The part lands at `final_path` (under the staging dir).
     * The content_type/key fields above are NOT used in this mode. */
    int         is_part;
    char        final_path[4096];    /* destination for atomic rename */
    uint8_t     mpu_algo;            /* part: upload's required checksum algo */

    /* Bucket id at put_begin. Commit publishes only if the bucket still
     * has this id: deleted-and-recreated (maybe by another user) is a
     * different bucket, even under the same name. */
    char        bucket_id[33];

    /* Quota reservation held by this writer (released by writer_free,
     * converted to usage at commit). */
    char        q_bucket[64];
    uint64_t    q_rbytes;
    uint32_t    q_robjs;

    /* SSE-C (item 8): plaintext is buffered into segments and sealed;
     * md5/pcrc/stored_written cover the ciphertext on disk. */
    int         ssec;
    uint8_t     ssec_kobj[32];
    uint32_t    ssec_part;
    uint64_t    ssec_idx;
    uint8_t    *ssec_buf;           /* SSEC_SEG plaintext + SSEC_TAG */
    size_t      ssec_len;
    uint64_t    stored_written;     /* on-disk payload bytes */

    /* Dedup: SHA-256 of the payload and where its TLV slot sits. */
    EVP_MD_CTX *sha;
    uint64_t    sha_off;
    char        dedup_scope[300];   /* "global" or "u-<hex owner>" */
};

static s3_err_t q_reserve(s3_store_t *s, const char *bucket, uint64_t bytes, uint32_t objs);
static void     q_release(s3_store_t *s, const char *bucket, uint64_t bytes, uint32_t objs);
static void     q_charge(s3_store_t *s, const char *bucket, int64_t dbytes, int64_t dobjs);
static void     key_usage(s3_store_t *s, s3_str_t bucket, const char hex[65],
                          uint64_t *bytes, uint64_t *objs);
static uint64_t upload_part_bytes(const char *up_dir);
static s3_err_t writer_ssec_on(s3_writer_t *w, const uint8_t key[32], const ssec_info_t *info,
                               uint32_t part);

/* Grow the writer's reservation to cover `total` bytes. */
static s3_err_t writer_reserve_to(s3_writer_t *w, uint64_t total) {
    if (total <= w->q_rbytes || !w->q_bucket[0]) return S3_OK;
    uint64_t need = total - w->q_rbytes;
    uint64_t want = need < (256u << 10) ? (256u << 10) : need;   /* fewer lock trips */
    if (q_reserve(w->store, w->q_bucket, want, 0) != S3_OK) {
        if (want == need || q_reserve(w->store, w->q_bucket, need, 0) != S3_OK)
            return S3_ERR_QUOTA_EXCEEDED;
        want = need;
    }
    w->q_rbytes += want;
    return S3_OK;
}

static void writer_release_quota(s3_writer_t *w) {
    if (w->q_bucket[0] && (w->q_rbytes || w->q_robjs))
        q_release(w->store, w->q_bucket, w->q_rbytes, w->q_robjs);
    w->q_rbytes = 0;
    w->q_robjs = 0;
}

s3_err_t store_put_expect(s3_writer_t *w, uint64_t n) {
    if (!w || w->finalized) return S3_ERR_INVALID_ARGUMENT;
    return writer_reserve_to(w, n);
}

static void writer_free(s3_writer_t *w) {
    if (!w) return;
    writer_release_quota(w);
    if (w->sha) EVP_MD_CTX_free(w->sha);
    OPENSSL_cleanse(w->ssec_kobj, sizeof(w->ssec_kobj));
    if (w->ssec_buf) { OPENSSL_cleanse(w->ssec_buf, SSEC_SEG + SSEC_TAG); free(w->ssec_buf); }
    cksum_free(&w->pcrc);
    if (w->fd >= 0) close(w->fd);
    if (w->tmp_path[0]) unlink(w->tmp_path);
    if (w->md5_ctx) EVP_MD_CTX_free(w->md5_ctx);
    free(w->bucket_dup);
    free(w->key_dup);
    free(w->content_type_dup);
    free(w);
}

s3_err_t store_put_begin(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                         const char *content_type, s3_writer_t **out) {
    store_put_opts_t o = { .content_type = content_type };
    return store_put_begin_opts(s, bucket, key, &o, out);
}

s3_err_t store_put_set_checksum(s3_writer_t *w, uint8_t algo, uint8_t type,
                                uint16_t parts, const uint8_t *digest,
                                size_t n) {
    if (!w || w->finalized || algo >= S3_CKSUM_MAX || n > sizeof(w->ext.cksum)
        || type > S3_CKSUM_TYPE_COMPOSITE)
        return S3_ERR_INVALID_ARGUMENT;
    memset(w->ext.cksum, 0, sizeof(w->ext.cksum));
    w->ext.cksum_algo  = algo;
    w->ext.cksum_type  = type;
    w->ext.cksum_parts = parts;
    if (n) memcpy(w->ext.cksum, digest, n);
    return S3_OK;
}

s3_err_t store_put_begin_opts(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                              const store_put_opts_t *opts,
                              s3_writer_t **out) {
    if (!s || !out || !opts) return S3_ERR_INVALID_ARGUMENT;
    const char *content_type = opts->content_type;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!valid_key(key))            return S3_ERR_INVALID_ARGUMENT;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;
    s3_err_t qe = quota_check(s);
    if (qe != S3_OK) return qe;

    s3_writer_t *w = calloc(1, sizeof(*w));
    if (!w) return S3_ERR_INTERNAL;
    w->store = s;
    w->fd = -1;
    {
        s3_bucket_meta_t bm;
        if (store_bucket_meta(s, bucket, &bm) != S3_OK) {
            writer_free(w); return S3_ERR_NO_SUCH_BUCKET;
        }
        memcpy(w->bucket_id, bm.id, sizeof(w->bucket_id));
    }
    /* SSE-C (item 8): per-object salt and key check go into the header. */
    ssec_info_t ssec_si;
    if (opts->ssec_key) {
        s3_err_t se = ssec_info_new(opts->ssec_key, &ssec_si) < 0 ? S3_ERR_INTERNAL
                    : writer_ssec_on(w, opts->ssec_key, &ssec_si, 0);
        if (se != S3_OK) { writer_free(w); return se; }
    }
    /* Quota: room for one more object before any byte is written. */
    if (q_reserve(s, (snprintf(w->q_bucket, sizeof(w->q_bucket), S3_STR_FMT,
                               S3_STR_ARG(bucket)), w->q_bucket), 0, 1) != S3_OK) {
        w->q_bucket[0] = '\0';
        writer_free(w); return S3_ERR_QUOTA_EXCEEDED;
    }
    w->q_robjs = 1;

    w->md5_ctx = EVP_MD_CTX_new();
    if (!w->md5_ctx
        || EVP_DigestInit_ex(w->md5_ctx, EVP_md5(), NULL) != 1) {
        writer_free(w);
        return S3_ERR_INTERNAL;
    }

    /* Stash bucket/key/content-type for commit-time path computation. */
    w->bucket_dup = malloc(bucket.n + 1);
    w->key_dup    = malloc(key.n);
    if (!w->bucket_dup || !w->key_dup) { writer_free(w); return S3_ERR_INTERNAL; }
    memcpy(w->bucket_dup, bucket.p, bucket.n);
    w->bucket_dup[bucket.n] = '\0';
    memcpy(w->key_dup, key.p, key.n);

    const char *ct = content_type ? content_type : "";
    size_t ct_n = strlen(ct);
    if (ct_n > OBJ_MAX_CT_LEN) { writer_free(w); return S3_ERR_INVALID_ARGUMENT; }
    w->content_type_dup = malloc(ct_n + 1);
    if (!w->content_type_dup) { writer_free(w); return S3_ERR_INTERNAL; }
    memcpy(w->content_type_dup, ct, ct_n);
    w->content_type_dup[ct_n] = '\0';

    /* Header lengths are known now; data size + etag come at commit time. */
    if (key.n > UINT16_MAX) { writer_free(w); return S3_ERR_INVALID_ARGUMENT; }
    if (ct_n > UINT16_MAX)  { writer_free(w); return S3_ERR_INVALID_ARGUMENT; }
    if (opts->have_cksum
        && store_put_set_checksum(w, opts->cksum_algo, opts->cksum_type,
                                  opts->cksum_parts, opts->cksum,
                                  sizeof(opts->cksum)) != S3_OK) {
        writer_free(w); return S3_ERR_INVALID_ARGUMENT;
    }
    /* data_size, mtime_ms, etag, payload CRC filled at commit */
    if (opts->tlv_len > OBJ_MAX_TLV
        || (opts->tlv_len && (!opts->tlv || tlv_validate(opts->tlv, opts->tlv_len) < 0))) {
        writer_free(w); return S3_ERR_INVALID_ARGUMENT;
    }
    if (cksum_begin(&w->pcrc, S3_CKSUM_CRC64NVME) < 0) { writer_free(w); return S3_ERR_INTERNAL; }

    /* Open temp file. */
    w->fd = tmp_open(s, w->tmp_path, sizeof(w->tmp_path));
    if (w->fd < 0) {
        LOG_E("tmp_open: %s", strerror(errno));
        s3_err_t e = map_io_err(errno);
        writer_free(w);
        return e;
    }
    if (s->fs_compress && !w->ssec
        && compress_worth_it(s, w->content_type_dup, w->key_dup, key.n, opts->size_hint))
        (void)set_compr_flag(w->fd);

    /* Reserve header space by writing the (incomplete) header, then the
     * variable-length content_type and key bytes. We'll pwrite the final
     * header back at offset 0 in commit. */
    /* Dedup (item 6b): a CONTENT_SHA256 TLV slot filled at commit. */
    const uint8_t *tlv = opts->tlv;
    size_t tlv_n = opts->tlv_len;
    uint8_t *tlv2 = NULL;
    if (w->ssec) {
        /* SSE-C objects are never pooled; their header carries the SSEC TLV. */
        if (tlv_n + 6 + SSEC_TLV_PAYLOAD > OBJ_MAX_TLV
            || !(tlv2 = malloc(tlv_n + 6 + SSEC_TLV_PAYLOAD))) {
            writer_free(w); return S3_ERR_INVALID_ARGUMENT;
        }
        if (tlv_n) memcpy(tlv2, tlv, tlv_n);
        tlv_n += ssec_tlv_encode(&ssec_si, tlv2 + tlv_n);
        tlv = tlv2;
    } else if (s->dedup_mode && s->reflink && s->pad_headers && !opts->no_dedup
        && tlv_n + 38 <= OBJ_MAX_TLV) {
        tlv2 = malloc(tlv_n + 38);
        w->sha = EVP_MD_CTX_new();
        if (!tlv2 || !w->sha || EVP_DigestInit_ex(w->sha, EVP_sha256(), NULL) != 1) {
            free(tlv2); writer_free(w); return S3_ERR_INTERNAL;
        }
        if (tlv_n) memcpy(tlv2, tlv, tlv_n);
        static const uint8_t slot_head[6] = { S3_TLV_CONTENT_SHA256, 0, 32, 0, 0, 0 };
        memcpy(tlv2 + tlv_n, slot_head, 6);
        memset(tlv2 + tlv_n + 6, 0, 32);
        w->sha_off = sizeof(obj_header_t) + sizeof(obj_ext_v3_t) + sizeof(obj_ext_v4_t)
                   + ct_n + key.n + tlv_n + 6;
        tlv = tlv2;
        tlv_n += 38;
        if (s->dedup_mode == STORE_DEDUP_GLOBAL) {
            snprintf(w->dedup_scope, sizeof(w->dedup_scope), "global");
        } else {
            s3_bucket_meta_t bm2;
            char hx[260] = "";
            if (store_bucket_meta(s, bucket, &bm2) == S3_OK) hex_name(bm2.owner, hx, sizeof(hx));
            snprintf(w->dedup_scope, sizeof(w->dedup_scope), "u-%s", hx);
        }
    }
    if (obj_write_prefix(s, w->fd, &w->hdr, &w->ext, &w->ext4,
                         w->content_type_dup, ct_n, w->key_dup, key.n,
                         tlv, tlv_n) < 0) {
        LOG_E("write header: %s", strerror(errno));
        s3_err_t e = map_io_err(errno);
        free(tlv2);
        writer_free(w);
        return e;
    }
    free(tlv2);

    *out = w;
    return S3_OK;
}

/* On-disk payload bytes: written, and hashed for the ETag and payload CRC. */
static s3_err_t writer_emit(s3_writer_t *w, const void *buf, size_t n) {
    if (EVP_DigestUpdate(w->md5_ctx, buf, n) != 1) return S3_ERR_INTERNAL;
    if (w->pcrc.algo) cksum_update(&w->pcrc, buf, n);
    const char *p = buf;
    size_t left = n;
    while (left > 0) {
        ssize_t r = xwrite(w->fd, p, left);
        if (r > 0) { p += r; left -= (size_t)r; w->stored_written += (uint64_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        LOG_W("put_write: %s", strerror(errno));
        return map_io_err(errno);
    }
    return S3_OK;
}

static s3_err_t ssec_seal_buf(s3_writer_t *w, int final) {
    if (ssec_seal(w->ssec_kobj, w->ssec_part, w->ssec_idx, final, w->bucket_id,
                  w->ssec_buf, w->ssec_len, w->ssec_buf) < 0)
        return S3_ERR_INTERNAL;
    s3_err_t e = writer_emit(w, w->ssec_buf, w->ssec_len + SSEC_TAG);
    w->ssec_idx++;
    w->ssec_len = 0;
    return e;
}

/* Plaintext in. SSE-C: a full segment is sealed only when more data
 * arrives, so the last one is always sealed as final at commit. */
static s3_err_t writer_feed(s3_writer_t *w, const void *buf, size_t n) {
    if (!w->ssec) {
        s3_err_t e = writer_emit(w, buf, n);
        if (e == S3_OK) w->data_written += n;
        return e;
    }
    const uint8_t *p = buf;
    while (n) {
        if (w->ssec_len == SSEC_SEG) {
            s3_err_t e = ssec_seal_buf(w, 0);
            if (e != S3_OK) return e;
        }
        size_t take = SSEC_SEG - w->ssec_len < n ? SSEC_SEG - w->ssec_len : n;
        memcpy(w->ssec_buf + w->ssec_len, p, take);
        w->ssec_len += take; p += take; n -= take;
        w->data_written += take;
    }
    return S3_OK;
}

/* Turn on SSE-C for a writer (salt already chosen). */
static s3_err_t writer_ssec_on(s3_writer_t *w, const uint8_t key[32], const ssec_info_t *info,
                               uint32_t part) {
    if (strlen(w->bucket_id) != 32) return S3_ERR_INVALID_REQUEST;   /* pre-isolation bucket */
    w->ssec_buf = malloc(SSEC_SEG + SSEC_TAG);
    if (!w->ssec_buf || ssec_derive(key, info->salt, w->ssec_kobj) < 0) return S3_ERR_INTERNAL;
    w->ssec = 1;
    w->ssec_part = part;
    return S3_OK;
}

s3_err_t store_put_write(s3_writer_t *w, const void *buf, size_t n) {
    if (!w || w->finalized) return S3_ERR_INVALID_ARGUMENT;
    if (n == 0) return S3_OK;
    if (writer_reserve_to(w, w->data_written + n) != S3_OK) return S3_ERR_QUOTA_EXCEEDED;
    if (w->sha) EVP_DigestUpdate(w->sha, buf, n);
    return writer_feed(w, buf, n);
}

s3_err_t store_put_commit(s3_writer_t *w, s3_obj_meta_t *meta_out) {
    if (!w || w->finalized) return S3_ERR_INVALID_ARGUMENT;
    w->finalized = 1;

    if (w->ssec && ssec_seal_buf(w, 1) != S3_OK) { writer_free(w); return S3_ERR_INTERNAL; }
    /* Finalize MD5 (of the on-disk payload: ciphertext for SSE-C, so no
     * plaintext digest is kept) and timestamp. */
    unsigned int mlen = 16;
    if (EVP_DigestFinal_ex(w->md5_ctx, w->hdr.etag, &mlen) != 1) {
        writer_free(w); return S3_ERR_INTERNAL;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    w->hdr.mtime_ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000);
    w->hdr.data_size = w->data_written;

    /* Versioning: an Enabled bucket gives every new object a fresh
     * version id; Suspended/Unset write the null version. */
    int versioning = 0;
    {
        s3_str_t bk = { w->bucket_dup, strlen(w->bucket_dup) };
        versioning = bucket_versioning(w->store, bk);
        memset(w->ext.version_id, 0, 16);
        if (versioning == S3_VERSIONING_ENABLED && random_vid(w->ext.version_id) < 0) {
            writer_free(w); return S3_ERR_INTERNAL;
        }
    }

    /* Pwrite the finalized header back at offset 0. */
    w->ext4.stored_size = w->stored_written;
    if (w->ssec) {
        /* Checksums were verified over the plaintext while it streamed;
         * storing them would leak a plaintext digest at rest. */
        w->ext.flags |= S3_OBJF_SSEC;
        w->ext.cksum_algo = w->ext.cksum_type = 0;
        w->ext.cksum_parts = 0;
        memset(w->ext.cksum, 0, sizeof(w->ext.cksum));
    }
    if (w->pcrc.algo) {
        uint8_t d[CKSUM_MAX_DIGEST]; size_t dn;
        if (cksum_final(&w->pcrc, d, &dn) == 0 && dn == 8) {
            memcpy(w->ext4.payload_crc64, d, 8);
            w->ext.flags |= S3_OBJF_PAYLOAD_CRC;
        }
    }
    if (w->sha) {
        /* Fill the CONTENT_SHA256 slot, then share extents through the
         * pool (item 6b). Any dedup failure just leaves a normal copy. */
        uint8_t dg[32]; unsigned dn = 32;
        if (EVP_DigestFinal_ex(w->sha, dg, &dn) == 1
            && pwrite(w->fd, dg, 32, (off_t)w->sha_off) == 32
            && w->data_written >= w->store->dedup_min && w->data_written > 0)
            dedup_commit(w, dg);
    }
    if (obj_rewrite_fixed(w->fd, &w->hdr, &w->ext, &w->ext4) < 0) {
        LOG_E("pwrite header: %s", strerror(errno));
        s3_err_t e = map_io_err(errno);
        writer_free(w); return e;
    }
    /* Durability: data and metadata both. A failed fsync here never
     * reaches the live tree — the rename below hasn't happened yet. */
    if (xfsync(w->fd) < 0) {
        LOG_E("fsync tmp: %s", strerror(errno));
        s3_err_t e = map_io_err(errno);
        writer_free(w); return e;
    }

    /* Compute final path. */
    s3_str_t bucket = { w->bucket_dup, strlen(w->bucket_dup) };
    s3_str_t key    = { w->key_dup,    w->hdr.key_len };

    char hex[65];
    hash_bucket_key(bucket, key, hex);

    char dir[4096], path[4096];
    if (obj_dir(w->store, bucket, hex, dir, sizeof(dir)) < 0
        || obj_path(w->store, bucket, hex, path, sizeof(path)) < 0) {
        writer_free(w); return S3_ERR_INTERNAL;
    }

    /* The body streamed across many event-loop turns and this may run on
     * a worker thread; the bucket may have been deleted meanwhile
     * (bucket_delete can't see tmp/ writes), and even re-created by
     * another user. Without this re-check under ns_mu, mkdir_p would
     * resurrect data/<bucket>/, or the object would land in a bucket
     * the uploader doesn't own. */
    pthread_mutex_t *km = key_lock(w->store, hex);
    pthread_mutex_lock(km);
    pthread_mutex_lock(&w->store->ns_mu);
    s3_bucket_meta_t bm;
    if (store_bucket_meta(w->store, bucket, &bm) != S3_OK
        || strcmp(bm.id, w->bucket_id) != 0) {
        pthread_mutex_unlock(&w->store->ns_mu);
    pthread_mutex_unlock(km);
        writer_free(w); return S3_ERR_NO_SUCH_BUCKET;
    }
    if (mkdir_p(dir, 0700) < 0) {
        LOG_E("mkdir_p %s: %s", dir, strerror(errno));
        s3_err_t e = map_io_err(errno);
        pthread_mutex_unlock(&w->store->ns_mu);
    pthread_mutex_unlock(km);
        writer_free(w); return e;
    }

    uint64_t q_b0 = 0, q_o0 = 0;
    key_usage(w->store, bucket, hex, &q_b0, &q_o0);

    /* Versioned bucket: move the current version aside first (hard link,
     * crash-safe; see store.h). Layout 2 instead writes the version into
     * versions/ and re-points the data symlink (item 9). */
    if (bm.layout == 2) {
        s3_err_t le = l2_publish(w->store, bucket, hex, w->tmp_path, w->hdr.mtime_ms,
                                 w->ext.version_id);
        if (le != S3_OK) {
            pthread_mutex_unlock(&w->store->ns_mu);
            pthread_mutex_unlock(km);
            writer_free(w); return le;
        }
    } else {
        s3_err_t le = link_aside_locked(w->store, bucket, hex, path, versioning);
        if (le != S3_OK) {
            pthread_mutex_unlock(&w->store->ns_mu);
            pthread_mutex_unlock(km);
            writer_free(w); return le;
        }
    }

    /* Atomic rename. Can also fail with ENOSPC (new dirent allocation). */
    if (bm.layout != 2 && rename(w->tmp_path, path) < 0) {
        LOG_E("rename %s -> %s: %s", w->tmp_path, path, strerror(errno));
        s3_err_t e = map_io_err(errno);
        pthread_mutex_unlock(&w->store->ns_mu);
    pthread_mutex_unlock(km);
        writer_free(w); return e;
    }
    pthread_mutex_unlock(&w->store->ns_mu);
    {
        /* Quota: the key's usage change replaces the reservation. */
        uint64_t q_b1 = 0, q_o1 = 0;
        key_usage(w->store, bucket, hex, &q_b1, &q_o1);
        q_charge(w->store, w->q_bucket, (int64_t)q_b1 - (int64_t)q_b0,
                 (int64_t)q_o1 - (int64_t)q_o0);
        writer_release_quota(w);
    }
    pthread_mutex_unlock(km);
    /* tmp_path is gone; clear so writer_free doesn't unlink the live file. */
    w->tmp_path[0] = '\0';

    /* Make the dirent durable. */
    if (fsync_dir(dir) < 0) {
        LOG_W("fsync_dir %s: %s", dir, strerror(errno));
        /* Not fatal — data is on disk; on crash the dirent might be lost. */
    }

    if (meta_out) {
        memset(meta_out, 0, sizeof(*meta_out));
        meta_out->size     = w->hdr.data_size;
        meta_out->mtime_ms = w->hdr.mtime_ms;
        memcpy(meta_out->etag, w->hdr.etag, 16);
        size_t ctn = w->hdr.ct_len;
        if (ctn >= sizeof(meta_out->content_type)) ctn = sizeof(meta_out->content_type) - 1;
        memcpy(meta_out->content_type, w->content_type_dup, ctn);
        meta_out->content_type[ctn] = '\0';
        memcpy(meta_out->version_id, w->ext.version_id, 16);
        meta_out->flags       = w->ext.flags;
        meta_out->cksum_algo  = w->ext.cksum_algo;
        meta_out->cksum_type  = w->ext.cksum_type;
        meta_out->cksum_parts = w->ext.cksum_parts;
        memcpy(meta_out->cksum, w->ext.cksum, 32);
        meta_out->stored_size = w->ext4.stored_size;
        memcpy(meta_out->payload_crc64, w->ext4.payload_crc64, 8);
        meta_out->header_size = w->hdr.header_size;
    }

    writer_free(w);
    return S3_OK;
}

void store_put_abort(s3_writer_t *w) {
    if (!w) return;
    /* writer_free unlinks tmp_path if non-empty. */
    writer_free(w);
}

/* ===================================================================== */
/* Streaming GET                                                          */
/* ===================================================================== */

typedef struct {
    uint32_t part;           /* nonce part number (0 for a single PUT) */
    uint64_t plain, poff;    /* plaintext length / offset */
    uint64_t coff;           /* ciphertext offset from data_off */
} rd_part_t;

struct s3_reader {
    int      fd;
    uint32_t tlv_off, tlv_len;  /* schema-4 TLV area (0 if none) */
    uint64_t data_off;       /* file offset where data begins */
    uint64_t data_size;      /* total data length (plaintext) */
    uint64_t pos;            /* bytes already returned to caller */
    /* SSE-C decrypt state (item 8); all reads are plaintext offsets. */
    int        ssec;
    uint8_t    kobj[32];
    char       bucket_id[33];
    rd_part_t *parts;
    size_t     n_parts;
    uint8_t   *seg;          /* decrypted segment cache */
    size_t     seg_len;
    size_t     seg_part;
    uint64_t   seg_idx;
    int        seg_valid;
};

/* Read and validate an object file's header. The share holding the data
 * root may be writable by other DSM users, so every length is treated as
 * untrusted: header_size must equal exactly fixed + ext + ct + key, fit
 * inside the file, and the data region must match the file size.
 * Fills h, x (zeroes for schema 2) and *ct_off (offset of content-type
 * bytes; the key follows them). */
/* Walk a TLV area: every record must fit exactly. 0 ok, -1 malformed. */
static int tlv_validate(const uint8_t *t, size_t n) {
    size_t o = 0;
    while (o < n) {
        if (n - o < 6) return -1;
        uint32_t len = (uint32_t)t[o+2] | (uint32_t)t[o+3] << 8
                     | (uint32_t)t[o+4] << 16 | (uint32_t)t[o+5] << 24;
        if (len > n - o - 6) return -1;
        o += 6 + len;
    }
    return 0;
}

static s3_err_t obj_read_hdr4(int fd, obj_header_t *h, obj_ext_v3_t *x,
                              obj_ext_v4_t *x4, uint32_t *ct_off,
                              uint32_t *tlv_off) {
    ssize_t r = pread(fd, h, sizeof(*h), 0);
    if (r != (ssize_t)sizeof(*h)) return S3_ERR_INTERNAL;
    if (memcmp(h->magic, OBJ_MAGIC, OBJ_MAGIC_LEN) != 0) return S3_ERR_INTERNAL;
    uint32_t fixed;
    obj_ext_v4_t x4l;
    if (!x4) x4 = &x4l;
    memset(x, 0, sizeof(*x));
    memset(x4, 0, sizeof(*x4));
    if (h->schema == OBJ_SCHEMA_V2) {
        fixed = (uint32_t)sizeof(*h);
    } else if (h->schema == OBJ_SCHEMA_V3 || h->schema == OBJ_SCHEMA) {
        fixed = (uint32_t)(sizeof(*h) + sizeof(*x));
        if (pread(fd, x, sizeof(*x), sizeof(*h)) != (ssize_t)sizeof(*x))
            return S3_ERR_INTERNAL;
        if (x->cksum_algo >= S3_CKSUM_MAX
            || x->cksum_type > S3_CKSUM_TYPE_COMPOSITE
            || (x->cksum_type == S3_CKSUM_TYPE_COMPOSITE
                && (x->cksum_parts == 0 || x->cksum_parts > 10000)))
            return S3_ERR_INTERNAL;
        if (h->schema == OBJ_SCHEMA) {
            if (pread(fd, x4, sizeof(*x4), fixed) != (ssize_t)sizeof(*x4))
                return S3_ERR_INTERNAL;
            fixed += (uint32_t)sizeof(*x4);
            if (x4->tlv_len > OBJ_MAX_TLV || x4->pad_len > OBJ_MAX_PAD)
                return S3_ERR_INTERNAL;
        }
    } else {
        return S3_ERR_INTERNAL;
    }
    if (h->ct_len > OBJ_MAX_CT_LEN || h->key_len == 0 || h->key_len > 1024)
        return S3_ERR_INTERNAL;
    if ((uint64_t)h->header_size != (uint64_t)fixed + h->ct_len + h->key_len
                                    + x4->tlv_len + x4->pad_len)
        return S3_ERR_INTERNAL;
    if (h->part_count > 10000) return S3_ERR_INTERNAL;
    uint64_t stored = h->schema == OBJ_SCHEMA ? x4->stored_size : h->data_size;
    if (h->schema != OBJ_SCHEMA) x4->stored_size = h->data_size;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < 0
        || (uint64_t)st.st_size < h->header_size
        || (uint64_t)st.st_size - h->header_size != stored)
        return S3_ERR_INTERNAL;
    if (x4->tlv_len) {
        uint8_t *t = malloc(x4->tlv_len);
        if (!t) return S3_ERR_INTERNAL;
        off_t to = (off_t)fixed + h->ct_len + h->key_len;
        int bad = pread(fd, t, x4->tlv_len, to) != (ssize_t)x4->tlv_len
                  || tlv_validate(t, x4->tlv_len) < 0;
        free(t);
        if (bad) return S3_ERR_INTERNAL;
    }
    *ct_off = fixed;
    if (tlv_off) *tlv_off = fixed + h->ct_len + h->key_len;
    return S3_OK;
}

static s3_err_t obj_read_hdr(int fd, obj_header_t *h, obj_ext_v3_t *x,
                             uint32_t *ct_off) {
    return obj_read_hdr4(fd, h, x, NULL, ct_off, NULL);
}

/* Fill meta from a validated header (content-type read from fd). */
static s3_err_t obj_fill_meta(int fd, const obj_header_t *h,
                              const obj_ext_v3_t *x, const obj_ext_v4_t *x4,
                              uint32_t ct_off, uint32_t tlv_off,
                              s3_obj_meta_t *m) {
    memset(m, 0, sizeof(*m));
    m->size       = h->data_size;
    m->stored_size = x4 ? x4->stored_size : h->data_size;
    if (x4) {
        memcpy(m->payload_crc64, x4->payload_crc64, 8);
        m->tlv_len = x4->tlv_len;
        m->tlv_off = x4->tlv_len ? tlv_off : 0;
    }
    m->header_size = h->header_size;
    m->mtime_ms   = h->mtime_ms;
    m->part_count = h->part_count;
    memcpy(m->etag, h->etag, 16);
    memcpy(m->version_id, x->version_id, 16);
    m->flags       = x->flags;
    m->cksum_algo  = x->cksum_algo;
    m->cksum_type  = x->cksum_type;
    m->cksum_parts = x->cksum_parts;
    memcpy(m->cksum, x->cksum, 32);
    if (h->ct_len > 0) {
        size_t ctn = h->ct_len;
        if (ctn >= sizeof(m->content_type)) ctn = sizeof(m->content_type) - 1;
        if (pread(fd, m->content_type, ctn, ct_off) != (ssize_t)ctn)
            return S3_ERR_INTERNAL;
        m->content_type[ctn] = '\0';
    }
    return S3_OK;
}

/* Read header from fd at offset 0; verify; populate meta. */
static s3_err_t read_header(int fd, obj_header_t *hdr_out, s3_obj_meta_t *meta_out) {
    obj_header_t h;
    obj_ext_v3_t x;
    obj_ext_v4_t x4;
    uint32_t ct_off, tlv_off;
    s3_err_t e = obj_read_hdr4(fd, &h, &x, &x4, &ct_off, &tlv_off);
    if (e != S3_OK) return e;
    if (hdr_out) *hdr_out = h;
    if (meta_out) return obj_fill_meta(fd, &h, &x, &x4, ct_off, tlv_off, meta_out);
    return S3_OK;
}

s3_err_t store_get_open(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                        s3_reader_t **out, s3_obj_meta_t *meta_out) {
    return store_get_open_version(s, bucket, key, NULL, out, meta_out);
}

static ssize_t ssec_read(s3_reader_t *r, void *buf, size_t n);

ssize_t store_get_read(s3_reader_t *r, void *buf, size_t n) {
    if (!r) { errno = EINVAL; return -1; }
    if (r->ssec) return ssec_read(r, buf, n);
    if (r->pos >= r->data_size) return 0;
    uint64_t avail = r->data_size - r->pos;
    if ((uint64_t)n > avail) n = (size_t)avail;
    ssize_t got = pread(r->fd, buf, n, (off_t)(r->data_off + r->pos));
    if (got > 0) r->pos += (uint64_t)got;
    return got;
}

ssize_t store_get_sendfile(s3_reader_t *r, int out_fd, size_t max) {
    if (!r || r->ssec) { errno = EINVAL; return -1; }    /* transformed: read path */
    if (r->pos >= r->data_size) return 0;
    uint64_t avail = r->data_size - r->pos;
    size_t want = max ? (max < avail ? max : (size_t)avail) : (size_t)avail;
    off_t off = (off_t)(r->data_off + r->pos);
    ssize_t sent = sendfile(out_fd, r->fd, &off, want);
    if (sent > 0) r->pos += (uint64_t)sent;
    return sent;
}

s3_err_t store_get_seek(s3_reader_t *r, uint64_t first, uint64_t last) {
    if (!r || first > last || last >= r->data_size) return S3_ERR_INVALID_ARGUMENT;
    r->pos = first;
    r->data_size = last + 1;
    return S3_OK;
}

void store_get_close(s3_reader_t *r) {
    if (!r) return;
    OPENSSL_cleanse(r->kobj, sizeof(r->kobj));
    if (r->seg) { OPENSSL_cleanse(r->seg, SSEC_SEG + SSEC_TAG); free(r->seg); }
    free(r->parts);
    if (r->fd >= 0) close(r->fd);
    free(r);
}

/* ===================================================================== */
/* HEAD / DELETE                                                          */
/* ===================================================================== */

s3_err_t store_head(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                    s3_obj_meta_t *meta_out) {
    s3_reader_t *r;
    s3_err_t e = store_get_open(s, bucket, key, &r, meta_out);
    if (e == S3_OK) store_get_close(r);
    return e;
}

s3_err_t store_delete(s3_store_t *s, s3_str_t bucket, s3_str_t key) {
    return store_delete_ex(s, bucket, key, NULL, NULL);
}

/* ===================================================================== */
/* List (FS-walk implementation; replaced by LMDB in Phase 2.2)          */
/* ===================================================================== */

/* The lister loads ALL keys for the bucket into memory at begin time,
 * sorts them lexicographically, then iterates with marker / prefix /
 * delimiter applied. For homelab scale this is fine; at >1M keys it
 * becomes painful, which is exactly why Phase 2.2 swaps in LMDB.
 *
 * "Common prefix" handling: when delimiter is set, keys sharing a
 * prefix up to the next delimiter character are rolled up into a
 * single "prefix" entry. Distinct prefixes are emitted at most once. */

typedef struct {
    char        *key;        /* malloc'd, NUL-terminated */
    size_t       key_len;
    s3_obj_meta_t meta;
} list_entry_t;

struct s3_lister {
    list_entry_t *items;
    size_t        n_items;
    size_t        cursor;       /* next item index to consider */

    s3_str_t      prefix;       /* points into opts_storage */
    s3_str_t      marker;
    s3_str_t      delimiter;
    int           max_keys;
    int           emitted;
    int           truncated;    /* 1 if we stopped at max_keys */

    /* Heap copies of the option strings so they outlive the caller's
     * stack frame. */
    char         *opts_storage;
    size_t        opts_storage_used;

    /* Last-emitted common prefix, to dedupe subsequent matches. */
    char         *last_prefix;
    size_t        last_prefix_len;

    /* Single-call return scratch. */
    char         *ret_buf;
    size_t        ret_cap;
};

static int cmp_entries(const void *a, const void *b) {
    const list_entry_t *ea = a, *eb = b;
    size_t n = ea->key_len < eb->key_len ? ea->key_len : eb->key_len;
    int c = memcmp(ea->key, eb->key, n);
    if (c) return c;
    if (ea->key_len < eb->key_len) return -1;
    if (ea->key_len > eb->key_len) return 1;
    return 0;
}

static int starts_with(const char *p, size_t n, s3_str_t pref) {
    if (pref.n == 0) return 1;
    if (n < pref.n) return 0;
    return memcmp(p, pref.p, pref.n) == 0;
}

/* Read one object file's header into entry. Sets entry->key (malloc'd). */
static int open_cur(const char *path);

static int load_entry(const char *path, list_entry_t *out) {
    int fd = open_cur(path);
    if (fd < 0) return -1;
    obj_header_t h;
    obj_ext_v3_t x;
    uint32_t ct_off;
    if (obj_read_hdr(fd, &h, &x, &ct_off) != S3_OK) { close(fd); return -1; }
    char *kbuf = malloc((size_t)h.key_len + 1);
    if (!kbuf) { close(fd); return -1; }
    if (pread(fd, kbuf, h.key_len, (off_t)ct_off + h.ct_len) != (ssize_t)h.key_len
        || obj_fill_meta(fd, &h, &x, NULL, ct_off, 0, &out->meta) != S3_OK) {
        free(kbuf); close(fd); return -1;
    }
    kbuf[h.key_len] = '\0';
    out->key = kbuf;
    out->key_len = h.key_len;
    close(fd);
    return 0;
}

/* Walk the per-bucket data dir collecting object files. */
static int walk_bucket(const char *bucket_data_dir, list_entry_t **items_out,
                       size_t *n_out) {
    list_entry_t *items = NULL;
    size_t n = 0, cap = 0;

    DIR *d1 = opendir(bucket_data_dir);
    if (!d1) {
        if (errno == ENOENT) { *items_out = NULL; *n_out = 0; return 0; }
        return -1;
    }
    struct dirent *e1;
    while ((e1 = readdir(d1)) != NULL) {
        if (e1->d_name[0] == '.') continue;
        char p2[4096];
        int n2 = snprintf(p2, sizeof(p2), "%s/%s", bucket_data_dir, e1->d_name);
        if (n2 < 0 || (size_t)n2 >= sizeof(p2)) continue;
        DIR *d2 = opendir(p2);
        if (!d2) continue;
        struct dirent *e2;
        while ((e2 = readdir(d2)) != NULL) {
            if (e2->d_name[0] == '.') continue;
            char p3[4096];
            int n3 = snprintf(p3, sizeof(p3), "%s/%s", p2, e2->d_name);
            if (n3 < 0 || (size_t)n3 >= sizeof(p3)) continue;
            DIR *d3 = opendir(p3);
            if (!d3) continue;
            struct dirent *e3;
            while ((e3 = readdir(d3)) != NULL) {
                if (e3->d_name[0] == '.') continue;
                char path[4096];
                int np = snprintf(path, sizeof(path), "%s/%s", p3, e3->d_name);
                if (np < 0 || (size_t)np >= sizeof(path)) continue;
                if (n == cap) {
                    size_t nc = cap ? cap * 2 : 64;
                    list_entry_t *ni = realloc(items, nc * sizeof(*items));
                    if (!ni) { closedir(d3); closedir(d2); closedir(d1); goto oom; }
                    items = ni; cap = nc;
                }
                if (load_entry(path, &items[n]) == 0) {
                    /* A delete marker hides the key from listings. */
                    if (items[n].meta.flags & S3_OBJF_DELETE_MARKER) free(items[n].key);
                    else n++;
                }
            }
            closedir(d3);
        }
        closedir(d2);
    }
    closedir(d1);
    *items_out = items;
    *n_out = n;
    return 0;

oom:
    for (size_t i = 0; i < n; i++) free(items[i].key);
    free(items);
    return -1;
}

s3_err_t store_list_begin(s3_store_t *s, s3_str_t bucket,
                          const s3_list_opts_t *opts, s3_lister_t **out) {
    if (!s || !out) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;

    s3_lister_t *l = calloc(1, sizeof(*l));
    if (!l) return S3_ERR_INTERNAL;
    l->max_keys = (opts && opts->max_keys > 0) ? opts->max_keys : 1000;

    /* Copy opts strings into a single arena. */
    size_t need = 0;
    if (opts) {
        need += opts->prefix.n + opts->marker.n + opts->delimiter.n;
    }
    if (need > 0) {
        l->opts_storage = malloc(need);
        if (!l->opts_storage) { store_list_close(l); return S3_ERR_INTERNAL; }
    }
    if (opts) {
        char *o = l->opts_storage;
        if (opts->prefix.n)    memcpy(o, opts->prefix.p, opts->prefix.n);
        l->prefix = (s3_str_t){ o, opts->prefix.n };
        o += opts->prefix.n;
        if (opts->marker.n)    memcpy(o, opts->marker.p, opts->marker.n);
        l->marker = (s3_str_t){ o, opts->marker.n };
        o += opts->marker.n;
        if (opts->delimiter.n) memcpy(o, opts->delimiter.p, opts->delimiter.n);
        l->delimiter = (s3_str_t){ o, opts->delimiter.n };
    }

    char dp[4096];
    snprintf(dp, sizeof(dp), "%s/" S3_STR_FMT, s->data_dir, S3_STR_ARG(bucket));
    if (walk_bucket(dp, &l->items, &l->n_items) < 0) {
        store_list_close(l);
        return S3_ERR_INTERNAL;
    }
    if (l->n_items) qsort(l->items, l->n_items, sizeof(list_entry_t), cmp_entries);
    *out = l;
    return S3_OK;
}

/* What entry e is for this listing: -1 skip, 0 a plain key, 1 a
 * rolled-up common prefix of *ptotal bytes. A rollup is skipped when it
 * was just emitted, or when it sorts at or before the marker — the
 * marker is then inside (or is) that prefix, which an earlier page
 * already returned (NextMarker/continuation token of a delimiter
 * listing is the last CommonPrefix). */
static int list_classify(const s3_lister_t *l, const list_entry_t *e, size_t *ptotal) {
    if (l->marker.n > 0) {
        size_t mn = l->marker.n < e->key_len ? l->marker.n : e->key_len;
        int c = memcmp(e->key, l->marker.p, mn);
        if (c < 0) return -1;
        if (c == 0 && e->key_len <= l->marker.n) return -1;
    }
    if (!starts_with(e->key, e->key_len, l->prefix)) return -1;
    if (l->delimiter.n == 0) return 0;
    const char *after = e->key + l->prefix.n;
    size_t after_n = e->key_len - l->prefix.n;
    const char *hit = NULL;
    if (l->delimiter.n == 1) {
        hit = memchr(after, l->delimiter.p[0], after_n);
    } else {
        for (size_t i = 0; i + l->delimiter.n <= after_n; i++) {
            if (memcmp(after + i, l->delimiter.p, l->delimiter.n) == 0) { hit = after + i; break; }
        }
    }
    if (!hit) return 0;
    size_t total = (size_t)(hit - e->key) + l->delimiter.n;
    if (l->last_prefix && l->last_prefix_len == total
        && memcmp(l->last_prefix, e->key, total) == 0)
        return -1;                                  /* already emitted */
    if (l->marker.n >= total && memcmp(l->marker.p, e->key, total) == 0)
        return -1;                                  /* rollup ≤ marker */
    *ptotal = total;
    return 1;
}

s3_err_t store_list_next(s3_lister_t *l, s3_str_t *key_out,
                         s3_obj_meta_t *meta_out, int *is_prefix_out) {
    if (!l || !key_out) return S3_ERR_INVALID_ARGUMENT;

    while (l->cursor < l->n_items) {
        size_t total = 0;
        if (l->emitted >= l->max_keys) {
            /* At max_keys: truncated iff one more item would be emitted. */
            for (size_t i = l->cursor; i < l->n_items; i++) {
                if (list_classify(l, &l->items[i], &total) >= 0) { l->truncated = 1; break; }
            }
            return S3_ERR_NO_SUCH_KEY;
        }

        list_entry_t *e = &l->items[l->cursor++];
        int kind = list_classify(l, e, &total);
        if (kind < 0) continue;
        if (kind == 1) {
            if (total + 1 > l->ret_cap) {
                char *nb = realloc(l->ret_buf, total + 1);
                if (!nb) return S3_ERR_INTERNAL;
                l->ret_buf = nb; l->ret_cap = total + 1;
            }
            memcpy(l->ret_buf, e->key, total);
            l->ret_buf[total] = '\0';
            char *np = realloc(l->last_prefix, total);
            if (!np) return S3_ERR_INTERNAL;
            l->last_prefix = np;
            memcpy(l->last_prefix, e->key, total);
            l->last_prefix_len = total;
            key_out->p = l->ret_buf;
            key_out->n = total;
            if (is_prefix_out) *is_prefix_out = 1;
            l->emitted++;
            return S3_OK;
        }

        /* Plain key. Copy into ret_buf. */
        if (e->key_len + 1 > l->ret_cap) {
            char *nb = realloc(l->ret_buf, e->key_len + 1);
            if (!nb) return S3_ERR_INTERNAL;
            l->ret_buf = nb; l->ret_cap = e->key_len + 1;
        }
        memcpy(l->ret_buf, e->key, e->key_len);
        l->ret_buf[e->key_len] = '\0';
        key_out->p = l->ret_buf;
        key_out->n = e->key_len;
        if (meta_out) *meta_out = e->meta;
        if (is_prefix_out) *is_prefix_out = 0;
        l->emitted++;
        return S3_OK;
    }
    return S3_ERR_NO_SUCH_KEY;
}

int store_list_truncated(const s3_lister_t *l) {
    return l ? l->truncated : 0;
}

void store_list_close(s3_lister_t *l) {
    if (!l) return;
    for (size_t i = 0; i < l->n_items; i++) free(l->items[i].key);
    free(l->items);
    free(l->opts_storage);
    free(l->last_prefix);
    free(l->ret_buf);
    free(l);
}

/* ===================================================================== */
/* Service-level: list all buckets                                        */
/* ===================================================================== */

s3_err_t store_list_buckets(s3_store_t *s,
                            s3_bucket_info_t **out, size_t *n_out) {
    if (!s || !out || !n_out) return S3_ERR_INVALID_ARGUMENT;
    *out = NULL;
    *n_out = 0;

    DIR *d = opendir(s->buckets_dir);
    if (!d) {
        if (errno == ENOENT) return S3_OK;   /* no buckets yet — empty list */
        LOG_E("opendir(%s): %s", s->buckets_dir, strerror(errno));
        return S3_ERR_INTERNAL;
    }

    size_t cap = 16, n = 0;
    s3_bucket_info_t *arr = malloc(cap * sizeof(*arr));
    if (!arr) { closedir(d); return S3_ERR_INTERNAL; }

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;   /* skip "." ".." and hidden */
        char path[4096];
        if (snprintf(path, sizeof(path), "%s/%s", s->buckets_dir, e->d_name)
            >= (int)sizeof(path)) continue;
        struct stat st;
        if (stat(path, &st) < 0 || !S_ISDIR(st.st_mode)) continue;

        if (n == cap) {
            size_t nc = cap * 2;
            s3_bucket_info_t *na = realloc(arr, nc * sizeof(*na));
            if (!na) {
                store_buckets_free(arr, n);
                closedir(d);
                return S3_ERR_INTERNAL;
            }
            arr = na; cap = nc;
        }
        s3_bucket_meta_t bm;
        read_bucket_meta(path, &bm);
        memcpy(arr[n].owner, bm.owner, sizeof(arr[n].owner));
        arr[n].name = strdup(e->d_name);
        if (!arr[n].name) {
            store_buckets_free(arr, n);
            closedir(d);
            return S3_ERR_INTERNAL;
        }
        arr[n].ctime_ms = (uint64_t)st.st_mtim.tv_sec * 1000
                        + (uint64_t)st.st_mtim.tv_nsec / 1000000;
        n++;
    }
    closedir(d);

    *out = arr;
    *n_out = n;
    return S3_OK;
}

void store_buckets_free(s3_bucket_info_t *list, size_t n) {
    if (!list) return;
    for (size_t i = 0; i < n; i++) free(list[i].name);
    free(list);
}

/* Noncurrent versions (and markers) under versions/<b>/xx/yy/<hex>/. */
static void count_versions(s3_store_t *s, s3_str_t bucket, s3_bucket_stats_t *st) {
    char vb[4200];
    snprintf(vb, sizeof(vb), "%s/" S3_STR_FMT, s->versions_dir, S3_STR_ARG(bucket));
    DIR *d1 = opendir(vb);
    if (!d1) return;
    struct dirent *e1;
    while ((e1 = readdir(d1)) != NULL) {
        if (e1->d_name[0] == '.') continue;
        char p1[4500];
        snprintf(p1, sizeof(p1), "%s/%s", vb, e1->d_name);
        DIR *d2 = opendir(p1);
        if (!d2) continue;
        struct dirent *e2;
        while ((e2 = readdir(d2)) != NULL) {
            if (e2->d_name[0] == '.') continue;
            char p2[4800];
            snprintf(p2, sizeof(p2), "%s/%s", p1, e2->d_name);
            DIR *d3 = opendir(p2);
            if (!d3) continue;
            struct dirent *e3;
            while ((e3 = readdir(d3)) != NULL) {
                if (e3->d_name[0] == '.') continue;
                char p3[5100];
                snprintf(p3, sizeof(p3), "%s/%s", p2, e3->d_name);
                DIR *d4 = opendir(p3);
                if (!d4) continue;
                struct dirent *e4;
                while ((e4 = readdir(d4)) != NULL) {
                    if (e4->d_name[0] == '.') continue;
                    char fp[5400];
                    snprintf(fp, sizeof(fp), "%s/%s", p3, e4->d_name);
                    int fd = open(fp, O_RDONLY | O_CLOEXEC);
                    if (fd < 0) continue;
                    obj_header_t h;
                    obj_ext_v3_t x;
                    uint32_t co;
                    if (obj_read_hdr(fd, &h, &x, &co) == S3_OK) {
                        st->versions++;
                        st->version_bytes += h.data_size;
                    }
                    close(fd);
                }
                closedir(d4);
            }
            closedir(d3);
        }
        closedir(d2);
    }
    closedir(d1);
}

/* Read just the header of one object file and accumulate into stats.
 * Unreadable or non-object files are skipped, not errors: the walk is
 * advisory (admin display), and a file mid-rename shouldn't fail it. */
static void stats_count_file(const char *path, s3_bucket_stats_t *st) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    obj_header_t h;
    obj_ext_v3_t x;
    uint32_t ct_off;
    s3_err_t e = obj_read_hdr(fd, &h, &x, &ct_off);
    close(fd);
    if (e != S3_OK) return;
    if (x.flags & S3_OBJF_DELETE_MARKER) { st->versions++; return; }
    st->objects++;
    st->bytes += h.data_size;
}

s3_err_t store_bucket_stats(s3_store_t *s, s3_str_t bucket,
                            s3_bucket_stats_t *out) {
    if (!s || !out) return S3_ERR_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;

    char dp[4096];
    snprintf(dp, sizeof(dp), "%s/" S3_STR_FMT, s->data_dir, S3_STR_ARG(bucket));

    /* Same two-level shard walk as walk_bucket, but header-only. */
    DIR *d1 = opendir(dp);
    if (!d1) return S3_OK;   /* bucket exists but has no data dir yet */
    struct dirent *e1;
    while ((e1 = readdir(d1)) != NULL) {
        if (e1->d_name[0] == '.') continue;
        char p2[4096];
        int n2 = snprintf(p2, sizeof(p2), "%s/%s", dp, e1->d_name);
        if (n2 < 0 || (size_t)n2 >= sizeof(p2)) continue;
        DIR *d2 = opendir(p2);
        if (!d2) continue;
        struct dirent *e2;
        while ((e2 = readdir(d2)) != NULL) {
            if (e2->d_name[0] == '.') continue;
            char p3[4096];
            int n3 = snprintf(p3, sizeof(p3), "%s/%s", p2, e2->d_name);
            if (n3 < 0 || (size_t)n3 >= sizeof(p3)) continue;
            DIR *d3 = opendir(p3);
            if (!d3) continue;
            struct dirent *e3;
            while ((e3 = readdir(d3)) != NULL) {
                if (e3->d_name[0] == '.') continue;
                char path[4096];
                int np = snprintf(path, sizeof(path), "%s/%s", p3, e3->d_name);
                if (np < 0 || (size_t)np >= sizeof(path)) continue;
                stats_count_file(path, out);
            }
            closedir(d3);
        }
        closedir(d2);
    }
    closedir(d1);
    count_versions(s, bucket, out);
    return S3_OK;
}

/* ===================================================================== */
/* Multipart upload                                                       */
/* ===================================================================== */

/* Layout under <root>/mpu/:
 *
 *   mpu/<bucket>/<upload_id>/meta            — metadata (key, content-type)
 *   mpu/<bucket>/<upload_id>/part-NNNNN      — one file per part, raw bytes
 *
 * `meta` format (line-oriented, easy to read/write):
 *   key=<key bytes>
 *   ct=<content-type or empty>
 *   ctime_ms=<unix epoch ms>
 *
 * The key is one line; we don't expect newlines in keys (S3 keys are
 * arbitrary bytes per spec, but every real client uses URL-safe forms;
 * if a newline ever shows up we'd fail to parse, which is fine — that
 * client's request would have failed many other places first).
 */

static int random_hex_id(char *out, size_t out_n) {
    /* /dev/urandom for unpredictability. */
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    static const char H[] = "0123456789abcdef";
    size_t need = out_n / 2;
    uint8_t buf[64];
    if (need > sizeof(buf)) need = sizeof(buf);
    ssize_t r = read(fd, buf, need);
    close(fd);
    if (r < (ssize_t)need) return -1;
    for (size_t i = 0; i < need; i++) {
        out[2*i + 0] = H[(buf[i] >> 4) & 0xF];
        out[2*i + 1] = H[ buf[i]       & 0xF];
    }
    out[out_n - 1] = '\0';
    return 0;
}

/* Build path: <mpu_dir>/<bucket>/<upload_id> */
static int mpu_dir_path(const s3_store_t *s, s3_str_t bucket,
                        const char *upload_id, char *out, size_t cap) {
    int n = snprintf(out, cap, "%s/" S3_STR_FMT "/%s",
                     s->mpu_dir, S3_STR_ARG(bucket), upload_id);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

/* Build path: <mpu_dir>/<bucket>/<upload_id>/part-NNNNN */
static int mpu_part_path(const s3_store_t *s, s3_str_t bucket,
                         const char *upload_id, int part_number,
                         char *out, size_t cap) {
    int n = snprintf(out, cap, "%s/" S3_STR_FMT "/%s/part-%05d",
                     s->mpu_dir, S3_STR_ARG(bucket), upload_id, part_number);
    return (n < 0 || (size_t)n >= cap) ? -1 : n;
}

/* Recursively remove a directory tree. Used for mpu_abort/complete cleanup. */
static int rm_rf(const char *path) {
    DIR *d = opendir(path);
    if (!d) {
        if (errno == ENOENT) return 0;
        return -1;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
        char child[4096];
        if (snprintf(child, sizeof(child), "%s/%s", path, e->d_name)
            >= (int)sizeof(child)) {
            closedir(d); return -1;
        }
        struct stat st;
        if (lstat(child, &st) == 0 && S_ISDIR(st.st_mode)) {
            if (rm_rf(child) < 0) { closedir(d); return -1; }
        } else {
            if (unlink(child) < 0 && errno != ENOENT) {
                closedir(d); return -1;
            }
        }
    }
    closedir(d);
    return rmdir(path) < 0 && errno != ENOENT ? -1 : 0;
}

s3_err_t store_mpu_create(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                          const char *content_type,
                          char upload_id_out[S3_MULTIPART_UPLOAD_ID_LEN + 1]) {
    return store_mpu_create_opts(s, bucket, key, content_type, 0, 0,
                                 upload_id_out);
}

s3_err_t store_mpu_create_opts(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                               const char *content_type,
                               uint8_t cksum_algo, uint8_t cksum_type,
                               char upload_id_out[S3_MULTIPART_UPLOAD_ID_LEN + 1]) {
    return store_mpu_create_tlv(s, bucket, key, content_type, cksum_algo, cksum_type,
                                NULL, 0, upload_id_out);
}

s3_err_t store_mpu_create_tlv(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                              const char *content_type,
                              uint8_t cksum_algo, uint8_t cksum_type,
                              const uint8_t *tlv, size_t tlv_n,
                              char upload_id_out[S3_MULTIPART_UPLOAD_ID_LEN + 1]) {
    if (!s || !upload_id_out) return S3_ERR_INVALID_ARGUMENT;
    if (tlv_n > OBJ_MAX_TLV || (tlv_n && (!tlv || tlv_validate(tlv, tlv_n) < 0)))
        return S3_ERR_INVALID_ARGUMENT;
    if (content_type && strlen(content_type) > OBJ_MAX_CT_LEN) return S3_ERR_INVALID_ARGUMENT;
    if (cksum_algo >= S3_CKSUM_MAX || cksum_type > S3_CKSUM_TYPE_COMPOSITE)
        return S3_ERR_INVALID_ARGUMENT;
    /* Content-type and key go into a line-based file: no newlines. */
    if (memchr(key.p, '\n', key.n)
        || (content_type && strpbrk(content_type, "\r\n")))
        return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!valid_key(key))            return S3_ERR_INVALID_ARGUMENT;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;

    /* Generate a random upload ID (32 hex chars = 128 bits) until we
     * find one that doesn't exist. Collision probability is negligible
     * but we check anyway. */
    char id[S3_MULTIPART_UPLOAD_ID_LEN + 1];
    char dir[4096];
    for (int attempt = 0; attempt < 8; attempt++) {
        if (random_hex_id(id, sizeof(id)) < 0) return S3_ERR_INTERNAL;
        if (mpu_dir_path(s, bucket, id, dir, sizeof(dir)) < 0)
            return S3_ERR_INTERNAL;
        if (mkdir_p(dir, 0700) < 0) {
            /* Possible reasons: bucket subdir under mpu/ doesn't exist
             * yet, or filesystem error. mkdir_p creates parents. */
            return S3_ERR_INTERNAL;
        }
        /* mkdir_p succeeds even if dir already exists (it uses
         * EEXIST tolerantly). To detect collision, check if meta exists. */
        char meta[4096];
        if (snprintf(meta, sizeof(meta), "%s/meta", dir) >= (int)sizeof(meta))
            return S3_ERR_INTERNAL;
        if (access(meta, F_OK) == 0) {
            /* Real collision — vanishingly unlikely; loop. */
            continue;
        }
        /* Write meta atomically. */
        char meta_tmp[4096];
        if (snprintf(meta_tmp, sizeof(meta_tmp), "%s/meta.tmp", dir)
            >= (int)sizeof(meta_tmp)) return S3_ERR_INTERNAL;
        int fd = open(meta_tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) {
            s3_err_t e = map_io_err(errno);
            rmdir(dir);  /* don't leave a meta-less staging dir behind */
            return e;
        }
        FILE *fp = fdopen(fd, "w");
        if (!fp) { close(fd); unlink(meta_tmp); rmdir(dir); return S3_ERR_INTERNAL; }

        /* ctime_ms */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        uint64_t ctime_ms = (uint64_t)ts.tv_sec * 1000
                          + (uint64_t)ts.tv_nsec / 1000000;

        fprintf(fp, "key=" S3_STR_FMT "\n", S3_STR_ARG(key));
        fprintf(fp, "ct=%s\n", content_type ? content_type : "");
        fprintf(fp, "ctime_ms=%" PRIu64 "\n", ctime_ms);
        if (cksum_algo)
            fprintf(fp, "cksum=%u\ncktype=%u\n", cksum_algo, cksum_type);
        if (tlv_n) {
            fputs("tlv=", fp);
            for (size_t i = 0; i < tlv_n; i++) fprintf(fp, "%02x", tlv[i]);
            fputc('\n', fp);
        }
        if (fflush(fp) < 0 || xfsync(fileno(fp)) < 0) {
            s3_err_t e = map_io_err(errno);
            fclose(fp); unlink(meta_tmp); rmdir(dir);
            return e;
        }
        fclose(fp);
        if (rename(meta_tmp, meta) < 0) {
            s3_err_t e = map_io_err(errno);
            unlink(meta_tmp); rmdir(dir);
            return e;
        }
        fsync_dir(dir);

        memcpy(upload_id_out, id, sizeof(id));
        return S3_OK;
    }
    return S3_ERR_INTERNAL;
}

/* Read the meta file for an upload. Fills out_key and out_ct (each may
 * be NULL to skip). out_key/out_ct are malloc'd; caller frees. Returns
 * S3_OK or S3_ERR_NO_SUCH_UPLOAD if the meta file doesn't exist. */
static s3_err_t mpu_read_meta(const s3_store_t *s, s3_str_t bucket,
                              const char *upload_id,
                              char **out_key, size_t *out_key_n,
                              char **out_ct, uint8_t *out_algo,
                              uint8_t *out_type) {
    char dir[4096], meta[4096];
    if (mpu_dir_path(s, bucket, upload_id, dir, sizeof(dir)) < 0)
        return S3_ERR_INTERNAL;
    if (snprintf(meta, sizeof(meta), "%s/meta", dir) >= (int)sizeof(meta))
        return S3_ERR_INTERNAL;
    FILE *fp = fopen(meta, "r");
    if (!fp) {
        if (errno == ENOENT) return S3_ERR_NO_SUCH_UPLOAD;
        return S3_ERR_INTERNAL;
    }
    char *line = NULL;
    size_t line_cap = 0;
    if (out_key) *out_key = NULL;
    if (out_ct)  *out_ct  = NULL;
    if (out_key_n) *out_key_n = 0;
    if (out_algo) *out_algo = 0;
    if (out_type) *out_type = 0;
    ssize_t r;
    while ((r = getline(&line, &line_cap, fp)) > 0) {
        if (r > 0 && line[r-1] == '\n') { line[r-1] = '\0'; r--; }
        if (strncmp(line, "key=", 4) == 0 && out_key) {
            *out_key = strdup(line + 4);
            if (out_key_n) *out_key_n = (size_t)r - 4;
        } else if (strncmp(line, "ct=", 3) == 0 && out_ct) {
            *out_ct = strdup(line + 3);
        } else if (strncmp(line, "cksum=", 6) == 0 && out_algo) {
            unsigned long a = strtoul(line + 6, NULL, 10);
            *out_algo = a < S3_CKSUM_MAX ? (uint8_t)a : 0;
        } else if (strncmp(line, "cktype=", 7) == 0 && out_type) {
            *out_type = strtoul(line + 7, NULL, 10) == 1 ? 1 : 0;
        }
    }
    free(line);
    fclose(fp);
    return S3_OK;
}

/* ---- Part records (round 2, item 1a) ---------------------------------
 *
 * part-NNNNN.rec, written for every part next to part-NNNNN: the part's
 * MD5 (its ETag), size, mtime, verified checksum and payload CRC64. It
 * is renamed in *before* the part, in the same ns_mu section, so a part
 * without a record is treated as absent and a record without a part is
 * garbage for the GC. Complete verifies the client's ETag list against
 * these records and builds the multipart ETag from them, never from
 * request bytes. Uploads begun before records existed fall back to
 * hashing the part file (and their .ck sidecar). */
#define PART_REC_MAGIC "FS3PREC1"

typedef struct __attribute__((packed)) {
    char     magic[8];
    uint32_t version;          /* 1 */
    uint8_t  md5[16];
    uint64_t size;
    uint64_t mtime_ms;
    uint8_t  ck_algo;
    uint8_t  ck_n;
    uint8_t  has_crc;
    uint8_t  pad0;
    uint8_t  ck[32];
    uint8_t  crc64[8];         /* CRC64NVME of the part bytes, BE */
} part_rec_t;

_Static_assert(sizeof(part_rec_t) == 88, "part_rec_t layout");

/* 0 ok, 1 absent, -1 corrupt (fields bounded: the share is untrusted). */
static int part_rec_read(const char *part_path, part_rec_t *r) {
    char rp[4200];
    snprintf(rp, sizeof(rp), "%s.rec", part_path);
    int fd = open(rp, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? 1 : -1;
    ssize_t n = read(fd, r, sizeof(*r));
    close(fd);
    if (n != (ssize_t)sizeof(*r) || memcmp(r->magic, PART_REC_MAGIC, 8) != 0
        || r->version != 1 || r->ck_algo >= S3_CKSUM_MAX
        || r->ck_n > sizeof(r->ck) || (r->ck_algo && r->ck_n != cksum_digest_len(r->ck_algo)))
        return -1;
    return 0;
}

/* mpu_read_meta plus the TLV area captured at Create ("tlv=<hex>" line,
 * item 1e). out_tlv is malloc'd (NULL if none). */
static s3_err_t mpu_read_meta2(const s3_store_t *s, s3_str_t bucket,
                               const char *upload_id,
                               char **out_key, size_t *out_key_n, char **out_ct,
                               uint8_t *out_algo, uint8_t *out_type,
                               uint8_t **out_tlv, size_t *out_tlv_n);

s3_err_t store_mpu_part_begin(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                              const char *upload_id, int part_number,
                              s3_writer_t **out) {
    return store_mpu_part_begin_ssec(s, bucket, key, upload_id, part_number, NULL, out);
}

s3_err_t store_mpu_part_begin_ssec(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                                   const char *upload_id, int part_number,
                                   const uint8_t *ssec_key, s3_writer_t **out) {
    if (!s || !upload_id || !out) return S3_ERR_INVALID_ARGUMENT;
    if (part_number < 1 || part_number > 10000) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!valid_key(key))            return S3_ERR_INVALID_ARGUMENT;
    s3_err_t qe = quota_check(s);
    if (qe != S3_OK) return qe;

    /* Verify the upload exists and the key matches. */
    char *stored_key = NULL;
    size_t stored_key_n = 0;
    uint8_t mpu_algo = 0;
    s3_err_t err = mpu_read_meta(s, bucket, upload_id,
                                  &stored_key, &stored_key_n, NULL,
                                  &mpu_algo, NULL);
    if (err != S3_OK) return err;
    if (stored_key_n != key.n
        || memcmp(stored_key, key.p, key.n) != 0) {
        free(stored_key);
        return S3_ERR_NO_SUCH_UPLOAD;
    }
    free(stored_key);

    s3_writer_t *w = calloc(1, sizeof(*w));
    if (!w) return S3_ERR_INTERNAL;
    w->store = s;
    w->fd = -1;
    w->is_part = 1;
    w->mpu_algo = mpu_algo;
    if (cksum_begin(&w->pcrc, S3_CKSUM_CRC64NVME) < 0) { writer_free(w); return S3_ERR_INTERNAL; }

    /* SSE-C (item 8): an SSE-C upload needs the same key on every part;
     * a plain upload refuses one. */
    {
        uint8_t *mt = NULL; size_t mtn = 0;
        char *k2 = NULL, *c2 = NULL;
        mpu_read_meta2(s, bucket, upload_id, &k2, NULL, &c2, NULL, NULL, &mt, &mtn);
        free(k2); free(c2);
        ssec_info_t si;
        int r = ssec_tlv_find(mt, mtn, &si);
        free(mt);
        s3_err_t se = S3_OK;
        if (r < 0) se = S3_ERR_INTERNAL;
        else if (r == 1 && !ssec_key) se = S3_ERR_INVALID_REQUEST;
        else if (r == 0 && ssec_key) se = S3_ERR_INVALID_REQUEST;
        else if (r == 1 && !ssec_key_matches(ssec_key, &si)) se = S3_ERR_ACCESS_DENIED;
        if (se == S3_OK && r == 1) {
            s3_bucket_meta_t bm;
            if (store_bucket_meta(s, bucket, &bm) == S3_OK)
                memcpy(w->bucket_id, bm.id, sizeof(w->bucket_id));
            se = writer_ssec_on(w, ssec_key, &si, (uint32_t)part_number);
        }
        if (se != S3_OK) { writer_free(w); return se; }
    }

    snprintf(w->q_bucket, sizeof(w->q_bucket), S3_STR_FMT, S3_STR_ARG(bucket));
    if (q_reserve(s, w->q_bucket, 0, 0) != S3_OK) {
        writer_free(w); return S3_ERR_QUOTA_EXCEEDED;
    }
    /* Final destination: <mpu>/<bucket>/<upload_id>/part-NNNNN */
    if (mpu_part_path(s, bucket, upload_id, part_number,
                      w->final_path, sizeof(w->final_path)) < 0) {
        writer_free(w);
        return S3_ERR_INTERNAL;
    }
    /* Tmp file in tmp_dir. */
    if (snprintf(w->tmp_path, sizeof(w->tmp_path),
                 "%s/part.XXXXXX", s->tmp_dir) >= (int)sizeof(w->tmp_path)) {
        writer_free(w);
        return S3_ERR_INTERNAL;
    }
    w->fd = mkstemp(w->tmp_path);
    if (w->fd < 0) {
        s3_err_t e = map_io_err(errno);
        writer_free(w);
        return e;
    }
    if (s->fs_compress && !w->ssec && compress_worth_it(s, NULL, key.p, key.n, 0))
        (void)set_compr_flag(w->fd);

    w->md5_ctx = EVP_MD_CTX_new();
    if (!w->md5_ctx
        || EVP_DigestInit_ex(w->md5_ctx, EVP_md5(), NULL) != 1) {
        writer_free(w);
        return S3_ERR_INTERNAL;
    }

    *out = w;
    return S3_OK;
}

s3_err_t store_mpu_part_write(s3_writer_t *w, const void *buf, size_t n) {
    if (!w || w->finalized || !w->is_part) return S3_ERR_INVALID_ARGUMENT;
    if (n == 0) return S3_OK;
    if (writer_reserve_to(w, w->data_written + n) != S3_OK) return S3_ERR_QUOTA_EXCEEDED;
    return writer_feed(w, buf, n);
}

s3_err_t store_mpu_part_commit(s3_writer_t *w, char etag_hex_out[33]) {
    if (!w || w->finalized || !w->is_part) return S3_ERR_INVALID_ARGUMENT;
    w->finalized = 1;

    if (w->ssec && ssec_seal_buf(w, 1) != S3_OK) { writer_free(w); return S3_ERR_INTERNAL; }
    uint8_t mac[16];
    unsigned int mac_n = 16;
    if (EVP_DigestFinal_ex(w->md5_ctx, mac, &mac_n) != 1) {
        writer_free(w); return S3_ERR_INTERNAL;
    }
    if (etag_hex_out) {
        static const char H[] = "0123456789abcdef";
        for (int i = 0; i < 16; i++) {
            etag_hex_out[2*i + 0] = H[(mac[i] >> 4) & 0xF];
            etag_hex_out[2*i + 1] = H[ mac[i]       & 0xF];
        }
        etag_hex_out[32] = '\0';
    }

    /* An upload created with a checksum algorithm needs every part to
     * carry a verified checksum of that algorithm. */
    if (w->mpu_algo && w->ext.cksum_algo != w->mpu_algo) {
        writer_free(w); return S3_ERR_INVALID_CHECKSUM;
    }
    if (xfsync(w->fd) < 0) {
        s3_err_t e = map_io_err(errno);
        writer_free(w); return e;
    }
    close(w->fd); w->fd = -1;

    /* Part record, staged in tmp/ and renamed in first (see above). */
    part_rec_t rec;
    memset(&rec, 0, sizeof(rec));
    memcpy(rec.magic, PART_REC_MAGIC, 8);
    rec.version = 1;
    memcpy(rec.md5, mac, 16);
    rec.size = w->stored_written;       /* on disk (ciphertext for SSE-C) */
    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        rec.mtime_ms = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
    }
    if (w->ext.cksum_algo && !w->ssec) {   /* SSE-C: no plaintext digest at rest */
        rec.ck_algo = w->ext.cksum_algo;
        rec.ck_n = (uint8_t)cksum_digest_len(w->ext.cksum_algo);
        memcpy(rec.ck, w->ext.cksum, rec.ck_n);
    }
    if (w->pcrc.algo) {
        uint8_t d[CKSUM_MAX_DIGEST]; size_t dn;
        if (cksum_final(&w->pcrc, d, &dn) == 0 && dn == 8) {
            memcpy(rec.crc64, d, 8);
            rec.has_crc = 1;
        }
    }
    char rec_tmp[4096], rec_final[4200], ck_old[4200];
    snprintf(rec_final, sizeof(rec_final), "%s.rec", w->final_path);
    snprintf(ck_old, sizeof(ck_old), "%s.ck", w->final_path);
    int rfd = tmp_open(w->store, rec_tmp, sizeof(rec_tmp));
    if (rfd < 0) { s3_err_t e = map_io_err(errno); writer_free(w); return e; }
    if (xwrite(rfd, &rec, sizeof(rec)) != (ssize_t)sizeof(rec) || xfsync(rfd) < 0) {
        s3_err_t e = map_io_err(errno);
        close(rfd); unlink(rec_tmp); writer_free(w); return e;
    }
    close(rfd);
    /* ns_mu: an rm_rf of the upload dir (abort, GC, complete, bucket
     * delete) must not interleave with these renames, and Complete reads
     * record + part under the same lock. */
    pthread_mutex_lock(&w->store->ns_mu);
    struct stat old_st;
    uint64_t old_part = stat(w->final_path, &old_st) == 0 ? (uint64_t)old_st.st_size : 0;
    int rc = rename(rec_tmp, rec_final);
    if (rc == 0) {
        unlink(ck_old);                       /* superseded by the record */
        rc = rename(w->tmp_path, w->final_path);
    }
    int rename_errno = errno;
    if (rc == 0) {
        /* Parts count toward the quota while the upload is in flight. */
        q_charge(w->store, w->q_bucket, (int64_t)w->stored_written - (int64_t)old_part, 0);
        writer_release_quota(w);
    }
    pthread_mutex_unlock(&w->store->ns_mu);
    if (rc < 0) unlink(rec_tmp);
    if (rc < 0) {
        /* ENOENT: the upload dir vanished mid-stream (abort, GC, or
         * bucket delete ran while this part was uploading). */
        s3_err_t e = rename_errno == ENOENT ? S3_ERR_NO_SUCH_UPLOAD
                                            : map_io_err(rename_errno);
        writer_free(w); return e;
    }
    w->tmp_path[0] = '\0';  /* don't unlink the live file in writer_free */

    /* fsync the upload dir so the part is durable. */
    char dir[4096];
    snprintf(dir, sizeof(dir), "%.*s",
             (int)(strrchr(w->final_path, '/') - w->final_path),
             w->final_path);
    fsync_dir(dir);

    writer_free(w);
    return S3_OK;
}

void store_mpu_part_abort(s3_writer_t *w) {
    /* Same as store_put_abort: writer_free removes the tmp file. */
    if (w) writer_free(w);
}

s3_err_t store_mpu_abort(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                         const char *upload_id) {
    if (!s || !upload_id) return S3_ERR_INVALID_ARGUMENT;
    (void)key;  /* not strictly needed for abort, but accept it for symmetry */
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;

    char dir[4096];
    if (mpu_dir_path(s, bucket, upload_id, dir, sizeof(dir)) < 0)
        return S3_ERR_INTERNAL;
    /* Verify the upload existed (return NoSuchUpload if not). */
    char meta[4200];
    if (snprintf(meta, sizeof(meta), "%s/meta", dir) >= (int)sizeof(meta))
        return S3_ERR_INTERNAL;
    pthread_mutex_lock(&s->ns_mu);
    s3_err_t e = S3_OK;
    if (access(meta, F_OK) < 0)  e = S3_ERR_NO_SUCH_UPLOAD;
    else {
        uint64_t pb = upload_part_bytes(dir);
        if (rm_rf(dir) < 0) e = S3_ERR_INTERNAL;
        char bn[64];
        snprintf(bn, sizeof(bn), S3_STR_FMT, S3_STR_ARG(bucket));
        q_charge(s, bn, -(int64_t)(pb - upload_part_bytes(dir)), 0);
    }
    pthread_mutex_unlock(&s->ns_mu);
    return e;
}

/* Concatenate the part files into a single object file under data/.
 * On success, the new object replaces any existing object at <bucket>/<key>.
 *
 * Returns S3_OK and writes the multipart-style ETag ("hex-N") to
 * etag_out, plus standard meta to meta_out.
 */
s3_err_t store_mpu_complete(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                            const char *upload_id,
                            const s3_part_ref_t *parts, size_t n_parts,
                            char etag_out[40], s3_obj_meta_t *meta_out) {
    return store_mpu_complete2(s, bucket, key, upload_id, parts, n_parts,
                               NULL, 0, etag_out, meta_out);
}

s3_err_t store_mpu_checksum_info(s3_store_t *s, s3_str_t bucket,
                                 const char *upload_id,
                                 uint8_t *algo, uint8_t *type) {
    if (!s || !upload_id) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    return mpu_read_meta(s, bucket, upload_id, NULL, NULL, NULL, algo, type);
}

/* Read part-NNNNN.ck. Returns digest length, 0 if absent, -1 if corrupt. */
static int read_part_cksum(const char *part_path, uint8_t algo_want,
                           uint8_t out[32]) {
    char ck[4200];
    snprintf(ck, sizeof(ck), "%s.ck", part_path);
    int fd = open(ck, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    uint8_t rec[1 + 32 + 1];
    ssize_t n = read(fd, rec, sizeof(rec));
    close(fd);
    if (n < 1) return -1;
    size_t dn = cksum_digest_len(rec[0]);
    if (!dn || (size_t)n != 1 + dn || rec[0] != algo_want) return -1;
    memcpy(out, rec + 1, dn);
    return (int)dn;
}

/* One listed part, snapshotted under ns_mu: its record and an open fd on
 * exactly the bytes that record describes. */
typedef struct {
    int        fd;
    part_rec_t rec;
    int        legacy;        /* no .rec: hash the file now */
} part_snap_t;

static void snaps_close(part_snap_t *ps, size_t n) {
    if (!ps) return;
    for (size_t i = 0; i < n; i++) if (ps[i].fd >= 0) close(ps[i].fd);
    free(ps);
}

static int hexval1(char c) {
    return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10
         : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1;
}

/* Hash a legacy part (no record): MD5 + CRC64 over the file. */
static s3_err_t legacy_part_hash(part_snap_t *p) {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    cksum_ctx_t crc;
    if (!md || EVP_DigestInit_ex(md, EVP_md5(), NULL) != 1
        || cksum_begin(&crc, S3_CKSUM_CRC64NVME) < 0) {
        EVP_MD_CTX_free(md);
        return S3_ERR_INTERNAL;
    }
    char buf[64 * 1024];
    off_t off = 0;
    for (;;) {
        ssize_t r = pread(p->fd, buf, sizeof(buf), off);
        if (r < 0) { if (errno == EINTR) continue; EVP_MD_CTX_free(md); cksum_free(&crc); return S3_ERR_INTERNAL; }
        if (r == 0) break;
        EVP_DigestUpdate(md, buf, (size_t)r);
        cksum_update(&crc, buf, (size_t)r);
        off += r;
    }
    unsigned int mn = 16;
    EVP_DigestFinal_ex(md, p->rec.md5, &mn);
    EVP_MD_CTX_free(md);
    uint8_t d[CKSUM_MAX_DIGEST]; size_t dn;
    if (cksum_final(&crc, d, &dn) == 0) { memcpy(p->rec.crc64, d, 8); p->rec.has_crc = 1; }
    cksum_free(&crc);
    p->rec.size = (uint64_t)off;
    return S3_OK;
}

s3_err_t store_mpu_complete2(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                             const char *upload_id,
                             const s3_part_ref_t *parts, size_t n_parts,
                             const uint8_t *full_expect, size_t full_n,
                             char etag_out[40], s3_obj_meta_t *meta_out) {
    if (!s || !upload_id || !parts || n_parts == 0) return S3_ERR_INVALID_ARGUMENT;
    if (n_parts > 10000) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!valid_key(key))            return S3_ERR_INVALID_ARGUMENT;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;

    /* Part numbers strictly increasing, 1..10000. */
    for (size_t i = 0; i < n_parts; i++) {
        if (parts[i].part_number < 1 || parts[i].part_number > 10000
            || (i && parts[i].part_number <= parts[i-1].part_number))
            return S3_ERR_INVALID_PART_ORDER;
    }

    char *stored_key = NULL, *stored_ct = NULL;
    size_t stored_key_n = 0;
    uint8_t mpu_algo = 0, mpu_type = 0;
    uint8_t *mpu_tlv = NULL;
    size_t mpu_tlv_n = 0;
    s3_err_t err = mpu_read_meta2(s, bucket, upload_id, &stored_key, &stored_key_n,
                                  &stored_ct, &mpu_algo, &mpu_type, &mpu_tlv, &mpu_tlv_n);
    if (err != S3_OK) { free(stored_key); free(stored_ct); free(mpu_tlv); return err; }
    int key_ok = stored_key_n == key.n && memcmp(stored_key, key.p, key.n) == 0;
    free(stored_key);
    if (!key_ok) { free(stored_ct); free(mpu_tlv); return S3_ERR_NO_SUCH_UPLOAD; }
    /* SSE-C upload (item 8): parts are ciphertext; no checksums are kept
     * (they would be plaintext digests); the object gets a part table. */
    ssec_info_t ssec_si;
    int is_ssec = ssec_tlv_find(mpu_tlv, mpu_tlv_n, &ssec_si) == 1;
    if (is_ssec) mpu_algo = 0;
    ssec_part_t *ssec_pt = NULL;
    uint8_t *tlv_out = NULL;
    uint64_t plain_total = 0;

    part_snap_t *ps = calloc(n_parts, sizeof(*ps));
    cksum_ctx_t comp, full;
    memset(&comp, 0, sizeof(comp));
    memset(&full, 0, sizeof(full));
    int tfd = -1;
    char tmp_path[4096] = "";
    s3_err_t e = S3_OK;
    if (!ps) { e = S3_ERR_INTERNAL; goto out; }
    for (size_t i = 0; i < n_parts; i++) ps[i].fd = -1;

    /* 1. Snapshot record + part under ns_mu: a concurrent re-upload of a
     *    part number can't pair an old record with new bytes (the open fd
     *    keeps the bytes the record describes). */
    pthread_mutex_lock(&s->ns_mu);
    for (size_t i = 0; i < n_parts && e == S3_OK; i++) {
        char pp[4096];
        if (mpu_part_path(s, bucket, upload_id, parts[i].part_number, pp, sizeof(pp)) < 0) {
            e = S3_ERR_INTERNAL; break;
        }
        int rr = part_rec_read(pp, &ps[i].rec);
        if (rr < 0) { e = S3_ERR_INVALID_PART; break; }
        ps[i].fd = open(pp, O_RDONLY | O_CLOEXEC);
        if (ps[i].fd < 0) { e = S3_ERR_INVALID_PART; break; }
        if (rr == 1) {
            /* Pre-upgrade part: no record; honour its .ck, hash later. */
            ps[i].legacy = 1;
            memset(&ps[i].rec, 0, sizeof(ps[i].rec));
            if (mpu_algo) {
                int n = read_part_cksum(pp, mpu_algo, ps[i].rec.ck);
                if (n > 0) { ps[i].rec.ck_algo = mpu_algo; ps[i].rec.ck_n = (uint8_t)n; }
            }
        } else {
            struct stat st;
            if (fstat(ps[i].fd, &st) < 0 || (uint64_t)st.st_size != ps[i].rec.size)
                e = S3_ERR_INVALID_PART;      /* record and part disagree */
        }
    }
    pthread_mutex_unlock(&s->ns_mu);
    if (e != S3_OK) goto out;

    /* 2. Verify every listed part against its record. */
    uint64_t total_size = 0, crc = 0;
    int crc_ok = 1;
    EVP_MD_CTX *etag_md = EVP_MD_CTX_new();
    if (!etag_md || EVP_DigestInit_ex(etag_md, EVP_md5(), NULL) != 1) {
        EVP_MD_CTX_free(etag_md); e = S3_ERR_INTERNAL; goto out;
    }
    if (mpu_algo) {
        int a = mpu_type == S3_CKSUM_TYPE_COMPOSITE ? cksum_begin(&comp, mpu_algo)
                                                    : cksum_begin(&full, mpu_algo);
        if (a < 0) { EVP_MD_CTX_free(etag_md); e = S3_ERR_INTERNAL; goto out; }
    }
    for (size_t i = 0; i < n_parts; i++) {
        part_snap_t *p = &ps[i];
        if (p->legacy && (e = legacy_part_hash(p)) != S3_OK) break;
        /* Client ETag (32 hex, any case) must equal the recorded MD5. */
        uint8_t want[16];
        int hex_ok = strlen(parts[i].etag_hex) == 32;
        for (int j = 0; j < 16 && hex_ok; j++) {
            int hi = hexval1(parts[i].etag_hex[2*j]), lo = hexval1(parts[i].etag_hex[2*j+1]);
            if (hi < 0 || lo < 0) hex_ok = 0;
            else want[j] = (uint8_t)(hi << 4 | lo);
        }
        if (!hex_ok || memcmp(want, p->rec.md5, 16) != 0) { e = S3_ERR_INVALID_PART; break; }
        /* S3: every part but the last must be at least the minimum size. */
        if (i + 1 < n_parts && p->rec.size < s->mpu_min_part) { e = S3_ERR_ENTITY_TOO_SMALL; break; }
        if (mpu_algo) {
            if (p->rec.ck_algo != mpu_algo
                || (parts[i].cksum_n && (parts[i].cksum_n != p->rec.ck_n
                                         || memcmp(parts[i].cksum, p->rec.ck, p->rec.ck_n)))) {
                e = S3_ERR_INVALID_PART; break;
            }
            if (comp.algo) cksum_update(&comp, p->rec.ck, p->rec.ck_n);
        }
        EVP_DigestUpdate(etag_md, p->rec.md5, 16);
        if (p->rec.has_crc) {
            uint64_t pc = crc64nvme_from_be(p->rec.crc64);
            crc = i ? crc64nvme_combine(crc, pc, p->rec.size) : pc;
        } else {
            crc_ok = 0;
        }
        total_size += p->rec.size;
        plain_total += is_ssec ? ssec_plain_len(p->rec.size, ssec_si.seg) : p->rec.size;
    }
    uint8_t mp_md5[16];
    unsigned int mp_md5_n = 16;
    EVP_DigestFinal_ex(etag_md, mp_md5, &mp_md5_n);
    EVP_MD_CTX_free(etag_md);
    if (e != S3_OK) goto out;

    char hex[65], target_dir[4096], target_path[4096];
    hash_bucket_key(bucket, key, hex);
    if (obj_dir(s, bucket, hex, target_dir, sizeof(target_dir)) < 0
        || obj_path(s, bucket, hex, target_path, sizeof(target_path)) < 0) {
        e = S3_ERR_INTERNAL; goto out;
    }
    snprintf(tmp_path, sizeof(tmp_path), "%s/mpu.XXXXXX", s->tmp_dir);
    tfd = mkstemp(tmp_path);
    if (tfd >= 0 && s->fs_compress && compress_worth_it(s, stored_ct, key.p, key.n, 0))
        (void)set_compr_flag(tfd);
    if (tfd < 0) { tmp_path[0] = '\0'; e = map_io_err(errno); goto out; }

    /* 3. Assemble: prefix, then the snapshotted part bytes. */
    obj_header_t hdr;
    obj_ext_v3_t ext;
    obj_ext_v4_t ext4;
    memset(&hdr, 0, sizeof(hdr));
    memset(&ext, 0, sizeof(ext));
    memset(&ext4, 0, sizeof(ext4));
    size_t ct_n = stored_ct ? strlen(stored_ct) : 0;
    hdr.part_count = (uint16_t)n_parts;
    hdr.data_size = plain_total;
    memcpy(hdr.etag, mp_md5, 16);
    ext4.stored_size = total_size;
    const uint8_t *obj_tlv = mpu_tlv;
    size_t obj_tlv_n = mpu_tlv_n;
    if (is_ssec) {
        ssec_pt = malloc(n_parts * sizeof(*ssec_pt));
        tlv_out = malloc(mpu_tlv_n + 6 + 12 * n_parts);
        if (!ssec_pt || !tlv_out || mpu_tlv_n + 6 + 12 * n_parts > OBJ_MAX_TLV) {
            e = S3_ERR_INTERNAL; goto out;
        }
        for (size_t i = 0; i < n_parts; i++) {
            ssec_pt[i].part = (uint32_t)parts[i].part_number;
            ssec_pt[i].plain = ssec_plain_len(ps[i].rec.size, ssec_si.seg);
        }
        memcpy(tlv_out, mpu_tlv, mpu_tlv_n);
        obj_tlv_n = mpu_tlv_n + ssec_parttable_encode(ssec_pt, n_parts, tlv_out + mpu_tlv_n);
        obj_tlv = tlv_out;
        ext.flags |= S3_OBJF_SSEC;
    }
    int versioning = bucket_versioning(s, bucket);
    if (versioning == S3_VERSIONING_ENABLED && random_vid(ext.version_id) < 0) {
        e = S3_ERR_INTERNAL; goto out;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    hdr.mtime_ms = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
    if (obj_write_prefix(s, tfd, &hdr, &ext, &ext4, stored_ct, ct_n,
                         key.p, key.n, obj_tlv, obj_tlv_n) < 0) {
        e = map_io_err(errno); goto out;
    }
    /* Reflink fast path (item 6a): clone each part's extents into the
     * padded object file — no bytes copied, no double disk space. A part
     * that can't be cloned (misaligned, ioctl refused) is copied. Bytes
     * are read only when a full-object checksum needs them. */
    off_t data_off = lseek(tfd, 0, SEEK_CUR);
    uint64_t doff = data_off < 0 ? 0 : (uint64_t)data_off;
    int try_clone = s->reflink && data_off >= 0 && doff % CLONE_BLK == 0;
    for (size_t i = 0; i < n_parts && e == S3_OK; i++) {
        char buf[64 * 1024];
        int cloned = try_clone && (i + 1 == n_parts || ps[i].rec.size % CLONE_BLK == 0)
                     && clone_range(tfd, doff, ps[i].fd, 0, ps[i].rec.size) == 0;
        if (!cloned) try_clone = 0;            /* keep the rest sequential */
        off_t off = 0;
        if (!cloned || full.algo) {
            for (;;) {
                ssize_t r = pread(ps[i].fd, buf, sizeof(buf), off);
                if (r == 0) break;
                if (r < 0) { if (errno == EINTR) continue; e = S3_ERR_INTERNAL; break; }
                if (full.algo) cksum_update(&full, buf, (size_t)r);
                if (!cloned && pwrite(tfd, buf, (size_t)r, (off_t)(doff + (uint64_t)off)) != r) {
                    e = map_io_err(errno); break;
                }
                off += r;
            }
        } else {
            off = (off_t)ps[i].rec.size;
        }
        if (e == S3_OK && (uint64_t)off != ps[i].rec.size) e = S3_ERR_INVALID_PART;
        doff += ps[i].rec.size;
    }
    if (e != S3_OK) goto out;

    /* Object checksum (v3) and payload CRC (v4, combined from the parts). */
    if (mpu_algo) {
        uint8_t dg[32]; size_t dn = 0;
        cksum_ctx_t *k = comp.algo ? &comp : &full;
        if (cksum_final(k, dg, &dn) < 0) { e = S3_ERR_INTERNAL; goto out; }
        if (!comp.algo && full_expect
            && (full_n != dn || memcmp(full_expect, dg, dn) != 0)) {
            e = S3_ERR_CHECKSUM_MISMATCH; goto out;
        }
        ext.cksum_algo = mpu_algo;
        ext.cksum_type = mpu_type;
        ext.cksum_parts = mpu_type == S3_CKSUM_TYPE_COMPOSITE ? (uint16_t)n_parts : 0;
        memcpy(ext.cksum, dg, dn);
    }
    if (crc_ok) {
        crc64nvme_to_be(crc, ext4.payload_crc64);
        ext.flags |= S3_OBJF_PAYLOAD_CRC;
    }
    if (obj_rewrite_fixed(tfd, &hdr, &ext, &ext4) < 0 || xfsync(tfd) < 0) {
        e = map_io_err(errno); goto out;
    }
    close(tfd);
    tfd = -1;

    /* 4. Publish under the key stripe + ns_mu. The assembly can take a
     *    long time on a worker, so re-check bucket and upload; the
     *    staging dir goes in the same critical section. */
    char up_dir[4096], up_meta[4200];
    mpu_dir_path(s, bucket, upload_id, up_dir, sizeof(up_dir));
    snprintf(up_meta, sizeof(up_meta), "%s/meta", up_dir);
    pthread_mutex_t *km = key_lock(s, hex);
    pthread_mutex_lock(km);
    uint64_t q_b0 = 0, q_o0 = 0, q_parts = 0;
    key_usage(s, bucket, hex, &q_b0, &q_o0);
    pthread_mutex_lock(&s->ns_mu);
    if (!store_bucket_exists(s, bucket))          e = S3_ERR_NO_SUCH_BUCKET;
    else if (access(up_meta, F_OK) < 0)           e = S3_ERR_NO_SUCH_UPLOAD;
    else if (bucket_layout(s, bucket) == 2) {
        e = l2_publish(s, bucket, hex, tmp_path, hdr.mtime_ms, ext.version_id);
        if (e == S3_OK) { q_parts = upload_part_bytes(up_dir); rm_rf(up_dir); tmp_path[0] = '\0'; }
    }
    else if ((e = link_aside_locked(s, bucket, hex, target_path, versioning)) != S3_OK) ;
    else if (mkdir_p(target_dir, 0700) < 0
             || rename(tmp_path, target_path) < 0) e = map_io_err(errno);
    else {
        q_parts = upload_part_bytes(up_dir);
        rm_rf(up_dir);
        tmp_path[0] = '\0';
    }
    pthread_mutex_unlock(&s->ns_mu);
    if (e == S3_OK) {
        /* The parts' charge becomes the object's (plus whatever it
         * replaced or moved aside). */
        uint64_t q_b1 = 0, q_o1 = 0;
        key_usage(s, bucket, hex, &q_b1, &q_o1);
        char bn[64];
        snprintf(bn, sizeof(bn), S3_STR_FMT, S3_STR_ARG(bucket));
        q_charge(s, bn, (int64_t)q_b1 - (int64_t)q_b0 - (int64_t)q_parts,
                 (int64_t)q_o1 - (int64_t)q_o0);
    }
    pthread_mutex_unlock(km);
    if (e != S3_OK) goto out;
    fsync_dir(target_dir);

    if (etag_out) {
        static const char H[] = "0123456789abcdef";
        char mh[33];
        for (int i = 0; i < 16; i++) { mh[2*i] = H[mp_md5[i] >> 4]; mh[2*i+1] = H[mp_md5[i] & 15]; }
        mh[32] = '\0';
        snprintf(etag_out, 40, "%s-%zu", mh, n_parts);
    }
    if (meta_out) {
        memset(meta_out, 0, sizeof(*meta_out));
        meta_out->size = total_size;
        meta_out->stored_size = total_size;
        meta_out->mtime_ms = hdr.mtime_ms;
        meta_out->part_count = (uint16_t)n_parts;
        memcpy(meta_out->etag, mp_md5, 16);
        memcpy(meta_out->version_id, ext.version_id, 16);
        meta_out->flags = ext.flags;
        meta_out->cksum_algo  = ext.cksum_algo;
        meta_out->cksum_type  = ext.cksum_type;
        meta_out->cksum_parts = ext.cksum_parts;
        memcpy(meta_out->cksum, ext.cksum, 32);
        memcpy(meta_out->payload_crc64, ext4.payload_crc64, 8);
        meta_out->header_size = hdr.header_size;
        if (stored_ct) snprintf(meta_out->content_type, sizeof(meta_out->content_type), "%s", stored_ct);
    }
out:
    if (tfd >= 0) close(tfd);
    if (tmp_path[0]) unlink(tmp_path);
    snaps_close(ps, n_parts);
    cksum_free(&comp);
    cksum_free(&full);
    free(stored_ct);
    free(mpu_tlv);
    free(ssec_pt);
    free(tlv_out);
    return e;
}

/* ===================================================================== */
/* List in-flight multipart uploads                                       */
/* ===================================================================== */

/* ---- ListParts (round 2, item 1b) ----------------------------------- */

static int part_info_cmp(const void *a, const void *b) {
    const s3_part_info_t *x = a, *y = b;
    return x->part_number < y->part_number ? -1 : x->part_number > y->part_number;
}

s3_err_t store_mpu_list_parts(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                              const char *upload_id, uint32_t marker, size_t max,
                              s3_part_info_t **out, size_t *n_out, int *truncated,
                              uint8_t *algo_out, uint8_t *type_out) {
    if (!s || !out || !n_out || !truncated || !upload_id) return S3_ERR_INVALID_ARGUMENT;
    *out = NULL; *n_out = 0; *truncated = 0;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;
    if (strlen(upload_id) != S3_MULTIPART_UPLOAD_ID_LEN) return S3_ERR_NO_SUCH_UPLOAD;
    if (max == 0 || max > 1000) max = 1000;

    char *stored_key = NULL; size_t stored_key_n = 0;
    uint8_t algo = 0, type = 0;
    s3_err_t err = mpu_read_meta(s, bucket, upload_id, &stored_key, &stored_key_n,
                                 NULL, &algo, &type);
    if (err != S3_OK) { free(stored_key); return err; }
    int key_ok = stored_key && stored_key_n == key.n && memcmp(stored_key, key.p, key.n) == 0;
    free(stored_key);
    if (!key_ok) return S3_ERR_NO_SUCH_UPLOAD;
    if (algo_out) *algo_out = algo;
    if (type_out) *type_out = type;
    int list_ssec = 0;
    {
        uint8_t *mt = NULL; size_t mtn = 0;
        char *k2 = NULL, *c2 = NULL;
        ssec_info_t si;
        if (mpu_read_meta2(s, bucket, upload_id, &k2, NULL, &c2, NULL, NULL, &mt, &mtn) == S3_OK)
            list_ssec = ssec_tlv_find(mt, mtn, &si) == 1;
        free(k2); free(c2); free(mt);
    }

    char dir[4096];
    if (snprintf(dir, sizeof(dir), "%s/" S3_STR_FMT "/%s", s->mpu_dir,
                 S3_STR_ARG(bucket), upload_id) >= (int)sizeof(dir))
        return S3_ERR_INTERNAL;
    DIR *d = opendir(dir);
    if (!d) return errno == ENOENT ? S3_ERR_NO_SUCH_UPLOAD : S3_ERR_INTERNAL;

    size_t cap = 16, n = 0;
    s3_part_info_t *arr = malloc(cap * sizeof(*arr));
    if (!arr) { closedir(d); return S3_ERR_INTERNAL; }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        /* Exactly "part-NNNNN": skips .rec, .ck and anything foreign. */
        if (strlen(e->d_name) != 10 || strncmp(e->d_name, "part-", 5) != 0) continue;
        uint32_t pn = 0; int ok = 1;
        for (int i = 5; i < 10; i++) {
            if (e->d_name[i] < '0' || e->d_name[i] > '9') { ok = 0; break; }
            pn = pn * 10 + (uint32_t)(e->d_name[i] - '0');
        }
        if (!ok || pn < 1 || pn > 10000 || pn <= marker) continue;
        char pp[4200];
        snprintf(pp, sizeof(pp), "%s/%s", dir, e->d_name);

        /* Record + bytes under ns_mu, as at Complete. */
        part_snap_t ps;
        memset(&ps, 0, sizeof(ps));
        pthread_mutex_lock(&s->ns_mu);
        int rr = part_rec_read(pp, &ps.rec);
        ps.fd = rr < 0 ? -1 : open(pp, O_RDONLY | O_CLOEXEC);
        pthread_mutex_unlock(&s->ns_mu);
        if (ps.fd < 0) continue;            /* corrupt record or gone */
        struct stat st;
        if (fstat(ps.fd, &st) < 0) { close(ps.fd); continue; }
        if (rr == 1) {
            /* Pre-upgrade part: hash it (ListParts on a legacy upload is
             * rare; it dies with its upload). */
            if (legacy_part_hash(&ps) != S3_OK) { close(ps.fd); continue; }
            ps.rec.mtime_ms = (uint64_t)st.st_mtim.tv_sec * 1000
                            + (uint64_t)st.st_mtim.tv_nsec / 1000000;
            if (algo) {
                int cn = read_part_cksum(pp, algo, ps.rec.ck);
                if (cn > 0) { ps.rec.ck_algo = algo; ps.rec.ck_n = (uint8_t)cn; }
            }
        } else if ((uint64_t)st.st_size != ps.rec.size) {
            close(ps.fd); continue;         /* mid re-upload */
        }
        close(ps.fd);
        if (n == cap) {
            s3_part_info_t *na = realloc(arr, cap * 2 * sizeof(*na));
            if (!na) { free(arr); closedir(d); return S3_ERR_INTERNAL; }
            arr = na; cap *= 2;
        }
        s3_part_info_t *pi = &arr[n++];
        memset(pi, 0, sizeof(*pi));
        pi->part_number = pn;
        pi->size = list_ssec ? ssec_plain_len(ps.rec.size, SSEC_SEG) : ps.rec.size;
        pi->mtime_ms = ps.rec.mtime_ms;
        static const char hx[] = "0123456789abcdef";
        for (int i = 0; i < 16; i++) {
            pi->etag[2*i] = hx[ps.rec.md5[i] >> 4];
            pi->etag[2*i+1] = hx[ps.rec.md5[i] & 15];
        }
        if (ps.rec.ck_algo == algo && ps.rec.ck_n) {
            pi->ck_algo = ps.rec.ck_algo;
            pi->ck_n = ps.rec.ck_n;
            memcpy(pi->ck, ps.rec.ck, ps.rec.ck_n);
        }
    }
    closedir(d);
    qsort(arr, n, sizeof(*arr), part_info_cmp);
    if (n > max) { *truncated = 1; n = max; }
    *out = arr; *n_out = n;
    return S3_OK;
}

/* Startup: a record without its part is left by a crash between the two
 * renames of a part commit (record first). Remove it so a later upload
 * of the same number can't be confused by it. */
static void recover_mpu_orphans(const s3_store_t *s) {
    DIR *bd = opendir(s->mpu_dir);
    if (!bd) return;
    int n = 0;
    struct dirent *b;
    while ((b = readdir(bd)) != NULL) {
        if (b->d_name[0] == '.') continue;
        char bp[4096];
        if (snprintf(bp, sizeof(bp), "%s/%s", s->mpu_dir, b->d_name) >= (int)sizeof(bp)) continue;
        DIR *ud = opendir(bp);
        if (!ud) continue;
        struct dirent *u;
        while ((u = readdir(ud)) != NULL) {
            if (strlen(u->d_name) != S3_MULTIPART_UPLOAD_ID_LEN) continue;
            char up[4200];
            snprintf(up, sizeof(up), "%s/%s", bp, u->d_name);
            DIR *pd = opendir(up);
            if (!pd) continue;
            struct dirent *f;
            while ((f = readdir(pd)) != NULL) {
                size_t fl = strlen(f->d_name);
                if (fl != 14 || strncmp(f->d_name, "part-", 5) != 0
                    || strcmp(f->d_name + 10, ".rec") != 0) continue;
                char rp[4400], pp[4400];
                snprintf(rp, sizeof(rp), "%s/%s", up, f->d_name);
                snprintf(pp, sizeof(pp), "%s/%.10s", up, f->d_name);
                struct stat st;
                if (stat(pp, &st) < 0 && errno == ENOENT && unlink(rp) == 0) n++;
            }
            closedir(pd);
        }
        closedir(ud);
    }
    closedir(bd);
    if (n > 0) LOG_I("recover: removed %d orphan part record(s)", n);
}

s3_err_t store_list_mpu_uploads(s3_store_t *s, s3_str_t bucket,
                                s3_str_t key_prefix,
                                s3_mpu_info_t **out, size_t *n_out) {
    if (!s || !out || !n_out) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;

    *out = NULL;
    *n_out = 0;

    char bucket_mpu_dir[4096];
    if (snprintf(bucket_mpu_dir, sizeof(bucket_mpu_dir), "%s/" S3_STR_FMT,
                 s->mpu_dir, S3_STR_ARG(bucket)) >= (int)sizeof(bucket_mpu_dir)) {
        return S3_ERR_INTERNAL;
    }

    DIR *d = opendir(bucket_mpu_dir);
    if (!d) {
        if (errno == ENOENT) return S3_OK;  /* no uploads yet */
        return S3_ERR_INTERNAL;
    }

    size_t cap = 16, n = 0;
    s3_mpu_info_t *arr = malloc(cap * sizeof(*arr));
    if (!arr) { closedir(d); return S3_ERR_INTERNAL; }

    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        /* Upload IDs are exactly 32 hex chars. */
        if (strlen(e->d_name) != S3_MULTIPART_UPLOAD_ID_LEN) continue;

        char *stored_key = NULL;
        size_t stored_key_n = 0;
        s3_err_t er = mpu_read_meta(s, bucket, e->d_name,
                                     &stored_key, &stored_key_n, NULL,
                                     NULL, NULL);
        if (er != S3_OK || !stored_key) {
            free(stored_key);
            continue;
        }

        /* Optional prefix filter. */
        if (key_prefix.n > 0) {
            if (stored_key_n < key_prefix.n
                || memcmp(stored_key, key_prefix.p, key_prefix.n) != 0) {
                free(stored_key);
                continue;
            }
        }

        /* Use ctime of the meta file as the upload's initiation time. */
        char meta_path[4200];
        snprintf(meta_path, sizeof(meta_path), "%s/%s/meta",
                 bucket_mpu_dir, e->d_name);
        struct stat st;
        uint64_t ctime_ms = 0;
        if (stat(meta_path, &st) == 0) {
            ctime_ms = (uint64_t)st.st_mtim.tv_sec * 1000
                     + (uint64_t)st.st_mtim.tv_nsec / 1000000;
        }

        if (n == cap) {
            size_t nc = cap * 2;
            s3_mpu_info_t *na = realloc(arr, nc * sizeof(*na));
            if (!na) {
                free(stored_key);
                store_mpu_uploads_free(arr, n);
                closedir(d);
                return S3_ERR_INTERNAL;
            }
            arr = na; cap = nc;
        }
        arr[n].key = stored_key;       /* takes ownership */
        memcpy(arr[n].upload_id, e->d_name, S3_MULTIPART_UPLOAD_ID_LEN);
        arr[n].upload_id[S3_MULTIPART_UPLOAD_ID_LEN] = '\0';
        arr[n].ctime_ms = ctime_ms;
        n++;
    }
    closedir(d);

    *out = arr;
    *n_out = n;
    return S3_OK;
}

void store_mpu_uploads_free(s3_mpu_info_t *list, size_t n) {
    if (!list) return;
    for (size_t i = 0; i < n; i++) free(list[i].key);
    free(list);
}

/* ===================================================================== */
/* Multipart GC                                                           */
/* ===================================================================== */

/* Read ctime_ms from a staging dir's meta file. Returns 0 if the file
 * is missing or unparseable (which causes the caller to skip the dir
 * rather than reap it — be conservative). */
static uint64_t read_meta_ctime_ms(const char *meta_path) {
    FILE *fp = fopen(meta_path, "r");
    if (!fp) return 0;
    char *line = NULL;
    size_t cap = 0;
    uint64_t ctime_ms = 0;
    ssize_t r;
    while ((r = getline(&line, &cap, fp)) > 0) {
        if (r > 0 && line[r-1] == '\n') line[r-1] = '\0';
        if (strncmp(line, "ctime_ms=", 9) == 0) {
            ctime_ms = strtoull(line + 9, NULL, 10);
            break;
        }
    }
    free(line);
    fclose(fp);
    return ctime_ms;
}

int store_mpu_gc(s3_store_t *s, uint64_t now_ms, uint64_t max_age_ms) {
    if (!s) return -1;
    int removed = 0;

    DIR *bd = opendir(s->mpu_dir);
    if (!bd) {
        if (errno == ENOENT) return 0;
        return -1;
    }

    struct dirent *be;
    while ((be = readdir(bd)) != NULL) {
        if (be->d_name[0] == '.') continue;

        char bucket_dir[4096];
        if (snprintf(bucket_dir, sizeof(bucket_dir), "%s/%s",
                     s->mpu_dir, be->d_name) >= (int)sizeof(bucket_dir)) {
            continue;
        }
        DIR *ud = opendir(bucket_dir);
        if (!ud) continue;

        struct dirent *ue;
        while ((ue = readdir(ud)) != NULL) {
            if (ue->d_name[0] == '.') continue;
            if (strlen(ue->d_name) != S3_MULTIPART_UPLOAD_ID_LEN) continue;

            char up_dir[4200];
            if (snprintf(up_dir, sizeof(up_dir), "%s/%s",
                         bucket_dir, ue->d_name) >= (int)sizeof(up_dir)) {
                continue;
            }
            char meta_path[4300];
            if (snprintf(meta_path, sizeof(meta_path), "%s/meta", up_dir)
                >= (int)sizeof(meta_path)) {
                continue;
            }
            uint64_t ctime_ms = read_meta_ctime_ms(meta_path);
            if (ctime_ms == 0) continue;  /* unknown age — skip conservatively */
            if (now_ms < ctime_ms) continue;
            if (now_ms - ctime_ms < max_age_ms) continue;
            if (s->mpu_gc_filter) {
                /* A bucket lifecycle AbortIncompleteMultipartUpload rule
                 * covering this key overrides the global TTL. */
                char *k = NULL; size_t kn = 0;
                s3_str_t bn = { be->d_name, strlen(be->d_name) };
                if (mpu_read_meta(s, bn, ue->d_name, &k, &kn, NULL, NULL, NULL) == S3_OK
                    && k) {
                    int skip = s->mpu_gc_filter(s->mpu_gc_filter_user, bn,
                                                (s3_str_t){ k, kn });
                    free(k);
                    if (skip) continue;
                }
            }

            LOG_I("mpu_gc: reaping stale upload %s (age=%" PRIu64 "ms)",
                  ue->d_name, now_ms - ctime_ms);
            pthread_mutex_lock(&s->ns_mu);
            uint64_t pb = upload_part_bytes(up_dir);
            if (rm_rf(up_dir) == 0) removed++;
            q_charge(s, be->d_name, -(int64_t)(pb - upload_part_bytes(up_dir)), 0);
            pthread_mutex_unlock(&s->ns_mu);
        }
        closedir(ud);
    }
    closedir(bd);
    return removed;
}

/* ===================================================================== */
/* Object walk + lifecycle expiry                                         */
/* ===================================================================== */

void store_set_mpu_gc_filter(s3_store_t *s,
                             int (*filter)(void *user, s3_str_t bucket,
                                           s3_str_t key),
                             void *user) {
    if (!s) return;
    s->mpu_gc_filter = filter;
    s->mpu_gc_filter_user = user;
}

s3_err_t store_walk_objects(s3_store_t *s, s3_str_t bucket,
                            store_walk_cb cb, void *user) {
    if (!s || !cb) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;
    char dp[4096];
    snprintf(dp, sizeof(dp), "%s/" S3_STR_FMT, s->data_dir, S3_STR_ARG(bucket));
    DIR *d1 = opendir(dp);
    if (!d1) return S3_OK;
    struct dirent *e1;
    int stop = 0;
    while (!stop && (e1 = readdir(d1)) != NULL) {
        if (e1->d_name[0] == '.') continue;
        char p2[4400];
        snprintf(p2, sizeof(p2), "%s/%s", dp, e1->d_name);
        DIR *d2 = opendir(p2);
        if (!d2) continue;
        struct dirent *e2;
        while (!stop && (e2 = readdir(d2)) != NULL) {
            if (e2->d_name[0] == '.') continue;
            char p3[4700];
            snprintf(p3, sizeof(p3), "%s/%s", p2, e2->d_name);
            DIR *d3 = opendir(p3);
            if (!d3) continue;
            struct dirent *e3;
            while (!stop && (e3 = readdir(d3)) != NULL) {
                if (e3->d_name[0] == '.') continue;
                char fp[5000];
                snprintf(fp, sizeof(fp), "%s/%s", p3, e3->d_name);
                list_entry_t ent;
                if (load_entry(fp, &ent) < 0) continue;
                stop = cb(user, (s3_str_t){ ent.key, ent.key_len }, &ent.meta);
                free(ent.key);
            }
            closedir(d3);
        }
        closedir(d2);
    }
    closedir(d1);
    return S3_OK;
}

s3_err_t store_expire_if_unchanged(s3_store_t *s, s3_str_t bucket,
                                   s3_str_t key, uint64_t mtime_ms) {
    if (!s) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!valid_key(key)) return S3_ERR_INVALID_ARGUMENT;
    char hex[65];
    hash_bucket_key(bucket, key, hex);
    pthread_mutex_t *km = key_lock(s, hex);
    pthread_mutex_lock(km);
    /* Normal delete path: a versioned bucket gets a delete marker. */
    store_delete_result_t res;
    memset(&res, 0, sizeof(res));
    s3_err_t e = delete_locked(s, bucket, key, hex, NULL, mtime_ms, &res);
    pthread_mutex_unlock(km);
    return e;
}

int store_valid_bucket_name(s3_str_t name) { return valid_bucket_name(name); }

/* ===================================================================== */
/* Versioning (item 8)                                                    */
/* ===================================================================== */

static __thread int g_guard_bypass;

void store_set_guard_bypass(int bypass) { g_guard_bypass = bypass; }

void store_set_version_guard(s3_store_t *s, store_version_guard_fn fn, void *user) {
    if (!s) return;
    s->vguard = fn;
    s->vguard_user = user;
}

static int vid_is_null(const uint8_t vid[16]) {
    for (int i = 0; i < 16; i++) if (vid[i]) return 0;
    return 1;
}

static void vid_hex(const uint8_t vid[16], char out[33]) {
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out[2*i] = H[vid[i] >> 4];
        out[2*i + 1] = H[vid[i] & 15];
    }
    out[32] = '\0';
}

void store_vid_format(const uint8_t vid[16], char out[33]) {
    if (vid_is_null(vid)) snprintf(out, 33, "null");
    else vid_hex(vid, out);
}

int store_vid_parse(s3_str_t s, uint8_t vid[16]) {
    if (s3_str_eq_lit(s, "null")) { memset(vid, 0, 16); return 0; }
    if (s.n != 32) return -1;
    for (size_t i = 0; i < 32; i++) {
        char c = s.p[i];
        int v = (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
        if (v < 0) return -1;
        if (i % 2 == 0) vid[i / 2] = (uint8_t)(v << 4); else vid[i / 2] |= (uint8_t)v;
    }
    return vid_is_null(vid) ? -1 : 0;    /* zeros only via "null" */
}

static int random_vid(uint8_t vid[16]) {
    char hx[33];
    if (random_hex_id(hx, sizeof(hx)) < 0) return -1;
    s3_str_t h = { hx, 32 };
    for (size_t i = 0; i < 32; i++) {
        char c = hx[i];
        if (c >= 'A' && c <= 'F') hx[i] = (char)(c + 32);
    }
    if (store_vid_parse(h, vid) < 0) { memset(vid, 0, 16); vid[15] = 1; }
    return 0;
}

static int vdir_path(const s3_store_t *s, s3_str_t bucket, const char hex[65],
                     char *out, size_t cap) {
    int n = snprintf(out, cap, "%s/" S3_STR_FMT "/%c%c/%c%c/%s", s->versions_dir,
                     S3_STR_ARG(bucket), hex[0], hex[1], hex[2], hex[3], hex);
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

/* "<inv_ts 16 hex>-<vid 32 hex>" */
static void ventry_name(uint64_t mtime_ms, const uint8_t vid[16], char out[50]) {
    char vh[33];
    vid_hex(vid, vh);
    snprintf(out, 50, "%016" PRIx64 "-%s", UINT64_MAX - mtime_ms, vh);
}

static int ventry_parse(const char *name, uint8_t vid[16]) {
    if (strlen(name) != 49 || name[16] != '-') return -1;
    s3_str_t h = { name + 17, 32 };
    if (s3_str_eq_lit(h, "00000000000000000000000000000000")) { memset(vid, 0, 16); return 0; }
    return store_vid_parse(h, vid);
}

typedef struct { char name[50]; } vname_t;

static int vname_cmp(const void *a, const void *b) {
    return strcmp(((const vname_t *)a)->name, ((const vname_t *)b)->name);
}

/* Layout 2 (round 2, item 9): data/<b>/xx/yy/<hex> may be a relative
 * symlink to the current version, ../../../../versions/<b>/xx/yy/<hex>/<entry>.
 * Anything else in the data tree that is not a regular file is refused:
 * the share is untrusted and a planted symlink must never redirect reads.
 * Returns 0 regular file (real = path), 1 valid layout-2 link (real =
 * the version file), -1 absent, -2 invalid. */
static int resolve_current(const char *path, char *real, size_t cap, char entry[50]) {
    struct stat st;
    if (lstat(path, &st) < 0) return -1;
    if (S_ISREG(st.st_mode)) {
        if (snprintf(real, cap, "%s", path) >= (int)cap) return -2;
        if (entry) entry[0] = '\0';
        return 0;
    }
    if (!S_ISLNK(st.st_mode)) return -2;
    char tgt[1024];
    ssize_t n = readlink(path, tgt, sizeof(tgt) - 1);
    if (n <= 0) return -2;
    tgt[n] = '\0';
    /* Last four components of path: <b>/<xx>/<yy>/<hex>. */
    const char *p = path + strlen(path);
    int slashes = 0;
    while (p > path && slashes < 5) { p--; if (*p == '/') slashes++; }
    if (slashes != 5) return -2;
    const char *tail = p + 1 + strlen("data/");             /* "<b>/<xx>/<yy>/<hex>" */
    if (strncmp(p + 1, "data/", 5)) return -2;
    char want[1024];
    int wn = snprintf(want, sizeof(want), "../../../../versions/%s/", tail);
    if (wn <= 0 || (size_t)wn >= sizeof(want) || strncmp(tgt, want, (size_t)wn)) return -2;
    const char *ent = tgt + wn;
    uint8_t vid[16];
    if (strchr(ent, '/') || ventry_parse(ent, vid) < 0) return -2;
    if (snprintf(real, cap, "%.*s/versions/%s/%s", (int)(p - path), path, tail, ent) >= (int)cap)
        return -2;
    if (entry) snprintf(entry, 50, "%s", ent);
    return 1;
}

/* Open the current object file (layout 1 or 2) without following any
 * other symlink. -1 with errno set when absent or invalid. */
static int open_cur(const char *path) {
    char real[4600];
    int r = resolve_current(path, real, sizeof(real), NULL);
    if (r == -1) { errno = ENOENT; return -1; }
    if (r < 0) { errno = ELOOP; return -1; }
    return open(real, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
}

/* Sorted (newest first) entry names of a version dir — the noncurrent
 * versions: in layout 2 the entry the data symlink points at is the
 * current version and is left out, so both layouts read the same. */
static vname_t *vdir_list(const char *vdir, size_t *n_out) {
    *n_out = 0;
    char cur_entry[50] = "";
    {
        /* data path: <root>/data/<b>/xx/yy/<hex> from <root>/versions/<b>/xx/yy/<hex> */
        const char *p = vdir + strlen(vdir);
        int slashes = 0;
        while (p > vdir && slashes < 5) { p--; if (*p == '/') slashes++; }
        if (slashes == 5 && !strncmp(p + 1, "versions/", 9)) {
            char dp[4600], real[4600];
            snprintf(dp, sizeof(dp), "%.*s/data/%s", (int)(p - vdir), vdir, p + 10);
            if (resolve_current(dp, real, sizeof(real), cur_entry) != 1) cur_entry[0] = '\0';
        }
    }
    DIR *d = opendir(vdir);
    if (!d) return NULL;
    vname_t *v = NULL;
    size_t n = 0, cap = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        uint8_t vid[16];
        if (ventry_parse(e->d_name, vid) < 0) continue;
        if (cur_entry[0] && !strcmp(e->d_name, cur_entry)) continue;   /* layout 2: current */
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 8;
            vname_t *nv = realloc(v, nc * sizeof(*nv));
            if (!nv) break;
            v = nv; cap = nc;
        }
        snprintf(v[n++].name, sizeof(v[0].name), "%.49s", e->d_name);  /* 49: ventry_parse */
    }
    closedir(d);
    if (n) qsort(v, n, sizeof(*v), vname_cmp);
    *n_out = n;
    return v;
}

static int bucket_versioning(s3_store_t *s, s3_str_t bucket) {
    s3_bucket_meta_t m;
    if (store_bucket_meta(s, bucket, &m) != S3_OK) return 0;
    return m.versioning;
}

/* Header of the file at path (0 ok). */
static int peek_meta(const char *path, s3_obj_meta_t *m) {
    int fd = open_cur(path);
    if (fd < 0) return -1;
    s3_err_t e = read_header(fd, NULL, m);
    close(fd);
    return e == S3_OK ? 0 : -1;
}

static int bucket_layout(s3_store_t *s, s3_str_t bucket) {
    s3_bucket_meta_t m;
    return store_bucket_meta(s, bucket, &m) == S3_OK ? m.layout : 0;
}

void store_set_version_unlink_hook(s3_store_t *s, int (*fn)(void *, const char *), void *user) {
    s->vunlink_hook = fn;
    s->vunlink_user = user;
}

/* Unlink one version file, asking the hook first. */
static s3_err_t unlink_version_file(s3_store_t *s, const char *vp) {
    if (s->vunlink_hook && s->vunlink_hook(s->vunlink_user, vp) != 0) return S3_ERR_LOCKED;
    if (unlink(vp) < 0 && errno != ENOENT) return map_io_err(errno);
    return S3_OK;
}

/* Layout 2: point data/<hex> at versions/.../<hex>/<entry> (NULL: no
 * current version — remove the link). New link made in tmp/ and renamed
 * over the old one, so readers see the old or the new current, never
 * none. Caller holds the key's stripe lock. */
static s3_err_t l2_point(s3_store_t *s, s3_str_t bucket, const char hex[65], const char *entry) {
    char path[4096], dir[4096];
    if (obj_path(s, bucket, hex, path, sizeof(path)) < 0
        || obj_dir(s, bucket, hex, dir, sizeof(dir)) < 0) return S3_ERR_INTERNAL;
    if (!entry) {
        if (unlink(path) < 0 && errno != ENOENT) return map_io_err(errno);
        fsync_dir(dir);
        return S3_OK;
    }
    if (mkdir_p(dir, 0700) < 0) return map_io_err(errno);
    char target[1200], lnk[4300], rid[33];
    snprintf(target, sizeof(target), "../../../../versions/" S3_STR_FMT "/%c%c/%c%c/%s/%s",
             S3_STR_ARG(bucket), hex[0], hex[1], hex[2], hex[3], hex, entry);
    if (random_hex_id(rid, sizeof(rid)) < 0) return S3_ERR_INTERNAL;
    snprintf(lnk, sizeof(lnk), "%s/lnk.%s", s->tmp_dir, rid);
    if (symlink(target, lnk) < 0) return map_io_err(errno);
    if (rename(lnk, path) < 0) { s3_err_t e = map_io_err(errno); unlink(lnk); return e; }
    fsync_dir(dir);
    return S3_OK;
}

/* Layout 2: tmp file → versions/.../<hex>/<inv_ts>-<vid>, then make it
 * current. Caller holds the stripe lock (and ns_mu for the bucket check). */
static s3_err_t l2_publish(s3_store_t *s, s3_str_t bucket, const char hex[65],
                           const char *tmp_file, uint64_t mtime_ms, const uint8_t vid[16]) {
    char vdir[4300], name[50], vp[4400];
    if (vdir_path(s, bucket, hex, vdir, sizeof(vdir)) < 0) return S3_ERR_INTERNAL;
    if (mkdir_p(vdir, 0700) < 0) return map_io_err(errno);
    ventry_name(mtime_ms, vid, name);
    snprintf(vp, sizeof(vp), "%s/%s", vdir, name);
    if (rename(tmp_file, vp) < 0) return map_io_err(errno);
    fsync_dir(vdir);
    return l2_point(s, bucket, hex, name);
}

/* Before replacing the current object of a versioned bucket: move the
 * current version aside (hard link) unless it is the null version in a
 * Suspended bucket (overwritten in place). In Suspended mode any older
 * noncurrent null version is dropped: there is only ever one null
 * version. Caller holds the key's stripe lock. */
static s3_err_t link_aside_locked(s3_store_t *s, s3_str_t bucket,
                                  const char hex[65], const char *path,
                                  int versioning) {
    if (versioning == S3_VERSIONING_UNSET) return S3_OK;
    char vdir[4300];
    if (vdir_path(s, bucket, hex, vdir, sizeof(vdir)) < 0) return S3_ERR_INTERNAL;
    if (versioning == S3_VERSIONING_SUSPENDED) {
        size_t n;
        vname_t *v = vdir_list(vdir, &n);
        for (size_t i = 0; i < n; i++) {
            if (!strcmp(v[i].name + 17, "00000000000000000000000000000000")) {
                char vp[4400];
                snprintf(vp, sizeof(vp), "%s/%s", vdir, v[i].name);
                unlink(vp);
            }
        }
        free(v);
    }
    s3_obj_meta_t cur;
    if (peek_meta(path, &cur) < 0) return S3_OK;          /* no current */
    if (versioning == S3_VERSIONING_SUSPENDED && vid_is_null(cur.version_id))
        return S3_OK;
    if (mkdir_p(vdir, 0700) < 0) return map_io_err(errno);
    char name[50], vp[4400];
    ventry_name(cur.mtime_ms, cur.version_id, name);
    snprintf(vp, sizeof(vp), "%s/%s", vdir, name);
    if (link(path, vp) < 0 && errno != EEXIST) return map_io_err(errno);
    fsync_dir(vdir);
    return S3_OK;
}

/* Startup: a crash between link-aside and the rename of the new current
 * leaves a version entry that is the same inode as current. Drop those. */
static void recover_version_links(const s3_store_t *s) {
    DIR *b = opendir(s->versions_dir);
    if (!b) return;
    int removed = 0;
    struct dirent *be;
    while ((be = readdir(b)) != NULL) {
        if (be->d_name[0] == '.') continue;
        char p1[4500];
        snprintf(p1, sizeof(p1), "%s/%s", s->versions_dir, be->d_name);
        DIR *d1 = opendir(p1);
        if (!d1) continue;
        struct dirent *e1;
        while ((e1 = readdir(d1)) != NULL) {
            if (e1->d_name[0] == '.') continue;
            char p2[4800];
            snprintf(p2, sizeof(p2), "%s/%s", p1, e1->d_name);
            DIR *d2 = opendir(p2);
            if (!d2) continue;
            struct dirent *e2;
            while ((e2 = readdir(d2)) != NULL) {
                if (e2->d_name[0] == '.') continue;
                char p3[5100];
                snprintf(p3, sizeof(p3), "%s/%s", p2, e2->d_name);
                DIR *dh = opendir(p3);
                if (!dh) continue;
                struct dirent *eh;
                while ((eh = readdir(dh)) != NULL) {
                    if (eh->d_name[0] == '.') continue;
                    char vdir[5400], cur[5400];
                    snprintf(vdir, sizeof(vdir), "%s/%s", p3, eh->d_name);
                    snprintf(cur, sizeof(cur), "%s/%s/%s/%s/%s", s->data_dir, be->d_name,
                             e1->d_name, e2->d_name, eh->d_name);
                    struct stat cst;
                    /* Layout 2: the current file is a symlink into the
                     * version dir — not a link-aside leftover. */
                    if (lstat(cur, &cst) < 0 || !S_ISREG(cst.st_mode)) continue;
                    DIR *d3 = opendir(vdir);
                    if (!d3) continue;
                    struct dirent *e3;
                    while ((e3 = readdir(d3)) != NULL) {
                        if (e3->d_name[0] == '.') continue;
                        char vp[5700];
                        snprintf(vp, sizeof(vp), "%s/%s", vdir, e3->d_name);
                        struct stat vst;
                        if (stat(vp, &vst) == 0 && vst.st_ino == cst.st_ino
                            && vst.st_dev == cst.st_dev && unlink(vp) == 0)
                            removed++;
                    }
                    closedir(d3);
                }
                closedir(dh);
            }
            closedir(d2);
        }
        closedir(d1);
    }
    closedir(b);
    if (removed) LOG_I("recovery: removed %d duplicate version link(s)", removed);
}

s3_err_t store_get_open_version(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                                const uint8_t *vid,
                                s3_reader_t **out, s3_obj_meta_t *meta_out) {
    if (!s || !out) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!valid_key(key))            return S3_ERR_INVALID_ARGUMENT;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;
    s3_obj_meta_t mtmp;
    if (!meta_out) meta_out = &mtmp;
    memset(meta_out, 0, sizeof(*meta_out));

    char hex[65], path[4096];
    hash_bucket_key(bucket, key, hex);
    if (obj_path(s, bucket, hex, path, sizeof(path)) < 0) return S3_ERR_INTERNAL;

    int fd = open_cur(path);
    obj_header_t h;
    if (fd >= 0) {
        s3_err_t e = read_header(fd, &h, meta_out);
        if (e != S3_OK) { close(fd); return e; }
        if (vid && memcmp(meta_out->version_id, vid, 16) != 0) {
            close(fd);
            fd = -1;
        }
    } else if (errno != ENOENT) {
        return S3_ERR_INTERNAL;
    }
    if (fd < 0 && vid) {
        /* Look for the version among the noncurrent ones. */
        char vdir[4300];
        if (vdir_path(s, bucket, hex, vdir, sizeof(vdir)) < 0) return S3_ERR_INTERNAL;
        size_t n;
        vname_t *v = vdir_list(vdir, &n);
        char want[33];
        vid_hex(vid, want);
        for (size_t i = 0; i < n && fd < 0; i++) {
            if (strcmp(v[i].name + 17, want) != 0) continue;
            char vp[4400];
            snprintf(vp, sizeof(vp), "%s/%s", vdir, v[i].name);
            fd = open(vp, O_RDONLY | O_CLOEXEC);
        }
        free(v);
        if (fd < 0) { memset(meta_out, 0, sizeof(*meta_out)); return S3_ERR_NO_SUCH_VERSION; }
        s3_err_t e = read_header(fd, &h, meta_out);
        if (e != S3_OK) { close(fd); return e; }
    }
    if (fd < 0) return S3_ERR_NO_SUCH_KEY;
    if (meta_out->flags & S3_OBJF_DELETE_MARKER) {
        close(fd);
        return vid ? S3_ERR_METHOD_NOT_ALLOWED : S3_ERR_NO_SUCH_KEY;
    }

    if (fd_is_known_corrupt(fd, h.mtime_ms)) {
        /* --scrub-fail-reads: never serve bytes the scrub found bad. */
        close(fd);
        return S3_ERR_INTERNAL;
    }
    s3_reader_t *r = calloc(1, sizeof(*r));
    if (!r) { close(fd); return S3_ERR_INTERNAL; }
    r->fd        = fd;
    r->data_off  = h.header_size;
    r->data_size = h.data_size;
    r->pos       = 0;
    r->tlv_off   = meta_out->tlv_off;
    r->tlv_len   = meta_out->tlv_len;
    *out = r;
    return S3_OK;
}

s3_err_t store_reader_tlv(const s3_reader_t *r, uint8_t **out, size_t *n_out) {
    *out = NULL;
    *n_out = 0;
    if (!r || !r->tlv_len) return S3_OK;
    uint8_t *b = malloc(r->tlv_len);
    if (!b) return S3_ERR_INTERNAL;
    if (pread(r->fd, b, r->tlv_len, r->tlv_off) != (ssize_t)r->tlv_len
        || tlv_validate(b, r->tlv_len) < 0) {       /* re-validate: untrusted */
        free(b);
        return S3_ERR_INTERNAL;
    }
    *out = b;
    *n_out = r->tlv_len;
    return S3_OK;
}

/* Write a delete marker (zero-length v3 object) into a tmp file. */
static s3_err_t make_marker_tmp(s3_store_t *s, s3_str_t key, const uint8_t vid[16],
                                char *tmp_path, size_t cap) {
    int fd = tmp_open(s, tmp_path, cap);
    if (fd < 0) return map_io_err(errno);
    obj_header_t h;
    obj_ext_v3_t x;
    obj_ext_v4_t x4;
    memset(&h, 0, sizeof(h));
    memset(&x, 0, sizeof(x));
    memset(&x4, 0, sizeof(x4));
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    h.mtime_ms = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
    static const uint8_t empty_md5[16] = { 0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,
                                           0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e };
    memcpy(h.etag, empty_md5, 16);
    memcpy(x.version_id, vid, 16);
    x.flags = S3_OBJF_DELETE_MARKER;
    if (obj_write_prefix(s, fd, &h, &x, &x4, NULL, 0, key.p, key.n, NULL, 0) < 0
        || xfsync(fd) < 0) {
        s3_err_t e = map_io_err(errno);
        close(fd); unlink(tmp_path);
        return e;
    }
    close(fd);
    return S3_OK;
}

static s3_err_t guard_check(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                            const s3_obj_meta_t *m) {
    int bypass = g_guard_bypass;
    if (!s->vguard || (m->flags & S3_OBJF_DELETE_MARKER)) return S3_OK;
    return s->vguard(s->vguard_user, bucket, key, m, bypass);
}

/* Delete (versioning-aware) with the key lock held. expect_mtime != 0:
 * lifecycle — only if the current object still has that mtime. */
static s3_err_t delete_locked_raw(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                                  const char hex[65], const uint8_t *vid,
                                  uint64_t expect_mtime, store_delete_result_t *res);

/* Quota: charge the key's usage change around every delete. */
static s3_err_t delete_locked(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                              const char hex[65], const uint8_t *vid,
                              uint64_t expect_mtime, store_delete_result_t *res) {
    uint64_t b0 = 0, o0 = 0, b1 = 0, o1 = 0;
    key_usage(s, bucket, hex, &b0, &o0);
    s3_err_t e = delete_locked_raw(s, bucket, key, hex, vid, expect_mtime, res);
    key_usage(s, bucket, hex, &b1, &o1);
    char bn[64];
    snprintf(bn, sizeof(bn), S3_STR_FMT, S3_STR_ARG(bucket));
    q_charge(s, bn, (int64_t)b1 - (int64_t)b0, (int64_t)o1 - (int64_t)o0);
    return e;
}

static s3_err_t delete_locked_raw(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                                  const char hex[65], const uint8_t *vid,
                                  uint64_t expect_mtime, store_delete_result_t *res) {
    char path[4096], dir[4096], vdir[4300];
    if (obj_path(s, bucket, hex, path, sizeof(path)) < 0
        || obj_dir(s, bucket, hex, dir, sizeof(dir)) < 0
        || vdir_path(s, bucket, hex, vdir, sizeof(vdir)) < 0)
        return S3_ERR_INTERNAL;
    int versioning = bucket_versioning(s, bucket);
    res->versioned = versioning != S3_VERSIONING_UNSET;
    s3_obj_meta_t cur;
    int have_cur = peek_meta(path, &cur) == 0;
    if (expect_mtime && (!have_cur || cur.mtime_ms != expect_mtime))
        return have_cur ? S3_ERR_INVALID_REQUEST : S3_ERR_NO_SUCH_KEY;

    if (!vid) {
        if (versioning == S3_VERSIONING_UNSET) {
            if (unlink(path) < 0)
                return errno == ENOENT ? S3_OK : map_io_err(errno);
            fsync_dir(dir);
            return S3_OK;
        }
        uint8_t nv[16] = {0};
        if (versioning == S3_VERSIONING_ENABLED && random_vid(nv) < 0)
            return S3_ERR_INTERNAL;
        char tmp[4096];
        s3_err_t e = make_marker_tmp(s, key, nv, tmp, sizeof(tmp));
        if (e != S3_OK) return e;
        int layout = bucket_layout(s, bucket);
        s3_obj_meta_t mm;
        if (layout == 2 && peek_meta(tmp, &mm) < 0) e = S3_ERR_INTERNAL;
        pthread_mutex_lock(&s->ns_mu);
        if (!store_bucket_exists(s, bucket)) e = S3_ERR_NO_SUCH_BUCKET;
        if (e == S3_OK && layout == 2) {
            e = l2_publish(s, bucket, hex, tmp, mm.mtime_ms, nv);
        } else {
            if (e == S3_OK) e = link_aside_locked(s, bucket, hex, path, versioning);
            if (e == S3_OK && (mkdir_p(dir, 0700) < 0 || rename(tmp, path) < 0))
                e = map_io_err(errno);
        }
        pthread_mutex_unlock(&s->ns_mu);
        if (e != S3_OK) { unlink(tmp); return e; }
        fsync_dir(dir);
        res->delete_marker = 1;
        store_vid_format(nv, res->version_id);
        return S3_OK;
    }

    /* Permanent removal of one version. */
    store_vid_format(vid, res->version_id);
    if (have_cur && memcmp(cur.version_id, vid, 16) == 0) {
        s3_err_t g = guard_check(s, bucket, key, &cur);
        if (g != S3_OK) return g;
        res->delete_marker = (cur.flags & S3_OBJF_DELETE_MARKER) != 0;
        size_t n;
        vname_t *v = vdir_list(vdir, &n);
        char real[4600];
        if (resolve_current(path, real, sizeof(real), NULL) == 1) {
            /* Layout 2: remove the version file, then re-point the link
             * at the newest remaining version (or drop it). */
            s3_err_t e2 = unlink_version_file(s, real);
            if (e2 == S3_OK) e2 = l2_point(s, bucket, hex, n ? v[0].name : NULL);
            fsync_dir(vdir);
            free(v);
            return e2;
        }
        int rc;
        if (n) {
            char vp[4400];
            snprintf(vp, sizeof(vp), "%s/%s", vdir, v[0].name);
            rc = rename(vp, path);                 /* promote the newest */
            fsync_dir(vdir);
        } else {
            rc = unlink(path);
        }
        free(v);
        if (rc < 0) return map_io_err(errno);
        fsync_dir(dir);
        return S3_OK;
    }
    size_t n;
    vname_t *v = vdir_list(vdir, &n);
    char want[33];
    vid_hex(vid, want);
    s3_err_t e = S3_OK;
    int found = 0;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(v[i].name + 17, want) != 0) continue;
        char vp[4400];
        snprintf(vp, sizeof(vp), "%s/%s", vdir, v[i].name);
        s3_obj_meta_t m;
        if (peek_meta(vp, &m) < 0) { e = S3_ERR_INTERNAL; break; }
        e = guard_check(s, bucket, key, &m);
        if (e != S3_OK) break;
        res->delete_marker = (m.flags & S3_OBJF_DELETE_MARKER) != 0;
        e = unlink_version_file(s, vp);
        fsync_dir(vdir);
        found = 1;
        break;
    }
    free(v);
    /* S3: deleting a version id that does not exist succeeds. */
    (void)found;
    return e;
}

s3_err_t store_delete_ex(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                         const uint8_t *vid, store_delete_result_t *res) {
    store_delete_result_t tmp;
    if (!res) res = &tmp;
    memset(res, 0, sizeof(*res));
    int bypass = g_guard_bypass;
    g_guard_bypass = 0;
    if (!s) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!valid_key(key))            return S3_ERR_INVALID_ARGUMENT;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;
    char hex[65];
    hash_bucket_key(bucket, key, hex);
    pthread_mutex_t *km = key_lock(s, hex);
    pthread_mutex_lock(km);
    g_guard_bypass = bypass;
    s3_err_t e = delete_locked(s, bucket, key, hex, vid, 0, res);
    g_guard_bypass = 0;
    pthread_mutex_unlock(km);
    return e;
}

s3_err_t store_list_noncurrent(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                               s3_noncurrent_t **out, size_t *n_out) {
    *out = NULL;
    *n_out = 0;
    char hex[65], vdir[4300], path[4096];
    hash_bucket_key(bucket, key, hex);
    if (vdir_path(s, bucket, hex, vdir, sizeof(vdir)) < 0
        || obj_path(s, bucket, hex, path, sizeof(path)) < 0) return S3_ERR_INTERNAL;
    size_t n;
    vname_t *v = vdir_list(vdir, &n);
    if (!n) { free(v); return S3_OK; }
    s3_noncurrent_t *r = calloc(n, sizeof(*r));
    if (!r) { free(v); return S3_ERR_INTERNAL; }
    s3_obj_meta_t cur;
    uint64_t newer = peek_meta(path, &cur) == 0 ? cur.mtime_ms : 0;
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        char vp[4400];
        snprintf(vp, sizeof(vp), "%s/%s", vdir, v[i].name);
        if (peek_meta(vp, &r[k].meta) < 0) continue;
        memcpy(r[k].vid, r[k].meta.version_id, 16);
        r[k].noncurrent_since_ms = newer ? newer : r[k].meta.mtime_ms;
        newer = r[k].meta.mtime_ms;
        k++;
    }
    free(v);
    *out = r;
    *n_out = k;
    return S3_OK;
}

/* ---- ListObjectVersions ----------------------------------------------- */

typedef struct { char *key; size_t kn; char hex[65]; } vkey_t;

static int vkey_cmp(const void *a, const void *b) {
    const vkey_t *x = a, *y = b;
    size_t n = x->kn < y->kn ? x->kn : y->kn;
    int r = memcmp(x->key, y->key, n);
    return r ? r : (x->kn < y->kn ? -1 : x->kn > y->kn);
}

typedef struct { vkey_t *v; size_t n, cap; s3_str_t prefix; } vkcollect_t;

static int vk_add(vkcollect_t *c, const char *key, size_t kn) {
    if (c->prefix.n && (kn < c->prefix.n || memcmp(key, c->prefix.p, c->prefix.n)))
        return 0;
    if (c->n == c->cap) {
        size_t nc = c->cap ? c->cap * 2 : 64;
        vkey_t *nv = realloc(c->v, nc * sizeof(*nv));
        if (!nv) return -1;
        c->v = nv; c->cap = nc;
    }
    char *k = malloc(kn + 1);
    if (!k) return -1;
    memcpy(k, key, kn);
    k[kn] = '\0';
    c->v[c->n++] = (vkey_t){ k, kn, "" };
    return 0;
}

static int vk_walk_cb(void *u, s3_str_t key, const s3_obj_meta_t *m) {
    (void)m;
    return vk_add(u, key.p, key.n) < 0;
}

s3_err_t store_list_versions(s3_store_t *s, s3_str_t bucket,
                             const s3_version_list_opts_t *o,
                             s3_version_info_t **out, size_t *n_out,
                             int *truncated, char **next_key,
                             char next_vid[33]) {
    *out = NULL; *n_out = 0; *truncated = 0; *next_key = NULL; next_vid[0] = '\0';
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;
    int max = o->max_keys > 0 && o->max_keys <= 1000 ? o->max_keys : 1000;

    /* Keys: every current object (markers included) plus keys that only
     * have noncurrent versions (read from their newest version file). */
    vkcollect_t kc = { .prefix = o->prefix };
    store_walk_objects(s, bucket, vk_walk_cb, &kc);
    char vb[4200];
    snprintf(vb, sizeof(vb), "%s/" S3_STR_FMT, s->versions_dir, S3_STR_ARG(bucket));
    DIR *d1 = opendir(vb);
    if (d1) {
        struct dirent *e1;
        while ((e1 = readdir(d1)) != NULL) {
            if (e1->d_name[0] == '.') continue;
            char p1[4500];
            snprintf(p1, sizeof(p1), "%s/%s", vb, e1->d_name);
            DIR *d2 = opendir(p1);
            if (!d2) continue;
            struct dirent *e2;
            while ((e2 = readdir(d2)) != NULL) {
                if (e2->d_name[0] == '.') continue;
                char p2[4800];
                snprintf(p2, sizeof(p2), "%s/%s", p1, e2->d_name);
                DIR *d3 = opendir(p2);
                if (!d3) continue;
                struct dirent *e3;
                while ((e3 = readdir(d3)) != NULL) {
                    if (e3->d_name[0] == '.') continue;
                    char cur[5100];
                    snprintf(cur, sizeof(cur), "%s/" S3_STR_FMT "/%s/%s/%s", s->data_dir,
                             S3_STR_ARG(bucket), e1->d_name, e2->d_name, e3->d_name);
                    struct stat st;
                    if (stat(cur, &st) == 0) continue;     /* already listed */
                    char vdir[5100];
                    snprintf(vdir, sizeof(vdir), "%s/%s", p2, e3->d_name);
                    size_t nv;
                    vname_t *vn = vdir_list(vdir, &nv);
                    if (nv) {
                        char vp[5400];
                        snprintf(vp, sizeof(vp), "%s/%s", vdir, vn[0].name);
                        list_entry_t ent;
                        if (load_entry(vp, &ent) == 0) {
                            vk_add(&kc, ent.key, ent.key_len);
                            free(ent.key);
                        }
                    }
                    free(vn);
                }
                closedir(d3);
            }
            closedir(d2);
        }
        closedir(d1);
    }
    if (kc.n) qsort(kc.v, kc.n, sizeof(*kc.v), vkey_cmp);

    s3_version_info_t *res = NULL;
    size_t rn = 0, rcap = 0;
    int emitted = 0;
    char *last_prefix = NULL;
    for (size_t i = 0; i < kc.n && !*truncated; i++) {
        s3_str_t key = { kc.v[i].key, kc.v[i].kn };
        /* key-marker: keys after it (or, with version-id-marker, the rest
         * of that key's versions after the marker). */
        int cmpm = 0;
        if (o->key_marker.n) {
            size_t n = key.n < o->key_marker.n ? key.n : o->key_marker.n;
            cmpm = memcmp(key.p, o->key_marker.p, n);
            if (!cmpm) cmpm = key.n < o->key_marker.n ? -1 : key.n > o->key_marker.n;
            if (cmpm < 0 || (cmpm == 0 && !o->version_id_marker.n)) continue;
        }
        if (o->delimiter.n) {
            const char *after = key.p + o->prefix.n;
            size_t an = key.n - o->prefix.n;
            const char *dl = memmem(after, an, o->delimiter.p, o->delimiter.n);
            if (dl) {
                size_t pn = (size_t)(dl - key.p) + o->delimiter.n;
                if (last_prefix && strlen(last_prefix) == pn && !memcmp(last_prefix, key.p, pn))
                    continue;
                if (emitted >= max) { *truncated = 1; break; }
                if (rn == rcap) {
                    rcap = rcap ? rcap * 2 : 32;
                    s3_version_info_t *nr = realloc(res, rcap * sizeof(*nr));
                    if (!nr) break;
                    res = nr;
                }
                memset(&res[rn], 0, sizeof(res[rn]));
                res[rn].prefix = strndup(key.p, pn);
                free(last_prefix);
                last_prefix = strndup(key.p, pn);
                rn++;
                emitted++;
                continue;
            }
        }
        /* Versions of this key: current, then noncurrent newest first. */
        char hex[65], path[4096], vdir[4300];
        hash_bucket_key(bucket, key, hex);
        obj_path(s, bucket, hex, path, sizeof(path));
        vdir_path(s, bucket, hex, vdir, sizeof(vdir));
        size_t nv;
        vname_t *vn = vdir_list(vdir, &nv);
        int skipping = cmpm == 0 && o->version_id_marker.n;
        for (size_t j = 0; j <= nv; j++) {
            s3_obj_meta_t m;
            int latest = 0;
            if (j == 0) {
                if (peek_meta(path, &m) < 0) continue;
                latest = 1;
            } else {
                char vp[4400];
                snprintf(vp, sizeof(vp), "%s/%s", vdir, vn[j-1].name);
                if (peek_meta(vp, &m) < 0) continue;
            }
            char vs[33];
            store_vid_format(m.version_id, vs);
            if (skipping) {
                if (o->version_id_marker.n == strlen(vs)
                    && !memcmp(o->version_id_marker.p, vs, strlen(vs)))
                    skipping = 0;
                continue;
            }
            if (emitted >= max) {
                *truncated = 1;
                break;
            }
            if (rn == rcap) {
                rcap = rcap ? rcap * 2 : 32;
                s3_version_info_t *nr = realloc(res, rcap * sizeof(*nr));
                if (!nr) break;
                res = nr;
            }
            memset(&res[rn], 0, sizeof(res[rn]));
            res[rn].key = strndup(key.p, key.n);
            memcpy(res[rn].version_id, vs, sizeof(vs));
            res[rn].is_latest = latest;
            res[rn].meta = m;
            rn++;
            emitted++;
        }
        free(vn);
    }
    if (*truncated && rn) {
        s3_version_info_t *l = &res[rn - 1];
        *next_key = strdup(l->key ? l->key : l->prefix);
        if (l->key) memcpy(next_vid, l->version_id, 33);
    }
    free(last_prefix);
    for (size_t i = 0; i < kc.n; i++) free(kc.v[i].key);
    free(kc.v);
    *out = res;
    *n_out = rn;
    return S3_OK;
}

void store_versions_free(s3_version_info_t *v, size_t n) {
    for (size_t i = 0; i < n; i++) { free(v[i].key); free(v[i].prefix); }
    free(v);
}

/* ===================================================================== */
/* Object lock sidecars (item 10)                                         */
/* ===================================================================== */

static int lock_path(const s3_store_t *s, s3_str_t bucket, s3_str_t key,
                     const uint8_t vid[16], char *dir, size_t dcap,
                     char *path, size_t pcap) {
    char hex[65], vh[33];
    hash_bucket_key(bucket, key, hex);
    vid_hex(vid, vh);
    int n = snprintf(dir, dcap, "%s/" S3_STR_FMT "/%c%c/%c%c/%s", s->locks_dir,
                     S3_STR_ARG(bucket), hex[0], hex[1], hex[2], hex[3], hex);
    if (n <= 0 || (size_t)n >= dcap) return -1;
    n = snprintf(path, pcap, "%s/%s", dir, vh);
    return (n > 0 && (size_t)n < pcap) ? 0 : -1;
}

/* 0 ok, 1 absent, -1 unreadable/unparseable. */
static int lock_parse_file(const char *path, s3_lock_t *out) {
    memset(out, 0, sizeof(*out));
    FILE *f = fopen(path, "re");
    if (!f) return errno == ENOENT ? 1 : -1;
    char line[128];
    int ok = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (!strcmp(line, "mode=GOVERNANCE")) out->mode = S3_LOCK_GOVERNANCE;
        else if (!strcmp(line, "mode=COMPLIANCE")) out->mode = S3_LOCK_COMPLIANCE;
        else if (!strcmp(line, "mode=NONE")) out->mode = S3_LOCK_NONE;
        else if (!strncmp(line, "until_ms=", 9)) out->until_ms = strtoull(line + 9, NULL, 10);
        else if (!strcmp(line, "legal_hold=1")) out->legal_hold = 1;
        else if (!strcmp(line, "legal_hold=0")) out->legal_hold = 0;
        else if (!strcmp(line, "v=1")) ok = 1;
    }
    fclose(f);
    return ok ? 0 : -1;
}

int store_lock_read(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                    const uint8_t vid[16], s3_lock_t *out) {
    memset(out, 0, sizeof(*out));
    char dir[4300], path[4400];
    if (!valid_bucket_name(bucket) || !valid_key(key)
        || lock_path(s, bucket, key, vid, dir, sizeof(dir), path, sizeof(path)) < 0)
        return -1;
    return lock_parse_file(path, out);
}

s3_err_t store_lock_write(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                          const uint8_t vid[16], const s3_lock_t *l) {
    char dir[4300], path[4400], tmp[4500];
    if (!valid_bucket_name(bucket) || !valid_key(key)
        || lock_path(s, bucket, key, vid, dir, sizeof(dir), path, sizeof(path)) < 0)
        return S3_ERR_INVALID_ARGUMENT;
    if (mkdir_p(dir, 0700) < 0) return map_io_err(errno);
    snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
    int fd = mkstemp(tmp);
    if (fd < 0) return map_io_err(errno);
    char buf[160];
    int n = snprintf(buf, sizeof(buf), "v=1\nmode=%s\nuntil_ms=%" PRIu64 "\nlegal_hold=%d\n",
                     l->mode == S3_LOCK_COMPLIANCE ? "COMPLIANCE"
                     : l->mode == S3_LOCK_GOVERNANCE ? "GOVERNANCE" : "NONE",
                     l->until_ms, l->legal_hold ? 1 : 0);
    if (xwrite(fd, buf, (size_t)n) != n || xfsync(fd) < 0) {
        s3_err_t e = map_io_err(errno);
        close(fd); unlink(tmp);
        return e;
    }
    close(fd);
    if (rename(tmp, path) < 0) { s3_err_t e = map_io_err(errno); unlink(tmp); return e; }
    fsync_dir(dir);
    return S3_OK;
}

void store_get_raw(const s3_reader_t *r, int *fd, off_t *off, uint64_t *remaining) {
    *fd = r->fd;
    *off = (off_t)(r->data_off + r->pos);
    *remaining = r->pos < r->data_size ? r->data_size - r->pos : 0;
}

void store_get_rewind(s3_reader_t *r, uint64_t n) {
    r->pos = n > r->pos ? 0 : r->pos - n;
}

void store_get_advance(s3_reader_t *r, uint64_t n) {
    r->pos += n;
    if (r->pos > r->data_size) r->pos = r->data_size;
}

static s3_err_t mpu_read_meta2(const s3_store_t *s, s3_str_t bucket,
                               const char *upload_id,
                               char **out_key, size_t *out_key_n, char **out_ct,
                               uint8_t *out_algo, uint8_t *out_type,
                               uint8_t **out_tlv, size_t *out_tlv_n) {
    *out_tlv = NULL;
    *out_tlv_n = 0;
    s3_err_t e = mpu_read_meta(s, bucket, upload_id, out_key, out_key_n, out_ct,
                               out_algo, out_type);
    if (e != S3_OK) return e;
    char dir[4096], meta[4200];
    if (mpu_dir_path(s, bucket, upload_id, dir, sizeof(dir)) < 0) return S3_ERR_INTERNAL;
    snprintf(meta, sizeof(meta), "%s/meta", dir);
    FILE *fp = fopen(meta, "re");
    if (!fp) return S3_OK;
    char *line = NULL;
    size_t cap = 0;
    ssize_t r;
    while ((r = getline(&line, &cap, fp)) > 0) {
        if (strncmp(line, "tlv=", 4)) continue;
        size_t hn = (size_t)r - 4;
        while (hn && (line[4 + hn - 1] == '\n' || line[4 + hn - 1] == '\r')) hn--;
        if (hn % 2 || hn / 2 > OBJ_MAX_TLV) break;
        uint8_t *t = malloc(hn / 2 + 1);
        if (!t) break;
        size_t i;
        for (i = 0; i < hn / 2; i++) {
            int hi = hexval1(line[4 + 2*i]), lo = hexval1(line[5 + 2*i]);
            if (hi < 0 || lo < 0) break;
            t[i] = (uint8_t)(hi << 4 | lo);
        }
        if (i == hn / 2 && tlv_validate(t, hn / 2) == 0) { *out_tlv = t; *out_tlv_n = hn / 2; }
        else free(t);
        break;
    }
    free(line);
    fclose(fp);
    return S3_OK;
}

void store_set_mpu_min_part_size(s3_store_t *s, uint64_t n) { if (s) s->mpu_min_part = n; }

/* ===================================================================== */
/* Quotas (round 2, item 2)                                               */
/* ===================================================================== */
/*
 * Logical bytes and object count per bucket (current objects, noncurrent
 * versions and delete markers; in-flight parts count bytes), charged to
 * the bucket and so to its owner. Every key mutation measures the key's
 * usage before and after under its stripe lock (key_usage) and charges
 * the difference, so overwrite, link-aside, promotion and Suspended-mode
 * null-version replacement all come out exact without special cases.
 * Writers reserve before bytes reach disk; writer_free releases whatever
 * a writer still holds, so no abort path can leak a reservation.
 */

struct q_bucket {
    char     name[64];
    char     owner[129];
    uint64_t bytes, objects;       /* committed */
    uint64_t rbytes, robjs;        /* reserved by open writers */
    int      has_cfg;              /* bucket quota sidecar present */
    uint64_t max_bytes, max_objects;
    uint64_t gen;                  /* bumped on every charge (recount race check) */
};

struct q_user {
    char     user[129];
    uint64_t max_bytes, max_objects;
};

static struct q_bucket *qb_find(s3_store_t *s, const char *name) {
    for (size_t i = 0; i < s->qb_n; i++)
        if (!strcmp(s->qb[i].name, name)) return &s->qb[i];
    return NULL;
}

static struct q_bucket *qb_get(s3_store_t *s, const char *name) {
    struct q_bucket *b = qb_find(s, name);
    if (b) return b;
    if (s->qb_n == s->qb_cap) {
        size_t nc = s->qb_cap ? s->qb_cap * 2 : 16;
        struct q_bucket *nb = realloc(s->qb, nc * sizeof(*nb));
        if (!nb) return NULL;
        s->qb = nb; s->qb_cap = nc;
    }
    b = &s->qb[s->qb_n++];
    memset(b, 0, sizeof(*b));
    snprintf(b->name, sizeof(b->name), "%s", name);
    return b;
}

static struct q_user *qu_find(s3_store_t *s, const char *user) {
    for (size_t i = 0; i < s->qu_n; i++)
        if (!strcmp(s->qu[i].user, user)) return &s->qu[i];
    return NULL;
}

static void qb_limits(const s3_store_t *s, const struct q_bucket *b,
                      uint64_t *mb, uint64_t *mo) {
    if (b->has_cfg) { *mb = b->max_bytes; *mo = b->max_objects; }
    else            { *mb = s->q_def_bucket; *mo = 0; }
}

static void qu_limits(s3_store_t *s, const char *user, uint64_t *mb, uint64_t *mo) {
    struct q_user *u = qu_find(s, user);
    if (u) { *mb = u->max_bytes; *mo = u->max_objects; }
    else   { *mb = s->q_def_user; *mo = 0; }
}

static int over(uint64_t used, uint64_t add, uint64_t max) {
    return max && (used > max || add > max - used);
}

static s3_err_t q_reserve(s3_store_t *s, const char *bucket, uint64_t bytes, uint32_t objs) {
    pthread_mutex_lock(&s->q_mu);
    struct q_bucket *b = qb_find(s, bucket);
    s3_err_t e = S3_OK;
    if (b) {
        uint64_t mb, mo;
        qb_limits(s, b, &mb, &mo);
        if (over(b->bytes + b->rbytes, bytes, mb)
            || (objs && over(b->objects + b->robjs, objs, mo)))
            e = S3_ERR_QUOTA_EXCEEDED;
        if (e == S3_OK && b->owner[0]) {
            qu_limits(s, b->owner, &mb, &mo);
            if (mb || mo) {
                uint64_t ub = 0, uo = 0;
                for (size_t i = 0; i < s->qb_n; i++) {
                    if (strcmp(s->qb[i].owner, b->owner)) continue;
                    ub += s->qb[i].bytes + s->qb[i].rbytes;
                    uo += s->qb[i].objects + s->qb[i].robjs;
                }
                if (over(ub, bytes, mb) || (objs && over(uo, objs, mo)))
                    e = S3_ERR_QUOTA_EXCEEDED;
            }
        }
        if (e == S3_OK) { b->rbytes += bytes; b->robjs += objs; }
        else s->q_rejections++;
    }
    pthread_mutex_unlock(&s->q_mu);
    return e;
}

static void q_release(s3_store_t *s, const char *bucket, uint64_t bytes, uint32_t objs) {
    pthread_mutex_lock(&s->q_mu);
    struct q_bucket *b = qb_find(s, bucket);
    if (b) {
        b->rbytes = b->rbytes > bytes ? b->rbytes - bytes : 0;
        b->robjs  = b->robjs > objs ? b->robjs - objs : 0;
    }
    pthread_mutex_unlock(&s->q_mu);
}

static void add_signed(uint64_t *v, int64_t d) {
    if (d >= 0) *v += (uint64_t)d;
    else *v = *v > (uint64_t)(-d) ? *v - (uint64_t)(-d) : 0;
}

static void q_charge(s3_store_t *s, const char *bucket, int64_t db, int64_t dobj) {
    if (!db && !dobj) return;
    pthread_mutex_lock(&s->q_mu);
    struct q_bucket *b = qb_find(s, bucket);
    if (b) { add_signed(&b->bytes, db); add_signed(&b->objects, dobj); b->gen++; }
    pthread_mutex_unlock(&s->q_mu);
}

static void q_bucket_added(s3_store_t *s, s3_str_t name, const char *owner) {
    char bn[64];
    snprintf(bn, sizeof(bn), S3_STR_FMT, S3_STR_ARG(name));
    pthread_mutex_lock(&s->q_mu);
    struct q_bucket *b = qb_get(s, bn);
    if (b) snprintf(b->owner, sizeof(b->owner), "%s", owner ? owner : "");
    pthread_mutex_unlock(&s->q_mu);
}

static void q_bucket_removed(s3_store_t *s, s3_str_t name) {
    char bn[64];
    snprintf(bn, sizeof(bn), S3_STR_FMT, S3_STR_ARG(name));
    pthread_mutex_lock(&s->q_mu);
    struct q_bucket *b = qb_find(s, bn);
    if (b) *b = s->qb[--s->qb_n];
    pthread_mutex_unlock(&s->q_mu);
}

/* Logical usage of one key: the current object plus every version
 * entry, counting an entry that is the current file's inode (the
 * link-aside window) once. Caller holds the key's stripe lock. */
static void key_usage(s3_store_t *s, s3_str_t bucket, const char hex[65],
                      uint64_t *bytes, uint64_t *objs) {
    *bytes = 0; *objs = 0;
    char path[4096], vdir[4300];
    if (obj_path(s, bucket, hex, path, sizeof(path)) < 0
        || vdir_path(s, bucket, hex, vdir, sizeof(vdir)) < 0) return;
    struct stat cst;
    char real[4600];
    int have = resolve_current(path, real, sizeof(real), NULL) >= 0 && stat(real, &cst) == 0;
    s3_obj_meta_t m;
    if (have) {
        (*objs)++;
        if (peek_meta(path, &m) == 0) *bytes += m.size;
    }
    size_t n;
    vname_t *v = vdir_list(vdir, &n);
    for (size_t i = 0; i < n; i++) {
        char vp[4400];
        snprintf(vp, sizeof(vp), "%s/%s", vdir, v[i].name);
        struct stat vst;
        if (stat(vp, &vst) < 0) continue;
        if (have && vst.st_ino == cst.st_ino && vst.st_dev == cst.st_dev) continue;
        (*objs)++;
        if (peek_meta(vp, &m) == 0) *bytes += m.size;
    }
    free(v);
}

/* Bytes of the part files in an upload dir. */
static uint64_t upload_part_bytes(const char *up_dir) {
    DIR *d = opendir(up_dir);
    if (!d) return 0;
    uint64_t sum = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strlen(e->d_name) != 10 || strncmp(e->d_name, "part-", 5)) continue;
        char p[4400];
        snprintf(p, sizeof(p), "%s/%s", up_dir, e->d_name);
        struct stat st;
        if (stat(p, &st) == 0 && S_ISREG(st.st_mode)) sum += (uint64_t)st.st_size;
    }
    closedir(d);
    return sum;
}

/* Walk depth levels of subdirectories under dir and call fn on each
 * regular file at the bottom. */
static void walk_leaves(const char *dir, int depth,
                        void (*fn)(const char *path, const char *name, void *ctx), void *ctx) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.') continue;
        char p[4400];
        if (snprintf(p, sizeof(p), "%s/%s", dir, e->d_name) >= (int)sizeof(p)) continue;
        if (depth > 0) walk_leaves(p, depth - 1, fn, ctx);
        else fn(p, e->d_name, ctx);
    }
    closedir(d);
}

typedef struct { uint64_t bytes, objs; } q_acc_t;

static void acc_object(const char *path, const char *name, void *ctx) {
    q_acc_t *a = ctx;
    struct stat lst;
    if (strlen(name) != 64 || lstat(path, &lst) < 0 || !S_ISREG(lst.st_mode)) return;
    s3_obj_meta_t m;
    a->objs++;
    if (peek_meta(path, &m) == 0) a->bytes += m.size;
}

static void acc_version(const char *path, const char *name, void *ctx) {
    q_acc_t *a = ctx;
    uint8_t vid[16];
    if (ventry_parse(name, vid) < 0) return;
    s3_obj_meta_t m;
    a->objs++;
    if (peek_meta(path, &m) == 0) a->bytes += m.size;
}

static void acc_part(const char *path, const char *name, void *ctx) {
    q_acc_t *a = ctx;
    if (strlen(name) != 10 || strncmp(name, "part-", 5)) return;
    struct stat st;
    if (stat(path, &st) == 0) a->bytes += (uint64_t)st.st_size;
}

/* Exact usage of a bucket from disk (startup rebuild; scrub). */
static void q_walk_bucket(s3_store_t *s, const char *name, uint64_t *bytes, uint64_t *objs) {
    q_acc_t a = { 0, 0 };
    char p[4200];
    snprintf(p, sizeof(p), "%s/%s", s->data_dir, name);
    walk_leaves(p, 2, acc_object, &a);              /* data/<b>/NN/NN/<hex> */
    snprintf(p, sizeof(p), "%s/%s", s->versions_dir, name);
    walk_leaves(p, 3, acc_version, &a);             /* versions/<b>/NN/NN/<hex>/<entry> */
    snprintf(p, sizeof(p), "%s/%s", s->mpu_dir, name);
    walk_leaves(p, 1, acc_part, &a);                /* mpu/<b>/<upload>/part-NNNNN */
    *bytes = a.bytes;
    *objs = a.objs;
}

static int parse_kv_u64(const char *text, const char *key, uint64_t *out) {
    size_t kn = strlen(key);
    for (const char *l = text; l && *l; ) {
        if (!strncmp(l, key, kn) && l[kn] == '=') {
            char *end;
            errno = 0;
            unsigned long long v = strtoull(l + kn + 1, &end, 10);
            if (errno || end == l + kn + 1 || (*end && *end != '\n')) return -1;
            *out = v;
            return 0;
        }
        l = strchr(l, '\n');
        if (l) l++;
    }
    return 1;
}

static void hex_name(const char *in, char *out, size_t cap) {
    static const char H[] = "0123456789abcdef";
    size_t k = 0;
    for (; *in && k + 3 < cap; in++) {
        out[k++] = H[(unsigned char)*in >> 4];
        out[k++] = H[(unsigned char)*in & 15];
    }
    out[k] = '\0';
}

/* Atomic small-file write: tmp + fsync + rename + fsync(dir). */
static s3_err_t write_file_atomic(const char *dir, const char *final,
                                  const char *data, size_t n) {
    char tmp[4700];
    snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", final);
    int fd = mkstemp(tmp);
    if (fd < 0) return map_io_err(errno);
    if ((n && xwrite(fd, data, n) != (ssize_t)n) || xfsync(fd) < 0) {
        s3_err_t e = map_io_err(errno);
        close(fd); unlink(tmp);
        return e;
    }
    close(fd);
    if (rename(tmp, final) < 0) { s3_err_t e = map_io_err(errno); unlink(tmp); return e; }
    fsync_dir(dir);
    return S3_OK;
}

static void q_load_users(s3_store_t *s) {
    char ud[4200];
    snprintf(ud, sizeof(ud), "%s/users", s->root);
    DIR *d = opendir(ud);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t nl = strlen(e->d_name);
        if (nl < 7 || strcmp(e->d_name + nl - 6, ".quota") || (nl - 6) % 2 || nl - 6 > 256)
            continue;
        char user[129];
        size_t un = (nl - 6) / 2, i;
        for (i = 0; i < un; i++) {
            int hi = hexval1(e->d_name[2*i]), lo = hexval1(e->d_name[2*i+1]);
            if (hi < 0 || lo < 0) break;
            user[i] = (char)(hi << 4 | lo);
        }
        if (i != un) continue;
        user[un] = '\0';
        if (!store_valid_identity(user)) continue;
        char p[4400], buf[256];
        snprintf(p, sizeof(p), "%s/%s", ud, e->d_name);
        int fd = open(p, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        ssize_t r = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (r <= 0) continue;
        buf[r] = '\0';
        uint64_t mb = 0, mo = 0;
        if (parse_kv_u64(buf, "max_bytes", &mb) < 0 || parse_kv_u64(buf, "max_objects", &mo) < 0)
            continue;
        if (s->qu_n == s->qu_cap) {
            size_t nc = s->qu_cap ? s->qu_cap * 2 : 8;
            struct q_user *nu = realloc(s->qu, nc * sizeof(*nu));
            if (!nu) break;
            s->qu = nu; s->qu_cap = nc;
        }
        struct q_user *u = &s->qu[s->qu_n++];
        snprintf(u->user, sizeof(u->user), "%s", user);
        u->max_bytes = mb; u->max_objects = mo;
    }
    closedir(d);
}

static void q_load_bucket_cfg(s3_store_t *s, struct q_bucket *b) {
    char *t = NULL; size_t n = 0;
    s3_str_t bn = { b->name, strlen(b->name) };
    b->has_cfg = 0;
    if (store_bucket_sidecar_read(s, bn, "quota", 256, &t, &n) != S3_OK) return;
    uint64_t mb = 0, mo = 0;
    if (parse_kv_u64(t, "max_bytes", &mb) >= 0 && parse_kv_u64(t, "max_objects", &mo) >= 0) {
        b->has_cfg = 1; b->max_bytes = mb; b->max_objects = mo;
    }
    free(t);
}

/* Startup: buckets, limits and usage. Usage files written at clean
 * shutdown are trusted only if the running marker is absent (the last
 * run closed the store); otherwise every bucket is walked. */
static void q_load(s3_store_t *s) {
    char marker[4200];
    snprintf(marker, sizeof(marker), "%s/.fs3-running", s->root);
    int clean = access(marker, F_OK) != 0;
    s3_bucket_info_t *list = NULL;
    size_t n = 0;
    if (store_list_buckets(s, &list, &n) != S3_OK) { list = NULL; n = 0; }
    int walked = 0;
    for (size_t i = 0; i < n; i++) {
        s3_str_t bn = { list[i].name, strlen(list[i].name) };
        s3_bucket_meta_t bm;
        if (store_bucket_meta(s, bn, &bm) != S3_OK) continue;
        struct q_bucket *b = qb_get(s, list[i].name);
        if (!b) break;
        snprintf(b->owner, sizeof(b->owner), "%s", bm.owner);
        q_load_bucket_cfg(s, b);
        int ok = 0;
        char *t = NULL; size_t tn = 0;
        if (clean && store_bucket_sidecar_read(s, bn, "usage", 256, &t, &tn) == S3_OK) {
            const char *idl = strstr(t, "id=");
            uint64_t ub = 0, uo = 0;
            if (idl && !strncmp(idl + 3, bm.id, strlen(bm.id)) && idl[3 + strlen(bm.id)] == '\n'
                && parse_kv_u64(t, "bytes", &ub) == 0 && parse_kv_u64(t, "objects", &uo) == 0) {
                b->bytes = ub; b->objects = uo; ok = 1;
            }
        }
        free(t);
        if (!ok) { q_walk_bucket(s, b->name, &b->bytes, &b->objects); walked++; }
    }
    if (list) store_buckets_free(list, n);
    q_load_users(s);
    if (walked) LOG_I("quota: rebuilt usage of %d bucket(s) from disk%s", walked,
                      clean ? "" : " (unclean shutdown)");
    int fd = open(marker, O_WRONLY | O_CREAT | O_CLOEXEC, 0600);
    if (fd >= 0) { xfsync(fd); close(fd); fsync_dir(s->root); }
    s->q_ready = 1;
}

/* Clean shutdown: persist usage, then drop the running marker. */
static void q_save(s3_store_t *s) {
    if (!s->q_ready) return;
    int ok = 1;
    for (size_t i = 0; i < s->qb_n; i++) {
        struct q_bucket *b = &s->qb[i];
        s3_str_t bn = { b->name, strlen(b->name) };
        s3_bucket_meta_t bm;
        if (store_bucket_meta(s, bn, &bm) != S3_OK) continue;
        char buf[256];
        int len = snprintf(buf, sizeof(buf), "id=%s\nbytes=%" PRIu64 "\nobjects=%" PRIu64 "\n",
                           bm.id, b->bytes, b->objects);
        if (store_bucket_sidecar_write(s, bn, "usage", buf, (size_t)len) != S3_OK) ok = 0;
    }
    char marker[4200];
    snprintf(marker, sizeof(marker), "%s/.fs3-running", s->root);
    if (ok) { unlink(marker); fsync_dir(s->root); }
}

/* ---- public API ---- */

int store_valid_identity(const char *u) {
    size_t n = u ? strlen(u) : 0;
    if (n == 0 || n > 128) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)u[i];
        if (ch <= ' ' || ch >= 0x7f || ch == ':') return 0;
    }
    return 1;
}

void store_set_default_quotas(s3_store_t *s, uint64_t bucket_bytes, uint64_t user_bytes) {
    pthread_mutex_lock(&s->q_mu);
    s->q_def_bucket = bucket_bytes;
    s->q_def_user = user_bytes;
    pthread_mutex_unlock(&s->q_mu);
}

uint64_t store_quota_rejections(s3_store_t *s) {
    pthread_mutex_lock(&s->q_mu);
    uint64_t v = s->q_rejections;
    pthread_mutex_unlock(&s->q_mu);
    return v;
}

s3_err_t store_bucket_quota_set(s3_store_t *s, s3_str_t bucket,
                                uint64_t max_bytes, uint64_t max_objects) {
    if (!s || !valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "max_bytes=%" PRIu64 "\nmax_objects=%" PRIu64 "\n",
                     max_bytes, max_objects);
    s3_err_t e = store_bucket_sidecar_write(s, bucket, "quota", buf, (size_t)n);
    if (e != S3_OK) return e;
    char bn[64];
    snprintf(bn, sizeof(bn), S3_STR_FMT, S3_STR_ARG(bucket));
    pthread_mutex_lock(&s->q_mu);
    struct q_bucket *b = qb_find(s, bn);
    if (b) { b->has_cfg = 1; b->max_bytes = max_bytes; b->max_objects = max_objects; }
    pthread_mutex_unlock(&s->q_mu);
    return S3_OK;
}

s3_err_t store_bucket_quota_clear(s3_store_t *s, s3_str_t bucket) {
    if (!s || !valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    s3_err_t e = store_bucket_sidecar_delete(s, bucket, "quota");
    if (e != S3_OK && e != S3_ERR_NO_SUCH_KEY) return e;
    char bn[64];
    snprintf(bn, sizeof(bn), S3_STR_FMT, S3_STR_ARG(bucket));
    pthread_mutex_lock(&s->q_mu);
    struct q_bucket *b = qb_find(s, bn);
    if (b) b->has_cfg = 0;
    pthread_mutex_unlock(&s->q_mu);
    return S3_OK;
}

s3_err_t store_bucket_usage(s3_store_t *s, s3_str_t bucket, s3_quota_usage_t *out) {
    if (!s || !out) return S3_ERR_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    char bn[64];
    snprintf(bn, sizeof(bn), S3_STR_FMT, S3_STR_ARG(bucket));
    pthread_mutex_lock(&s->q_mu);
    struct q_bucket *b = qb_find(s, bn);
    if (b) {
        out->bytes = b->bytes; out->objects = b->objects;
        out->reserved = b->rbytes;
        out->has_cfg = b->has_cfg;
        qb_limits(s, b, &out->max_bytes, &out->max_objects);
        snprintf(out->owner, sizeof(out->owner), "%s", b->owner);
    }
    pthread_mutex_unlock(&s->q_mu);
    return b ? S3_OK : S3_ERR_NO_SUCH_BUCKET;
}

static s3_err_t user_quota_path(const s3_store_t *s, const char *user,
                                char *dir, size_t dcap, char *path, size_t pcap) {
    if (!store_valid_identity(user)) return S3_ERR_INVALID_ARGUMENT;
    char hx[260];
    hex_name(user, hx, sizeof(hx));          /* never a path from the raw name */
    snprintf(dir, dcap, "%s/users", s->root);
    if (snprintf(path, pcap, "%s/%s.quota", dir, hx) >= (int)pcap) return S3_ERR_INTERNAL;
    return S3_OK;
}

s3_err_t store_user_quota_set(s3_store_t *s, const char *user,
                              uint64_t max_bytes, uint64_t max_objects) {
    char dir[4200], path[4600];
    s3_err_t e = user_quota_path(s, user, dir, sizeof(dir), path, sizeof(path));
    if (e != S3_OK) return e;
    if (mkdir_p(dir, 0700) < 0) return map_io_err(errno);
    char buf[128];
    int n = snprintf(buf, sizeof(buf), "max_bytes=%" PRIu64 "\nmax_objects=%" PRIu64 "\n",
                     max_bytes, max_objects);
    e = write_file_atomic(dir, path, buf, (size_t)n);
    if (e != S3_OK) return e;
    pthread_mutex_lock(&s->q_mu);
    struct q_user *u = qu_find(s, user);
    if (!u && s->qu_n == s->qu_cap) {
        size_t nc = s->qu_cap ? s->qu_cap * 2 : 8;
        struct q_user *nu = realloc(s->qu, nc * sizeof(*nu));
        if (nu) { s->qu = nu; s->qu_cap = nc; }
    }
    if (!u && s->qu_n < s->qu_cap) {
        u = &s->qu[s->qu_n++];
        snprintf(u->user, sizeof(u->user), "%s", user);
    }
    if (u) { u->max_bytes = max_bytes; u->max_objects = max_objects; }
    pthread_mutex_unlock(&s->q_mu);
    return u ? S3_OK : S3_ERR_INTERNAL;
}

s3_err_t store_user_quota_clear(s3_store_t *s, const char *user) {
    char dir[4200], path[4600];
    s3_err_t e = user_quota_path(s, user, dir, sizeof(dir), path, sizeof(path));
    if (e != S3_OK) return e;
    if (unlink(path) < 0 && errno != ENOENT) return map_io_err(errno);
    fsync_dir(dir);
    pthread_mutex_lock(&s->q_mu);
    struct q_user *u = qu_find(s, user);
    if (u) *u = s->qu[--s->qu_n];
    pthread_mutex_unlock(&s->q_mu);
    return S3_OK;
}

s3_err_t store_user_usage(s3_store_t *s, const char *user, s3_quota_usage_t *out) {
    if (!s || !out || !store_valid_identity(user)) return S3_ERR_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    pthread_mutex_lock(&s->q_mu);
    for (size_t i = 0; i < s->qb_n; i++) {
        if (strcmp(s->qb[i].owner, user)) continue;
        out->bytes += s->qb[i].bytes;
        out->objects += s->qb[i].objects;
        out->reserved += s->qb[i].rbytes;
    }
    out->has_cfg = qu_find(s, user) != NULL;
    qu_limits(s, user, &out->max_bytes, &out->max_objects);
    snprintf(out->owner, sizeof(out->owner), "%s", user);
    pthread_mutex_unlock(&s->q_mu);
    return S3_OK;
}

s3_err_t store_quota_recount(s3_store_t *s, s3_str_t bucket, int64_t *drift_bytes) {
    if (!s || !valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (drift_bytes) *drift_bytes = 0;
    char bn[64];
    snprintf(bn, sizeof(bn), S3_STR_FMT, S3_STR_ARG(bucket));
    pthread_mutex_lock(&s->q_mu);
    struct q_bucket *qb = qb_find(s, bn);
    uint64_t gen0 = qb ? qb->gen : 0;
    pthread_mutex_unlock(&s->q_mu);
    if (!qb) return S3_ERR_NO_SUCH_BUCKET;
    uint64_t b = 0, o = 0;
    q_walk_bucket(s, bn, &b, &o);
    s3_err_t e = S3_OK;
    pthread_mutex_lock(&s->q_mu);
    qb = qb_find(s, bn);
    if (!qb) e = S3_ERR_NO_SUCH_BUCKET;
    else if (qb->gen != gen0) e = S3_ERR_SLOW_DOWN;     /* written meanwhile: walk is stale */
    else {
        if (drift_bytes) *drift_bytes = (int64_t)qb->bytes - (int64_t)b;
        qb->bytes = b; qb->objects = o;
    }
    pthread_mutex_unlock(&s->q_mu);
    return e;
}

/* ===================================================================== */
/* Integrity scrub support (round 2, item 3)                              */
/* ===================================================================== */

/* Known-corrupt versions (--scrub-fail-reads): identified by inode and
 * header mtime, so the mark follows a version through link-aside and a
 * reused inode number does not inherit it. */
typedef struct { uint64_t dev, ino, mtime_ms; } corrupt_id_t;
static pthread_mutex_t g_corrupt_mu = PTHREAD_MUTEX_INITIALIZER;
static corrupt_id_t   *g_corrupt;
static size_t          g_corrupt_n, g_corrupt_cap;
static int             g_corrupt_fail_reads;

void store_scrub_fail_reads(int on) { g_corrupt_fail_reads = on; }

void store_scrub_mark_corrupt(uint64_t dev, uint64_t ino, uint64_t mtime_ms) {
    pthread_mutex_lock(&g_corrupt_mu);
    for (size_t i = 0; i < g_corrupt_n; i++)
        if (g_corrupt[i].dev == dev && g_corrupt[i].ino == ino && g_corrupt[i].mtime_ms == mtime_ms) {
            pthread_mutex_unlock(&g_corrupt_mu);
            return;
        }
    if (g_corrupt_n == g_corrupt_cap) {
        size_t nc = g_corrupt_cap ? g_corrupt_cap * 2 : 16;
        corrupt_id_t *n = realloc(g_corrupt, nc * sizeof(*n));
        if (!n) { pthread_mutex_unlock(&g_corrupt_mu); return; }
        g_corrupt = n; g_corrupt_cap = nc;
    }
    g_corrupt[g_corrupt_n++] = (corrupt_id_t){ dev, ino, mtime_ms };
    pthread_mutex_unlock(&g_corrupt_mu);
}

static int fd_is_known_corrupt(int fd, uint64_t mtime_ms) {
    if (!g_corrupt_fail_reads || !g_corrupt_n) return 0;
    struct stat st;
    if (fstat(fd, &st) < 0) return 0;
    int hit = 0;
    pthread_mutex_lock(&g_corrupt_mu);
    for (size_t i = 0; i < g_corrupt_n && !hit; i++)
        hit = g_corrupt[i].dev == (uint64_t)st.st_dev && g_corrupt[i].ino == (uint64_t)st.st_ino
           && g_corrupt[i].mtime_ms == mtime_ms;
    pthread_mutex_unlock(&g_corrupt_mu);
    return hit;
}

const char *store_root(const s3_store_t *s) { return s->root; }

/* Read [off, off+len) of fd through the hashes, calling throttle(ctx, n)
 * after each chunk. -1 on read error or short file. */
static int scrub_read(int fd, uint64_t off, uint64_t len, EVP_MD_CTX *md, cksum_ctx_t *k1,
                      cksum_ctx_t *k2, void (*throttle)(void *, uint64_t), void *tctx,
                      uint64_t *read_total) {
    char buf[128 * 1024];
    while (len) {
        size_t want = len < sizeof(buf) ? (size_t)len : sizeof(buf);
        ssize_t r = pread(fd, buf, want, (off_t)off);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return -1;
        if (md) EVP_DigestUpdate(md, buf, (size_t)r);
        if (k1 && k1->algo) cksum_update(k1, buf, (size_t)r);
        if (k2 && k2->algo) cksum_update(k2, buf, (size_t)r);
        off += (uint64_t)r; len -= (uint64_t)r;
        *read_total += (uint64_t)r;
        if (throttle) throttle(tctx, (uint64_t)r);
    }
    return 0;
}

static void hex16(const uint8_t *b, size_t n, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = H[b[i] >> 4]; out[2*i+1] = H[b[i] & 15]; }
    out[2*n] = '\0';
}

static void scrub_object_fd(int fd, const struct stat *st, store_scrub_result_t *r,
                            void (*throttle)(void *, uint64_t), void *tctx) {
    obj_header_t h;
    obj_ext_v3_t x;
    obj_ext_v4_t x4;
    uint32_t ct_off = 0, tlv_off = 0;
    if (obj_read_hdr4(fd, &h, &x, &x4, &ct_off, &tlv_off) != S3_OK) {
        r->verdict = SCRUB_CORRUPT;
        snprintf(r->reason, sizeof(r->reason), "bad header");
        /* Say "size" when the fixed header is intact but the file is
         * shorter/longer than it claims (truncation). */
        obj_header_t raw;
        if (pread(fd, &raw, sizeof(raw), 0) == (ssize_t)sizeof(raw)
            && !memcmp(raw.magic, OBJ_MAGIC, OBJ_MAGIC_LEN)
            && (raw.schema == OBJ_SCHEMA_V2 || raw.schema == OBJ_SCHEMA_V3)
            && (uint64_t)st->st_size != (uint64_t)raw.header_size + raw.data_size) {
            snprintf(r->reason, sizeof(r->reason), "size");
        } else if (pread(fd, &raw, sizeof(raw), 0) == (ssize_t)sizeof(raw)
                   && !memcmp(raw.magic, OBJ_MAGIC, OBJ_MAGIC_LEN) && raw.schema == OBJ_SCHEMA) {
            obj_ext_v4_t rx4;
            if (pread(fd, &rx4, sizeof(rx4), sizeof(raw) + sizeof(obj_ext_v3_t)) == (ssize_t)sizeof(rx4)
                && (uint64_t)st->st_size != (uint64_t)raw.header_size + rx4.stored_size) {
                snprintf(r->reason, sizeof(r->reason), "size");
                snprintf(r->expected, sizeof(r->expected), "%llu",
                         (unsigned long long)raw.header_size + rx4.stored_size);
                snprintf(r->actual, sizeof(r->actual), "%llu", (unsigned long long)st->st_size);
            }
        }
        return;
    }
    r->mtime_ms = h.mtime_ms;
    r->logical_size = h.data_size;
    memcpy(r->version_id, x.version_id, 16);
    if (h.key_len && h.key_len < sizeof(r->key)
        && pread(fd, r->key, h.key_len, (off_t)ct_off + h.ct_len) == (ssize_t)h.key_len)
        r->key[h.key_len] = '\0';
    uint64_t stored = h.schema == OBJ_SCHEMA ? x4.stored_size : h.data_size;
    if ((uint64_t)st->st_size != (uint64_t)h.header_size + stored) {
        r->verdict = SCRUB_CORRUPT;
        snprintf(r->reason, sizeof(r->reason), "size");
        snprintf(r->expected, sizeof(r->expected), "%llu",
                 (unsigned long long)h.header_size + stored);
        snprintf(r->actual, sizeof(r->actual), "%llu", (unsigned long long)st->st_size);
        return;
    }
    int transformed = (x.flags & (S3_OBJF_SSEC | S3_OBJF_ZSTD)) != 0;
    int use_crc = (x.flags & S3_OBJF_PAYLOAD_CRC) != 0;
    int use_md5 = !use_crc && h.part_count == 0 && !transformed
                  && !(x.flags & S3_OBJF_DELETE_MARKER);
    int use_ck  = !use_crc && !use_md5 && !transformed && x.cksum_algo
                  && x.cksum_type == S3_CKSUM_TYPE_FULL_OBJECT;
    if (x.flags & S3_OBJF_DELETE_MARKER) { r->verdict = stored ? SCRUB_CORRUPT : SCRUB_OK;
        if (stored) snprintf(r->reason, sizeof(r->reason), "delete marker with payload");
        return; }
    if (!use_crc && !use_md5 && !use_ck) { r->verdict = SCRUB_UNVERIFIABLE; return; }
    EVP_MD_CTX *md = use_md5 ? EVP_MD_CTX_new() : NULL;
    cksum_ctx_t kc, kf;
    memset(&kc, 0, sizeof(kc)); memset(&kf, 0, sizeof(kf));
    if (use_md5 && (!md || EVP_DigestInit_ex(md, EVP_md5(), NULL) != 1)) {
        EVP_MD_CTX_free(md); r->verdict = SCRUB_UNVERIFIABLE; return;
    }
    if (use_crc) cksum_begin(&kc, S3_CKSUM_CRC64NVME);
    if (use_ck)  cksum_begin(&kf, x.cksum_algo);
    if (scrub_read(fd, h.header_size, stored, md, &kc, &kf, throttle, tctx, &r->bytes_read) < 0) {
        r->verdict = SCRUB_CORRUPT;
        snprintf(r->reason, sizeof(r->reason), "short read");
    } else if (use_crc) {
        uint8_t d[CKSUM_MAX_DIGEST]; size_t dn = 0;
        cksum_final(&kc, d, &dn);
        r->verdict = (dn == 8 && !memcmp(d, x4.payload_crc64, 8)) ? SCRUB_OK : SCRUB_CORRUPT;
        snprintf(r->reason, sizeof(r->reason), "payload crc64");
        hex16(x4.payload_crc64, 8, r->expected);
        hex16(d, dn < 8 ? dn : 8, r->actual);
    } else if (use_md5) {
        uint8_t d[16]; unsigned dn = 16;
        EVP_DigestFinal_ex(md, d, &dn);
        r->verdict = !memcmp(d, h.etag, 16) ? SCRUB_OK : SCRUB_CORRUPT;
        snprintf(r->reason, sizeof(r->reason), "md5");
        hex16(h.etag, 16, r->expected);
        hex16(d, 16, r->actual);
    } else {
        uint8_t d[CKSUM_MAX_DIGEST]; size_t dn = 0;
        cksum_final(&kf, d, &dn);
        r->verdict = (dn && !memcmp(d, x.cksum, dn)) ? SCRUB_OK : SCRUB_CORRUPT;
        snprintf(r->reason, sizeof(r->reason), "checksum %s", cksum_upper_name(x.cksum_algo));
        hex16(x.cksum, dn > 16 ? 16 : dn, r->expected);
        hex16(d, dn > 16 ? 16 : dn, r->actual);
    }
    if (r->verdict == SCRUB_OK) { r->reason[0] = r->expected[0] = r->actual[0] = '\0'; }
    EVP_MD_CTX_free(md);
    cksum_free(&kc);
    cksum_free(&kf);
}

static void scrub_part_fd(int fd, const char *path, const struct stat *st,
                          store_scrub_result_t *r, void (*throttle)(void *, uint64_t), void *tctx) {
    part_rec_t rec;
    int rr = part_rec_read(path, &rec);
    r->logical_size = (uint64_t)st->st_size;
    r->mtime_ms = (uint64_t)st->st_mtim.tv_sec * 1000 + (uint64_t)st->st_mtim.tv_nsec / 1000000;
    if (rr == 1) { r->verdict = SCRUB_UNVERIFIABLE; return; }
    if (rr < 0) { r->verdict = SCRUB_CORRUPT; snprintf(r->reason, sizeof(r->reason), "bad part record"); return; }
    if ((uint64_t)st->st_size != rec.size) {
        r->verdict = SCRUB_CORRUPT;
        snprintf(r->reason, sizeof(r->reason), "size");
        snprintf(r->expected, sizeof(r->expected), "%llu", (unsigned long long)rec.size);
        snprintf(r->actual, sizeof(r->actual), "%llu", (unsigned long long)st->st_size);
        return;
    }
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    if (!md || EVP_DigestInit_ex(md, EVP_md5(), NULL) != 1) {
        EVP_MD_CTX_free(md); r->verdict = SCRUB_UNVERIFIABLE; return;
    }
    if (scrub_read(fd, 0, rec.size, md, NULL, NULL, throttle, tctx, &r->bytes_read) < 0) {
        r->verdict = SCRUB_CORRUPT;
        snprintf(r->reason, sizeof(r->reason), "short read");
    } else {
        uint8_t d[16]; unsigned dn = 16;
        EVP_DigestFinal_ex(md, d, &dn);
        r->verdict = !memcmp(d, rec.md5, 16) ? SCRUB_OK : SCRUB_CORRUPT;
        if (r->verdict != SCRUB_OK) {
            snprintf(r->reason, sizeof(r->reason), "part md5");
            hex16(rec.md5, 16, r->expected);
            hex16(d, 16, r->actual);
        }
    }
    EVP_MD_CTX_free(md);
}

s3_err_t store_scrub_file(s3_store_t *s, const char *path, int kind, const char *lock_hex,
                          void (*throttle)(void *, uint64_t), void *tctx,
                          store_scrub_result_t *r) {
    memset(r, 0, sizeof(*r));
    pthread_mutex_t *km = lock_hex ? key_lock(s, lock_hex) : NULL;
    if (km) pthread_mutex_lock(km);
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        r->verdict = SCRUB_GONE;            /* replaced or deleted: not corruption */
        if (km) pthread_mutex_unlock(km);
        return S3_OK;
    }
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        r->verdict = SCRUB_GONE;
        if (km) pthread_mutex_unlock(km);
        return S3_OK;
    }
    r->dev = (uint64_t)st.st_dev;
    r->ino = (uint64_t)st.st_ino;
    r->nlink = (uint64_t)st.st_nlink;
    if (kind == STORE_SCRUB_PART) {
        scrub_part_fd(fd, path, &st, r, throttle, tctx);
    } else if (kind == STORE_SCRUB_LOCK) {
        /* An unparseable lock record already fails closed (the version
         * cannot be deleted); report it so the admin can fix it. */
        s3_lock_t l;
        r->bytes_read = (uint64_t)st.st_size;
        r->verdict = lock_parse_file(path, &l) == 0 ? SCRUB_OK : SCRUB_CORRUPT;
        if (r->verdict != SCRUB_OK) snprintf(r->reason, sizeof(r->reason), "unparseable lock record");
    } else {
        scrub_object_fd(fd, &st, r, throttle, tctx);
    }
#ifdef POSIX_FADV_DONTNEED
    (void)posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);   /* don't evict the page cache */
#endif
    close(fd);
    if (km) pthread_mutex_unlock(km);
    return S3_OK;
}

/* Reflink copy (item 6a): clone the reader's remaining payload into the
 * writer's payload and feed the same bytes through the writer's hashes
 * (and `extra`, e.g. a part checksum) without writing them. The source
 * fd stays open, so a concurrent overwrite can't change what is cloned.
 * S3_ERR_NOT_IMPLEMENTED: not possible here — nothing was done, stream
 * the bytes instead. */
s3_err_t store_writer_clone(s3_writer_t *w, s3_reader_t *r,
                            void (*extra)(void *ctx, const void *p, size_t n), void *ctx) {
    if (!w || !r || w->finalized) return S3_ERR_INVALID_ARGUMENT;
    if (!w->store->reflink || w->ssec || r->ssec) return S3_ERR_NOT_IMPLEMENTED;
    uint64_t len = r->pos < r->data_size ? r->data_size - r->pos : 0;
    uint64_t soff = r->data_off + r->pos;
    uint64_t doff = (w->is_part ? 0 : w->hdr.header_size) + w->data_written;
    if (len == 0) return S3_OK;
    if (writer_reserve_to(w, w->data_written + len) != S3_OK) return S3_ERR_QUOTA_EXCEEDED;
    /* The writer's fd position must follow (later writes append). */
    if (clone_range(w->fd, doff, r->fd, soff, len) < 0) return S3_ERR_NOT_IMPLEMENTED;
    if (lseek(w->fd, (off_t)(doff + len), SEEK_SET) < 0) return map_io_err(errno);
    char buf[128 * 1024];
    uint64_t done = 0;
    while (done < len) {
        size_t want = len - done < sizeof(buf) ? (size_t)(len - done) : sizeof(buf);
        ssize_t n = pread(r->fd, buf, want, (off_t)(soff + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return S3_ERR_INTERNAL;
        EVP_DigestUpdate(w->md5_ctx, buf, (size_t)n);
        if (w->pcrc.algo) cksum_update(&w->pcrc, buf, (size_t)n);
        if (w->sha) EVP_DigestUpdate(w->sha, buf, (size_t)n);
        if (extra) extra(ctx, buf, (size_t)n);
        done += (uint64_t)n;
    }
    w->data_written += len;
    w->stored_written += len;          /* not transformed: plaintext == on disk */
    r->pos += len;
    return S3_OK;
}

/* ===================================================================== */
/* Whole-object dedup (round 2, item 6b)                                  */
/* ===================================================================== */
/*
 * Pool: <root>/cas/<scope>/<aa>/<bb>/<sha256>, payload-only files whose
 * extents objects share via reflink. Object files stay complete, so the
 * pool can be wiped at any time (future dedup is lost, never data) and
 * there are no refcounts to repair after a crash. Runs at commit before
 * the key stripe lock: it only touches the writer's private tmp file and
 * the pool, where a concurrent miss just renames an identical file. A hit
 * opens the pool file first, so a concurrent pool GC can't pull it away
 * mid-clone.
 */
uint64_t g_store_dedup_hits, g_store_dedup_misses;

void store_set_dedup(s3_store_t *s, int mode, uint64_t min_size, int verify) {
    s->dedup_mode = mode;
    s->dedup_min = min_size;
    s->dedup_verify = verify;
}

static int pool_path(const s3_store_t *s, const char *scope, const uint8_t dg[32],
                     char *dir, size_t dcap, char *path, size_t pcap) {
    char hx[65];
    hex16(dg, 32, hx);
    int n = snprintf(dir, dcap, "%s/cas/%s/%c%c/%c%c", s->root, scope, hx[0], hx[1], hx[2], hx[3]);
    if (n <= 0 || (size_t)n >= dcap) return -1;
    n = snprintf(path, pcap, "%s/%s", dir, hx);
    return n > 0 && (size_t)n < pcap ? 0 : -1;
}

static int same_bytes(int a, uint64_t aoff, int b, uint64_t boff, uint64_t len) {
    char x[64 * 1024], y[64 * 1024];
    while (len) {
        size_t n = len < sizeof(x) ? (size_t)len : sizeof(x);
        if (pread(a, x, n, (off_t)aoff) != (ssize_t)n || pread(b, y, n, (off_t)boff) != (ssize_t)n
            || memcmp(x, y, n)) return 0;
        aoff += n; boff += n; len -= n;
    }
    return 1;
}

static void dedup_commit(s3_writer_t *w, const uint8_t dg[32]) {
    s3_store_t *s = w->store;
    char dir[4300], path[4400];
    if (pool_path(s, w->dedup_scope, dg, dir, sizeof(dir), path, sizeof(path)) < 0) return;
    uint64_t doff = w->hdr.header_size, len = w->data_written;
    int pf = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (pf >= 0) {
        struct stat st;
        if (fstat(pf, &st) == 0 && S_ISREG(st.st_mode) && (uint64_t)st.st_size == len
            && (!s->dedup_verify || same_bytes(pf, 0, w->fd, doff, len))
            && clone_range(w->fd, doff, pf, 0, len) == 0) {
            __atomic_fetch_add(&g_store_dedup_hits, 1, __ATOMIC_RELAXED);
        }
        close(pf);
        return;
    }
    /* Miss: the payload's extents become a new pool entry (no extra space). */
    if (mkdir_p(dir, 0700) < 0) return;
    char tmp[4500];
    snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
    int tf = mkstemp(tmp);
    if (tf < 0) return;
    if (clone_range(tf, 0, w->fd, doff, len) == 0 && xfsync(tf) == 0 && rename(tmp, path) == 0) {
        __atomic_fetch_add(&g_store_dedup_misses, 1, __ATOMIC_RELAXED);
        close(tf);
        return;
    }
    close(tf);
    unlink(tmp);
}

/* Pool GC (from the scrub): remove pool entries not in `keep` (sorted
 * array of 32-byte digests) and last modified before `older_than`.
 * Returns the number removed. */
static int dg_cmp(const void *a, const void *b) { return memcmp(a, b, 32); }

int store_dedup_gc(s3_store_t *s, const uint8_t *keep, size_t n_keep, time_t older_than) {
    char cas[4200];
    snprintf(cas, sizeof(cas), "%s/cas", s->root);
    DIR *d0 = opendir(cas);
    if (!d0) return 0;
    int removed = 0;
    struct dirent *e0;
    while ((e0 = readdir(d0)) != NULL) {
        if (e0->d_name[0] == '.') continue;
        char p0[4500];
        snprintf(p0, sizeof(p0), "%s/%s", cas, e0->d_name);
        DIR *d1 = opendir(p0);
        if (!d1) continue;
        struct dirent *e1;
        while ((e1 = readdir(d1)) != NULL) {
            if (e1->d_name[0] == '.') continue;
            char p1[4800];
            snprintf(p1, sizeof(p1), "%s/%s", p0, e1->d_name);
            DIR *d2 = opendir(p1);
            if (!d2) continue;
            struct dirent *e2;
            while ((e2 = readdir(d2)) != NULL) {
                if (e2->d_name[0] == '.') continue;
                char p2[5100];
                snprintf(p2, sizeof(p2), "%s/%s", p1, e2->d_name);
                DIR *d3 = opendir(p2);
                if (!d3) continue;
                struct dirent *e3;
                while ((e3 = readdir(d3)) != NULL) {
                    const char *nm = e3->d_name;
                    if (nm[0] == '.') continue;
                    char p3[5400];
                    snprintf(p3, sizeof(p3), "%s/%s", p2, nm);
                    struct stat st;
                    if (lstat(p3, &st) < 0 || st.st_mtime >= older_than) continue;
                    uint8_t dg[32];
                    int ok = strlen(nm) == 64;
                    for (int i = 0; ok && i < 32; i++) {
                        int hi = hexval1(nm[2*i]), lo = hexval1(nm[2*i+1]);
                        if (hi < 0 || lo < 0) ok = 0; else dg[i] = (uint8_t)(hi << 4 | lo);
                    }
                    /* Leftover tmp files and unreferenced entries go. */
                    if (!ok || !keep || !bsearch(dg, keep, n_keep, 32, dg_cmp)) {
                        if (unlink(p3) == 0) removed++;
                    }
                }
                closedir(d3);
            }
            closedir(d2);
        }
        closedir(d1);
    }
    closedir(d0);
    return removed;
}

/* The CONTENT_SHA256 TLV of an object file (scrub collects referenced
 * pool digests). 1 found, 0 none. */
int store_object_content_sha256(const char *path, uint8_t out[32]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    obj_header_t h; obj_ext_v3_t x; obj_ext_v4_t x4;
    uint32_t ct_off = 0, tlv_off = 0;
    int found = 0;
    if (obj_read_hdr4(fd, &h, &x, &x4, &ct_off, &tlv_off) == S3_OK && x4.tlv_len
        && x4.tlv_len <= OBJ_MAX_TLV) {
        uint8_t *t = malloc(x4.tlv_len);
        if (t && pread(fd, t, x4.tlv_len, tlv_off) == (ssize_t)x4.tlv_len
            && tlv_validate(t, x4.tlv_len) == 0) {
            for (uint32_t o = 0; o + 6 <= x4.tlv_len; ) {
                unsigned type = (unsigned)t[o] | (unsigned)t[o+1] << 8;
                uint32_t len = (uint32_t)t[o+2] | (uint32_t)t[o+3] << 8 | (uint32_t)t[o+4] << 16
                             | (uint32_t)t[o+5] << 24;
                if (type == S3_TLV_CONTENT_SHA256 && len == 32) {
                    memcpy(out, t + o + 6, 32);
                    static const uint8_t zero[32];
                    found = memcmp(out, zero, 32) != 0;
                    break;
                }
                o += 6 + len;
            }
        }
        free(t);
    }
    close(fd);
    return found;
}

/* ===================================================================== */
/* SSE-C read side (round 2, item 8)                                      */
/* ===================================================================== */

int store_reader_transformed(const s3_reader_t *r) { return r && r->ssec; }

s3_err_t store_reader_ssec(s3_store_t *s, s3_str_t bucket, s3_reader_t *r, const uint8_t key[32]) {
    if (!s || !r || !key) return S3_ERR_INVALID_ARGUMENT;
    uint8_t *t = NULL; size_t tn = 0;
    if (store_reader_tlv(r, &t, &tn) != S3_OK) return S3_ERR_INTERNAL;
    ssec_info_t si;
    int found = ssec_tlv_find(t, tn, &si);
    if (found <= 0) { free(t); return found < 0 ? S3_ERR_INTERNAL : S3_ERR_INVALID_REQUEST; }
    if (!ssec_key_matches(key, &si)) { free(t); return S3_ERR_ACCESS_DENIED; }
    ssec_part_t *pt = NULL; size_t pn = 0;
    int ptf = ssec_parttable_find(t, tn, &pt, &pn);
    free(t);
    if (ptf < 0) return S3_ERR_INTERNAL;
    s3_bucket_meta_t bm;
    if (store_bucket_meta(s, bucket, &bm) != S3_OK || strlen(bm.id) != 32) { free(pt); return S3_ERR_INTERNAL; }
    size_t k = ptf == 1 ? pn : 1;
    r->parts = calloc(k, sizeof(*r->parts));
    r->seg = malloc(SSEC_SEG + SSEC_TAG);
    if (!r->parts || !r->seg) { free(pt); return S3_ERR_INTERNAL; }
    uint64_t poff = 0, coff = 0;
    for (size_t i = 0; i < k; i++) {
        r->parts[i].part = ptf == 1 ? pt[i].part : 0;
        r->parts[i].plain = ptf == 1 ? pt[i].plain : r->data_size;
        r->parts[i].poff = poff;
        r->parts[i].coff = coff;
        poff += r->parts[i].plain;
        coff += ssec_cipher_len(r->parts[i].plain, si.seg);
    }
    free(pt);
    struct stat st;
    /* The geometry must account for exactly the stored payload. */
    if (poff != r->data_size || fstat(r->fd, &st) < 0
        || (uint64_t)st.st_size != r->data_off + coff)
        return S3_ERR_INTERNAL;
    r->n_parts = k;
    if (ssec_derive(key, si.salt, r->kobj) < 0) return S3_ERR_INTERNAL;
    memcpy(r->bucket_id, bm.id, 33);
    r->ssec = 1;
    return S3_OK;
}

/* Decrypt (and authenticate) the segment holding plaintext offset pos. */
static int ssec_load(s3_reader_t *r, uint64_t pos, size_t *pi_out, uint64_t *in_seg) {
    size_t pi = 0;
    while (pi + 1 < r->n_parts && pos >= r->parts[pi + 1].poff) pi++;
    rd_part_t *p = &r->parts[pi];
    uint64_t rel = pos - p->poff, idx = rel / SSEC_SEG;
    uint64_t nseg = p->plain ? (p->plain + SSEC_SEG - 1) / SSEC_SEG : 1;
    *pi_out = pi;
    *in_seg = rel % SSEC_SEG;
    if (r->seg_valid && r->seg_part == pi && r->seg_idx == idx) return 0;
    size_t plen = idx + 1 < nseg ? SSEC_SEG : (size_t)(p->plain - idx * SSEC_SEG);
    uint64_t off = r->data_off + p->coff + idx * (SSEC_SEG + SSEC_TAG);
    size_t clen = plen + SSEC_TAG;
    if (pread(r->fd, r->seg, clen, (off_t)off) != (ssize_t)clen) return -1;
    r->seg_valid = 0;
    if (ssec_open(r->kobj, p->part, idx, idx + 1 == nseg, r->bucket_id, r->seg, clen, r->seg) < 0)
        return -1;                          /* tampered or truncated: never return bytes */
    r->seg_len = plen;
    r->seg_part = pi;
    r->seg_idx = idx;
    r->seg_valid = 1;
    return 0;
}

static ssize_t ssec_read(s3_reader_t *r, void *buf, size_t n) {
    size_t done = 0;
    while (done < n && r->pos < r->data_size) {
        size_t pi; uint64_t in;
        if (ssec_load(r, r->pos, &pi, &in) < 0) { errno = EIO; return done ? (ssize_t)done : -1; }
        size_t avail = r->seg_len - (size_t)in;
        uint64_t left = r->data_size - r->pos;
        size_t take = n - done < avail ? n - done : avail;
        if (take > left) take = (size_t)left;
        memcpy((uint8_t *)buf + done, r->seg + in, take);
        done += take;
        r->pos += take;
    }
    return (ssize_t)done;
}

int store_version_file(s3_store_t *s, s3_str_t bucket, s3_str_t key, const uint8_t vid[16],
                       char *out, size_t cap) {
    if (!valid_bucket_name(bucket) || !valid_key(key) || bucket_layout(s, bucket) != 2) return -1;
    char hex[65], vdir[4300], want[33];
    hash_bucket_key(bucket, key, hex);
    if (vdir_path(s, bucket, hex, vdir, sizeof(vdir)) < 0) return -1;
    vid_hex(vid, want);
    DIR *d = opendir(vdir);
    if (!d) return -1;
    int rc = -1;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        uint8_t v[16];
        if (ventry_parse(e->d_name, v) < 0 || strcmp(e->d_name + 17, want)) continue;
        rc = snprintf(out, cap, "%s/%s", vdir, e->d_name) < (int)cap ? 0 : -1;
        break;
    }
    closedir(d);
    return rc;
}
