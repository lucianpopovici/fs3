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
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wstringop-overread"
#endif

#include "store.h"
#include "checksum.h"
#include "log.h"

#include <dirent.h>
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
#define OBJ_SCHEMA   3u         /* v3 added obj_ext_v3_t (checksum, version id, flags) */

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

/* Upper bound on content-type bytes we write (s3_obj_meta_t holds 127). */
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

    int  (*mpu_gc_filter)(void *user, s3_str_t bucket, s3_str_t key);
    void  *mpu_gc_filter_user;

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
    for (int i = 0; i < 256; i++) pthread_mutex_init(&s->key_mu[i], NULL);

    s->root        = strdup(root);
    s->data_dir    = xstrdup_join(root, "data");
    s->tmp_dir     = xstrdup_join(root, "tmp");
    s->buckets_dir = xstrdup_join(root, "buckets");
    s->mpu_dir     = xstrdup_join(root, "mpu");
    if (!s->root || !s->data_dir || !s->tmp_dir || !s->buckets_dir || !s->mpu_dir) {
        store_close(s);
        return S3_ERR_INTERNAL;
    }

    if (mkdir_p(s->root, 0700) < 0
        || mkdir_p(s->data_dir, 0700) < 0
        || mkdir_p(s->tmp_dir, 0700) < 0
        || mkdir_p(s->buckets_dir, 0700) < 0
        || mkdir_p(s->mpu_dir, 0700) < 0) {
        LOG_E("store_open: mkdir failed under %s: %s", root, strerror(errno));
        store_close(s);
        return S3_ERR_INTERNAL;
    }

    recover_tmp_dir(s);
    recover_sidecar_tmp(s);

    *out = s;
    return S3_OK;
}

void store_close(s3_store_t *s) {
    if (!s) return;
    free(s->root);
    free(s->data_dir);
    free(s->tmp_dir);
    free(s->buckets_dir);
    free(s->mpu_dir);
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
static s3_err_t write_bucket_meta(const char *dir, const char *id,
                                  const char *owner) {
    char tmp[4200], final[4200];
    snprintf(tmp, sizeof(tmp), "%s/meta.tmp", dir);
    snprintf(final, sizeof(final), "%s/meta", dir);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return map_io_err(errno);
    char buf[256];
    int n = snprintf(buf, sizeof(buf), "id=%s\nowner=%s\n", id,
                     owner ? owner : "");
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
    }
    fclose(fp);
}

s3_err_t store_bucket_create(s3_store_t *s, s3_str_t name) {
    return store_bucket_create_owned(s, name, NULL);
}

/* The bucket dir and its meta are assembled under tmp/ and renamed into
 * buckets/ in one step, so a bucket never exists without its owner
 * (a crash leaves only a tmp/ dir, swept at startup). */
s3_err_t store_bucket_create_owned(s3_store_t *s, s3_str_t name,
                                   const char *owner) {
    if (!s) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(name)) return S3_ERR_INVALID_BUCKET_NAME;

    char bp[4096];
    if (bucket_path(s, name, bp, sizeof(bp)) < 0) return S3_ERR_INTERNAL;

    char stage[4096], id[33];
    snprintf(stage, sizeof(stage), "%s/bucket.XXXXXX", s->tmp_dir);
    if (random_hex_id(id, sizeof(id)) < 0) return S3_ERR_INTERNAL;
    if (!mkdtemp(stage)) return map_io_err(errno);
    s3_err_t e = write_bucket_meta(stage, id, owner);
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
        if (!m.id[0] && random_hex_id(m.id, sizeof(m.id)) < 0)
            e = S3_ERR_INTERNAL;
        else
            e = write_bucket_meta(bp, m.id, owner);
    }
    pthread_mutex_unlock(&s->ns_mu);
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
    return e;
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

struct s3_writer {
    s3_store_t *store;
    int         fd;                  /* tmp file fd */
    char        tmp_path[4096];      /* tmp file path */
    uint64_t    data_written;        /* bytes written to data region so far */
    EVP_MD_CTX *md5_ctx;             /* running MD5 */
    obj_header_t hdr;                /* accumulated header (filled in begin) */
    obj_ext_v3_t ext;                /* schema-3 extension (checksum, ...) */
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
};

static void writer_free(s3_writer_t *w) {
    if (!w) return;
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
    if (ct_n > sizeof(((s3_obj_meta_t*)0)->content_type) - 1) {
        ct_n = sizeof(((s3_obj_meta_t*)0)->content_type) - 1;
    }
    w->content_type_dup = malloc(ct_n + 1);
    if (!w->content_type_dup) { writer_free(w); return S3_ERR_INTERNAL; }
    memcpy(w->content_type_dup, ct, ct_n);
    w->content_type_dup[ct_n] = '\0';

    /* Header lengths are known now; data size + etag come at commit time. */
    if (key.n > UINT16_MAX) { writer_free(w); return S3_ERR_INVALID_ARGUMENT; }
    if (ct_n > UINT16_MAX)  { writer_free(w); return S3_ERR_INVALID_ARGUMENT; }
    memcpy(w->hdr.magic, OBJ_MAGIC, OBJ_MAGIC_LEN);
    w->hdr.schema      = OBJ_SCHEMA;
    w->hdr.header_size = (uint32_t)(sizeof(obj_header_t) + sizeof(obj_ext_v3_t)
                                    + ct_n + key.n);
    if (opts->have_cksum
        && store_put_set_checksum(w, opts->cksum_algo, opts->cksum_type,
                                  opts->cksum_parts, opts->cksum,
                                  sizeof(opts->cksum)) != S3_OK) {
        writer_free(w); return S3_ERR_INVALID_ARGUMENT;
    }
    w->hdr.ct_len      = (uint16_t)ct_n;
    w->hdr.key_len     = (uint16_t)key.n;
    /* data_size, mtime_ms, etag filled at commit */

    /* Open temp file. */
    w->fd = tmp_open(s, w->tmp_path, sizeof(w->tmp_path));
    if (w->fd < 0) {
        LOG_E("tmp_open: %s", strerror(errno));
        s3_err_t e = map_io_err(errno);
        writer_free(w);
        return e;
    }

    /* Reserve header space by writing the (incomplete) header, then the
     * variable-length content_type and key bytes. We'll pwrite the final
     * header back at offset 0 in commit. */
    if (xwrite(w->fd, &w->hdr, sizeof(w->hdr)) != (ssize_t)sizeof(w->hdr)
        || xwrite(w->fd, &w->ext, sizeof(w->ext)) != (ssize_t)sizeof(w->ext)
        || (ct_n  && xwrite(w->fd, w->content_type_dup, ct_n) != (ssize_t)ct_n)
        || (key.n && xwrite(w->fd, w->key_dup, key.n)         != (ssize_t)key.n)) {
        LOG_E("write header: %s", strerror(errno));
        s3_err_t e = map_io_err(errno);
        writer_free(w);
        return e;
    }

    *out = w;
    return S3_OK;
}

s3_err_t store_put_write(s3_writer_t *w, const void *buf, size_t n) {
    if (!w || w->finalized) return S3_ERR_INVALID_ARGUMENT;
    if (n == 0) return S3_OK;

    if (EVP_DigestUpdate(w->md5_ctx, buf, n) != 1) return S3_ERR_INTERNAL;

    const char *p = buf;
    size_t left = n;
    while (left > 0) {
        ssize_t r = xwrite(w->fd, p, left);
        if (r > 0) { p += r; left -= (size_t)r; w->data_written += (uint64_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        LOG_W("put_write: %s", strerror(errno));
        return map_io_err(errno);
    }
    return S3_OK;
}

s3_err_t store_put_commit(s3_writer_t *w, s3_obj_meta_t *meta_out) {
    if (!w || w->finalized) return S3_ERR_INVALID_ARGUMENT;
    w->finalized = 1;

    /* Finalize MD5 and timestamp. */
    unsigned int mlen = 16;
    if (EVP_DigestFinal_ex(w->md5_ctx, w->hdr.etag, &mlen) != 1) {
        writer_free(w); return S3_ERR_INTERNAL;
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    w->hdr.mtime_ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000);
    w->hdr.data_size = w->data_written;

    /* Pwrite the finalized header back at offset 0. */
    if (pwrite(w->fd, &w->hdr, sizeof(w->hdr), 0) != (ssize_t)sizeof(w->hdr)
        || pwrite(w->fd, &w->ext, sizeof(w->ext), sizeof(w->hdr))
           != (ssize_t)sizeof(w->ext)) {
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

    /* Atomic rename. Can also fail with ENOSPC (new dirent allocation). */
    if (rename(w->tmp_path, path) < 0) {
        LOG_E("rename %s -> %s: %s", w->tmp_path, path, strerror(errno));
        s3_err_t e = map_io_err(errno);
        pthread_mutex_unlock(&w->store->ns_mu);
    pthread_mutex_unlock(km);
        writer_free(w); return e;
    }
    pthread_mutex_unlock(&w->store->ns_mu);
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

struct s3_reader {
    int      fd;
    uint64_t data_off;       /* file offset where data begins */
    uint64_t data_size;      /* total data length */
    uint64_t pos;            /* bytes already returned to caller */
};

/* Read and validate an object file's header. The share holding the data
 * root may be writable by other DSM users, so every length is treated as
 * untrusted: header_size must equal exactly fixed + ext + ct + key, fit
 * inside the file, and the data region must match the file size.
 * Fills h, x (zeroes for schema 2) and *ct_off (offset of content-type
 * bytes; the key follows them). */
static s3_err_t obj_read_hdr(int fd, obj_header_t *h, obj_ext_v3_t *x,
                             uint32_t *ct_off) {
    ssize_t r = pread(fd, h, sizeof(*h), 0);
    if (r != (ssize_t)sizeof(*h)) return S3_ERR_INTERNAL;
    if (memcmp(h->magic, OBJ_MAGIC, OBJ_MAGIC_LEN) != 0) return S3_ERR_INTERNAL;
    uint32_t fixed;
    memset(x, 0, sizeof(*x));
    if (h->schema == OBJ_SCHEMA_V2) {
        fixed = (uint32_t)sizeof(*h);
    } else if (h->schema == OBJ_SCHEMA) {
        fixed = (uint32_t)(sizeof(*h) + sizeof(*x));
        if (pread(fd, x, sizeof(*x), sizeof(*h)) != (ssize_t)sizeof(*x))
            return S3_ERR_INTERNAL;
        if (x->cksum_algo >= S3_CKSUM_MAX
            || x->cksum_type > S3_CKSUM_TYPE_COMPOSITE
            || (x->cksum_type == S3_CKSUM_TYPE_COMPOSITE
                && (x->cksum_parts == 0 || x->cksum_parts > 10000)))
            return S3_ERR_INTERNAL;
    } else {
        return S3_ERR_INTERNAL;
    }
    if (h->ct_len > OBJ_MAX_CT_LEN || h->key_len == 0 || h->key_len > 1024)
        return S3_ERR_INTERNAL;
    if ((uint64_t)h->header_size != (uint64_t)fixed + h->ct_len + h->key_len)
        return S3_ERR_INTERNAL;
    if (h->part_count > 10000) return S3_ERR_INTERNAL;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < 0
        || (uint64_t)st.st_size < h->header_size
        || (uint64_t)st.st_size - h->header_size != h->data_size)
        return S3_ERR_INTERNAL;
    *ct_off = fixed;
    return S3_OK;
}

/* Fill meta from a validated header (content-type read from fd). */
static s3_err_t obj_fill_meta(int fd, const obj_header_t *h,
                              const obj_ext_v3_t *x, uint32_t ct_off,
                              s3_obj_meta_t *m) {
    memset(m, 0, sizeof(*m));
    m->size       = h->data_size;
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
    uint32_t ct_off;
    s3_err_t e = obj_read_hdr(fd, &h, &x, &ct_off);
    if (e != S3_OK) return e;
    if (hdr_out) *hdr_out = h;
    if (meta_out) return obj_fill_meta(fd, &h, &x, ct_off, meta_out);
    return S3_OK;
}

s3_err_t store_get_open(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                        s3_reader_t **out, s3_obj_meta_t *meta_out) {
    if (!s || !out) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!valid_key(key))            return S3_ERR_INVALID_ARGUMENT;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;

    char hex[65];
    hash_bucket_key(bucket, key, hex);
    char path[4096];
    if (obj_path(s, bucket, hex, path, sizeof(path)) < 0) return S3_ERR_INTERNAL;

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT) return S3_ERR_NO_SUCH_KEY;
        return S3_ERR_INTERNAL;
    }

    obj_header_t h;
    s3_err_t e = read_header(fd, &h, meta_out);
    if (e != S3_OK) { close(fd); return e; }

    s3_reader_t *r = calloc(1, sizeof(*r));
    if (!r) { close(fd); return S3_ERR_INTERNAL; }
    r->fd        = fd;
    r->data_off  = h.header_size;
    r->data_size = h.data_size;
    r->pos       = 0;
    *out = r;
    return S3_OK;
}

ssize_t store_get_read(s3_reader_t *r, void *buf, size_t n) {
    if (!r) { errno = EINVAL; return -1; }
    if (r->pos >= r->data_size) return 0;
    uint64_t avail = r->data_size - r->pos;
    if ((uint64_t)n > avail) n = (size_t)avail;
    ssize_t got = pread(r->fd, buf, n, (off_t)(r->data_off + r->pos));
    if (got > 0) r->pos += (uint64_t)got;
    return got;
}

ssize_t store_get_sendfile(s3_reader_t *r, int out_fd, size_t max) {
    if (!r) { errno = EINVAL; return -1; }
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
    if (!s) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!valid_key(key))            return S3_ERR_INVALID_ARGUMENT;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;

    char hex[65];
    hash_bucket_key(bucket, key, hex);
    char path[4096];
    if (obj_path(s, bucket, hex, path, sizeof(path)) < 0) return S3_ERR_INTERNAL;
    pthread_mutex_t *km = key_lock(s, hex);
    pthread_mutex_lock(km);
    int urc = unlink(path);
    int uerr = errno;
    pthread_mutex_unlock(km);
    errno = uerr;
    if (urc < 0) {
        if (errno == ENOENT) {
            /* S3 DELETE is idempotent: deleting a missing key is success. */
            return S3_OK;
        }
        LOG_W("unlink %s: %s", path, strerror(errno));
        return S3_ERR_INTERNAL;
    }
    /* fsync the leaf dir for durability. */
    char *slash = strrchr(path, '/');
    if (slash) {
        *slash = '\0';
        (void)fsync_dir(path);
    }
    return S3_OK;
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
static int load_entry(const char *path, list_entry_t *out) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    obj_header_t h;
    obj_ext_v3_t x;
    uint32_t ct_off;
    if (obj_read_hdr(fd, &h, &x, &ct_off) != S3_OK) { close(fd); return -1; }
    char *kbuf = malloc((size_t)h.key_len + 1);
    if (!kbuf) { close(fd); return -1; }
    if (pread(fd, kbuf, h.key_len, (off_t)ct_off + h.ct_len) != (ssize_t)h.key_len
        || obj_fill_meta(fd, &h, &x, ct_off, &out->meta) != S3_OK) {
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
                if (load_entry(path, &items[n]) == 0) n++;
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
    qsort(l->items, l->n_items, sizeof(list_entry_t), cmp_entries);
    *out = l;
    return S3_OK;
}

s3_err_t store_list_next(s3_lister_t *l, s3_str_t *key_out,
                         s3_obj_meta_t *meta_out, int *is_prefix_out) {
    if (!l || !key_out) return S3_ERR_INVALID_ARGUMENT;

    while (l->cursor < l->n_items) {
        if (l->emitted >= l->max_keys) {
            /* We hit max_keys. Are there any more matching items still
             * available? If so, mark truncated. We need to scan ahead
             * once to find out — at most one matching item is enough. */
            for (size_t i = l->cursor; i < l->n_items; i++) {
                list_entry_t *e2 = &l->items[i];
                /* Apply same filters used in the main loop. */
                if (l->marker.n > 0) {
                    size_t mn = l->marker.n < e2->key_len ? l->marker.n : e2->key_len;
                    int c = memcmp(e2->key, l->marker.p, mn);
                    if (c < 0) continue;
                    if (c == 0 && e2->key_len <= l->marker.n) continue;
                }
                if (!starts_with(e2->key, e2->key_len, l->prefix)) continue;
                /* For delimiter, we also need to ensure the rolled-up
                 * prefix would be different from last_prefix. Simplification:
                 * any further matching key counts as "more available". This
                 * may overestimate truncation in rare delimiter-rollup
                 * cases but never under-reports. */
                l->truncated = 1;
                break;
            }
            return S3_ERR_NO_SUCH_KEY;
        }

        list_entry_t *e = &l->items[l->cursor++];

        /* Marker: skip keys lexicographically <= marker. */
        if (l->marker.n > 0) {
            size_t mn = l->marker.n < e->key_len ? l->marker.n : e->key_len;
            int c = memcmp(e->key, l->marker.p, mn);
            if (c < 0) continue;
            if (c == 0 && e->key_len <= l->marker.n) continue;
        }

        /* Prefix filter. */
        if (!starts_with(e->key, e->key_len, l->prefix)) continue;

        /* Delimiter handling: roll up keys sharing a prefix up to next
         * occurrence of delimiter (after l->prefix). */
        if (l->delimiter.n > 0) {
            const char *after = e->key + l->prefix.n;
            size_t after_n = e->key_len - l->prefix.n;
            const char *hit = NULL;
            if (l->delimiter.n == 1) {
                hit = memchr(after, l->delimiter.p[0], after_n);
            } else {
                /* Multi-char delimiter; rare. Naive scan. */
                for (size_t i = 0; i + l->delimiter.n <= after_n; i++) {
                    if (memcmp(after + i, l->delimiter.p, l->delimiter.n) == 0) {
                        hit = after + i; break;
                    }
                }
            }
            if (hit) {
                size_t prefix_total = (size_t)(hit - e->key) + l->delimiter.n;
                if (l->last_prefix && l->last_prefix_len == prefix_total
                    && memcmp(l->last_prefix, e->key, prefix_total) == 0) {
                    continue;  /* already emitted this rollup */
                }
                /* Save the rollup as the value to return. */
                if (prefix_total + 1 > l->ret_cap) {
                    char *nb = realloc(l->ret_buf, prefix_total + 1);
                    if (!nb) return S3_ERR_INTERNAL;
                    l->ret_buf = nb; l->ret_cap = prefix_total + 1;
                }
                memcpy(l->ret_buf, e->key, prefix_total);
                l->ret_buf[prefix_total] = '\0';

                /* Update last-prefix dedupe tracker. */
                char *np = realloc(l->last_prefix, prefix_total);
                if (!np) return S3_ERR_INTERNAL;
                l->last_prefix = np;
                memcpy(l->last_prefix, e->key, prefix_total);
                l->last_prefix_len = prefix_total;

                key_out->p = l->ret_buf;
                key_out->n = prefix_total;
                if (is_prefix_out) *is_prefix_out = 1;
                l->emitted++;
                return S3_OK;
            }
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
    if (!s || !upload_id_out) return S3_ERR_INVALID_ARGUMENT;
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

s3_err_t store_mpu_part_begin(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                              const char *upload_id, int part_number,
                              s3_writer_t **out) {
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
    ssize_t off = 0;
    while ((size_t)off < n) {
        ssize_t r = xwrite(w->fd, (const char *)buf + off, n - (size_t)off);
        if (r < 0) {
            if (errno == EINTR) continue;
            return map_io_err(errno);
        }
        off += r;
    }
    EVP_DigestUpdate(w->md5_ctx, buf, n);
    w->data_written += n;
    return S3_OK;
}

s3_err_t store_mpu_part_commit(s3_writer_t *w, char etag_hex_out[33]) {
    if (!w || w->finalized || !w->is_part) return S3_ERR_INVALID_ARGUMENT;
    w->finalized = 1;

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

    /* Part checksum sidecar part-NNNNN.ck: [algo][digest]. Staged in
     * tmp/ and renamed in with the part. */
    char ck_tmp[4096] = "", ck_final[4200] = "";
    if (w->ext.cksum_algo) {
        size_t dn = cksum_digest_len(w->ext.cksum_algo);
        uint8_t rec[1 + 32];
        rec[0] = w->ext.cksum_algo;
        memcpy(rec + 1, w->ext.cksum, dn);
        snprintf(ck_final, sizeof(ck_final), "%s.ck", w->final_path);
        int cfd = tmp_open(w->store, ck_tmp, sizeof(ck_tmp));
        if (cfd < 0) { s3_err_t e = map_io_err(errno); writer_free(w); return e; }
        if (xwrite(cfd, rec, 1 + dn) != (ssize_t)(1 + dn) || xfsync(cfd) < 0) {
            s3_err_t e = map_io_err(errno);
            close(cfd); unlink(ck_tmp); writer_free(w); return e;
        }
        close(cfd);
    }
    /* ns_mu: an rm_rf of the upload dir (abort, GC, complete, bucket
     * delete) must not interleave with this rename, or its final rmdir
     * would fail on the newly-arrived part. */
    pthread_mutex_lock(&w->store->ns_mu);
    int rc = 0;
    if (ck_tmp[0]) {
        rc = rename(ck_tmp, ck_final);
    } else {
        /* A re-upload without a checksum must not inherit a stale one. */
        char stale[4200];
        snprintf(stale, sizeof(stale), "%s.ck", w->final_path);
        unlink(stale);
    }
    if (rc == 0) rc = rename(w->tmp_path, w->final_path);
    int rename_errno = errno;
    pthread_mutex_unlock(&w->store->ns_mu);
    if (rc < 0 && ck_tmp[0]) unlink(ck_tmp);
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
    else if (rm_rf(dir) < 0)     e = S3_ERR_INTERNAL;
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

s3_err_t store_mpu_complete2(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                             const char *upload_id,
                             const s3_part_ref_t *parts, size_t n_parts,
                             const uint8_t *full_expect, size_t full_n,
                             char etag_out[40], s3_obj_meta_t *meta_out) {
    if (!s || !upload_id || !parts || n_parts == 0) return S3_ERR_INVALID_ARGUMENT;
    cksum_ctx_t comp, full;        /* composite / full-object checksum */
    memset(&comp, 0, sizeof(comp));
    memset(&full, 0, sizeof(full));
    if (n_parts > 10000) return S3_ERR_INVALID_ARGUMENT;
    if (!valid_bucket_name(bucket)) return S3_ERR_INVALID_BUCKET_NAME;
    if (!valid_key(key))            return S3_ERR_INVALID_ARGUMENT;
    if (!store_bucket_exists(s, bucket)) return S3_ERR_NO_SUCH_BUCKET;

    /* Verify the upload exists and the key matches. */
    char *stored_key = NULL;
    size_t stored_key_n = 0;
    char *stored_ct = NULL;
    uint8_t mpu_algo = 0, mpu_type = 0;
    s3_err_t err = mpu_read_meta(s, bucket, upload_id,
                                  &stored_key, &stored_key_n, &stored_ct,
                                  &mpu_algo, &mpu_type);
    if (err != S3_OK) {
        free(stored_key); free(stored_ct); cksum_free(&comp); cksum_free(&full);
        return err;
    }
    if (stored_key_n != key.n
        || memcmp(stored_key, key.p, key.n) != 0) {
        free(stored_key); free(stored_ct); cksum_free(&comp); cksum_free(&full);
        return S3_ERR_NO_SUCH_UPLOAD;
    }
    free(stored_key);
    /* stored_ct may be NULL/empty; we'll use it for the new object. */

    /* Validate the parts list:
     *   - part_numbers strictly increasing, each in [1,10000]
     *   - each part file exists and has the right size
     *   - each part's MD5 (recomputed via stat? — no, we trust the
     *     filename and the etag in the request body. Real S3 verifies
     *     against the server-side ETag stored when the part was committed.
     *     We don't persist that today; the part file's MD5 is the etag.
     *     For now, accept whatever etag the client sent — and trust
     *     that if a wrong part file is on disk somehow, the resulting
     *     object will be wrong but we haven't actively misbehaved.)
     *
     * Compute total size and the multipart-style ETag:
     *   ETag = MD5(concat of raw 16-byte MD5s of each part) + "-N"
     */
    EVP_MD_CTX *etag_md = EVP_MD_CTX_new();
    if (!etag_md || EVP_DigestInit_ex(etag_md, EVP_md5(), NULL) != 1) {
        if (etag_md) EVP_MD_CTX_free(etag_md);
        free(stored_ct); cksum_free(&comp); cksum_free(&full);
        return S3_ERR_INTERNAL;
    }

    int prev_pn = 0;
    /* First pass: validate ordering and ranges (cheap, no disk access). */
    for (size_t i = 0; i < n_parts; i++) {
        if (parts[i].part_number <= prev_pn
            || parts[i].part_number < 1
            || parts[i].part_number > 10000) {
            EVP_MD_CTX_free(etag_md);
            free(stored_ct); cksum_free(&comp); cksum_free(&full);
            return S3_ERR_INVALID_ARGUMENT;
        }
        prev_pn = parts[i].part_number;
    }

    if (mpu_algo) {
        int a = mpu_type == S3_CKSUM_TYPE_COMPOSITE ? cksum_begin(&comp, mpu_algo)
                                                    : cksum_begin(&full, mpu_algo);
        if (a < 0) {
            EVP_MD_CTX_free(etag_md);
            free(stored_ct); cksum_free(&comp); cksum_free(&full);
            return S3_ERR_INTERNAL;
        }
    }

    /* Second pass: stat each part, accumulate sizes + multipart-MD5. */
    uint64_t total_size = 0;
    for (size_t i = 0; i < n_parts; i++) {
        char pp[4096];
        if (mpu_part_path(s, bucket, upload_id, parts[i].part_number,
                          pp, sizeof(pp)) < 0) {
            EVP_MD_CTX_free(etag_md);
            free(stored_ct); cksum_free(&comp); cksum_free(&full);
            return S3_ERR_INTERNAL;
        }
        struct stat st;
        if (stat(pp, &st) < 0) {
            EVP_MD_CTX_free(etag_md);
            free(stored_ct); cksum_free(&comp); cksum_free(&full);
            return S3_ERR_INVALID_PART;
        }
        total_size += (uint64_t)st.st_size;

        if (mpu_algo) {
            uint8_t pck[32];
            int pn = read_part_cksum(pp, mpu_algo, pck);
            if (pn <= 0 || (parts[i].cksum_n
                            && (parts[i].cksum_n != pn
                                || memcmp(parts[i].cksum, pck, (size_t)pn)))) {
                EVP_MD_CTX_free(etag_md);
                free(stored_ct); cksum_free(&comp); cksum_free(&full);
                return S3_ERR_INVALID_PART;
            }
            if (comp.algo) cksum_update(&comp, pck, (size_t)pn);
        }

        /* Decode the etag hex into 16 raw bytes and feed into multipart-MD5. */
        uint8_t raw[16];
        for (int j = 0; j < 16; j++) {
            char hi = parts[i].etag_hex[2*j];
            char lo = parts[i].etag_hex[2*j + 1];
            int hv = (hi >= '0' && hi <= '9') ? hi - '0'
                   : (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10
                   : (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
            int lv = (lo >= '0' && lo <= '9') ? lo - '0'
                   : (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10
                   : (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
            if (hv < 0 || lv < 0) {
                EVP_MD_CTX_free(etag_md);
                free(stored_ct); cksum_free(&comp); cksum_free(&full);
                return S3_ERR_INVALID_PART;
            }
            raw[j] = (uint8_t)((hv << 4) | lv);
        }
        EVP_DigestUpdate(etag_md, raw, 16);
    }

    uint8_t mp_md5[16];
    unsigned int mp_md5_n = 16;
    EVP_DigestFinal_ex(etag_md, mp_md5, &mp_md5_n);
    EVP_MD_CTX_free(etag_md);
    static const char H[] = "0123456789abcdef";
    char mp_hex[33];
    for (int i = 0; i < 16; i++) {
        mp_hex[2*i + 0] = H[(mp_md5[i] >> 4) & 0xF];
        mp_hex[2*i + 1] = H[ mp_md5[i]       & 0xF];
    }
    mp_hex[32] = '\0';

    /* Now assemble the object file. We mirror the single-PUT layout:
     * obj_header_t + content_type + key + concatenated part data.
     * The header.etag is the raw 16 bytes of mp_md5.
     */

    /* Build target dir + path using the same hash + obj_dir/obj_path
     * helpers as single-PUT. */
    char hex[65];
    hash_bucket_key(bucket, key, hex);
    char target_dir[4096];
    if (obj_dir(s, bucket, hex, target_dir, sizeof(target_dir)) < 0) {
        free(stored_ct); cksum_free(&comp); cksum_free(&full);
        return S3_ERR_INTERNAL;
    }
    char target_path[4096];
    if (obj_path(s, bucket, hex, target_path, sizeof(target_path)) < 0) {
        free(stored_ct); cksum_free(&comp); cksum_free(&full);
        return S3_ERR_INTERNAL;
    }

    /* Open temp file in tmp/ */
    char tmp_path[4096];
    snprintf(tmp_path, sizeof(tmp_path), "%s/mpu.XXXXXX", s->tmp_dir);
    int tfd = mkstemp(tmp_path);
    if (tfd < 0) {
        s3_err_t e = map_io_err(errno);
        free(stored_ct); cksum_free(&comp); cksum_free(&full);
        return e;
    }

    /* Build header — native byte order, like single-PUT. */
    obj_header_t hdr = {0};
    memcpy(hdr.magic, OBJ_MAGIC, OBJ_MAGIC_LEN);
    hdr.schema = OBJ_SCHEMA;
    size_t ct_n = stored_ct ? strlen(stored_ct) : 0;
    if (ct_n > UINT16_MAX || key.n > UINT16_MAX) {
        close(tfd); unlink(tmp_path); free(stored_ct); cksum_free(&comp); cksum_free(&full);
        return S3_ERR_INVALID_ARGUMENT;
    }
    hdr.ct_len = (uint16_t)ct_n;
    hdr.key_len = (uint16_t)key.n;
    hdr.part_count = (uint16_t)n_parts;
    hdr.header_size = (uint32_t)(sizeof(hdr) + sizeof(obj_ext_v3_t)
                                 + ct_n + key.n);
    hdr.data_size = total_size;
    obj_ext_v3_t ext;
    memset(&ext, 0, sizeof(ext));
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t mtime_ms = (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
    hdr.mtime_ms = mtime_ms;
    memcpy(hdr.etag, mp_md5, 16);

    if (xwrite(tfd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)
        || xwrite(tfd, &ext, sizeof(ext)) != (ssize_t)sizeof(ext)
        || (ct_n && xwrite(tfd, stored_ct, ct_n) != (ssize_t)ct_n)
        || (key.n && xwrite(tfd, key.p, key.n) != (ssize_t)key.n)) {
        s3_err_t e = map_io_err(errno);
        close(tfd); unlink(tmp_path); free(stored_ct); cksum_free(&comp); cksum_free(&full);
        return e;
    }

    /* Concatenate part files. */
    for (size_t i = 0; i < n_parts; i++) {
        char pp[4096];
        mpu_part_path(s, bucket, upload_id, parts[i].part_number,
                      pp, sizeof(pp));
        int pfd = open(pp, O_RDONLY | O_CLOEXEC);
        if (pfd < 0) {
            close(tfd); unlink(tmp_path); free(stored_ct); cksum_free(&comp); cksum_free(&full);
            return S3_ERR_INVALID_PART;
        }
        char buf[64 * 1024];
        for (;;) {
            ssize_t r = read(pfd, buf, sizeof(buf));
            if (r == 0) break;
            if (r < 0) {
                if (errno == EINTR) continue;
                close(pfd); close(tfd); unlink(tmp_path); free(stored_ct); cksum_free(&comp); cksum_free(&full);
                return S3_ERR_INTERNAL;
            }
            if (full.algo) cksum_update(&full, buf, (size_t)r);
            ssize_t off = 0;
            while (off < r) {
                ssize_t wr = xwrite(tfd, buf + off, (size_t)(r - off));
                if (wr < 0) {
                    if (errno == EINTR) continue;
                    s3_err_t e = map_io_err(errno);
                    close(pfd); close(tfd); unlink(tmp_path); free(stored_ct); cksum_free(&comp); cksum_free(&full);
                    return e;
                }
                off += wr;
            }
        }
        close(pfd);
    }

    /* Object checksum into the v3 extension. */
    if (mpu_algo) {
        uint8_t dg[32]; size_t dn = 0;
        cksum_ctx_t *k = comp.algo ? &comp : &full;
        if (cksum_final(k, dg, &dn) < 0) {
            close(tfd); unlink(tmp_path); free(stored_ct); cksum_free(&comp); cksum_free(&full);
            return S3_ERR_INTERNAL;
        }
        if (!comp.algo && full_expect
            && (full_n != dn || memcmp(full_expect, dg, dn) != 0)) {
            close(tfd); unlink(tmp_path); free(stored_ct); cksum_free(&comp); cksum_free(&full);
            return S3_ERR_CHECKSUM_MISMATCH;
        }
        ext.cksum_algo = mpu_algo;
        ext.cksum_type = mpu_type;
        ext.cksum_parts = mpu_type == S3_CKSUM_TYPE_COMPOSITE ? (uint16_t)n_parts : 0;
        memcpy(ext.cksum, dg, dn);
        if (pwrite(tfd, &ext, sizeof(ext), sizeof(hdr)) != (ssize_t)sizeof(ext)) {
            s3_err_t e = map_io_err(errno);
            close(tfd); unlink(tmp_path); free(stored_ct); cksum_free(&comp); cksum_free(&full);
            return e;
        }
    }
    cksum_free(&comp);
    cksum_free(&full);

    if (xfsync(tfd) < 0) {
        s3_err_t e = map_io_err(errno);
        close(tfd); unlink(tmp_path); free(stored_ct); cksum_free(&comp); cksum_free(&full);
        return e;
    }
    close(tfd);

    /* Publish under ns_mu. The concatenation above can take a long time
     * on a worker thread, so re-check that neither the bucket (delete)
     * nor the upload (abort/GC) went away meanwhile — if one did, the
     * later operation wins and nothing is published. The staging dir is
     * removed in the same critical section, so no concurrent abort can
     * observe a half-removed upload. */
    char up_dir[4096], up_meta[4200];
    mpu_dir_path(s, bucket, upload_id, up_dir, sizeof(up_dir));
    snprintf(up_meta, sizeof(up_meta), "%s/meta", up_dir);
    pthread_mutex_t *km = key_lock(s, hex);
    pthread_mutex_lock(km);
    pthread_mutex_lock(&s->ns_mu);
    s3_err_t pe = S3_OK;
    if (!store_bucket_exists(s, bucket))          pe = S3_ERR_NO_SUCH_BUCKET;
    else if (access(up_meta, F_OK) < 0)           pe = S3_ERR_NO_SUCH_UPLOAD;
    else if (mkdir_p(target_dir, 0700) < 0
             || rename(tmp_path, target_path) < 0) pe = map_io_err(errno);
    else                                          rm_rf(up_dir);
    pthread_mutex_unlock(&s->ns_mu);
    pthread_mutex_unlock(km);
    if (pe != S3_OK) {
        unlink(tmp_path); free(stored_ct); cksum_free(&comp); cksum_free(&full);
        return pe;
    }
    fsync_dir(target_dir);

    /* Fill outputs. */
    if (etag_out) {
        snprintf(etag_out, 40, "%s-%zu", mp_hex, n_parts);
    }
    if (meta_out) {
        memset(meta_out, 0, sizeof(*meta_out));
        meta_out->size = total_size;
        meta_out->mtime_ms = mtime_ms;
        meta_out->part_count = (uint16_t)n_parts;
        memcpy(meta_out->etag, mp_md5, 16);
        meta_out->cksum_algo  = ext.cksum_algo;
        meta_out->cksum_type  = ext.cksum_type;
        meta_out->cksum_parts = ext.cksum_parts;
        memcpy(meta_out->cksum, ext.cksum, 32);
        if (stored_ct) {
            strncpy(meta_out->content_type, stored_ct,
                    sizeof(meta_out->content_type) - 1);
        }
    }
    free(stored_ct); cksum_free(&comp); cksum_free(&full);
    return S3_OK;
}

/* ===================================================================== */
/* List in-flight multipart uploads                                       */
/* ===================================================================== */

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
            if (rm_rf(up_dir) == 0) removed++;
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
    char hex[65], path[4096], dir[4096];
    hash_bucket_key(bucket, key, hex);
    if (obj_path(s, bucket, hex, path, sizeof(path)) < 0
        || obj_dir(s, bucket, hex, dir, sizeof(dir)) < 0)
        return S3_ERR_INTERNAL;
    pthread_mutex_t *km = key_lock(s, hex);
    pthread_mutex_lock(km);
    s3_err_t e = S3_OK;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        e = errno == ENOENT ? S3_ERR_NO_SUCH_KEY : S3_ERR_INTERNAL;
    } else {
        s3_obj_meta_t m;
        e = read_header(fd, NULL, &m);
        close(fd);
        if (e == S3_OK && m.mtime_ms != mtime_ms) e = S3_ERR_INVALID_REQUEST;
        if (e == S3_OK && unlink(path) < 0) e = map_io_err(errno);
    }
    pthread_mutex_unlock(km);
    if (e == S3_OK) fsync_dir(dir);
    return e;
}
