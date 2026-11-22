/* src/dedup_estimate.c — fs3-dedup-estimate: how much would block-level
 * dedup save on an existing fs3 data root?
 *
 * Read-only. Walks <root>/data/<bucket>/NN/NN/<hex> (current objects) and
 * <root>/versions/<bucket>/NN/NN/<hex>/<entry> (noncurrent versions),
 * parses each object header (schemas 2, 3 and 4, validated the same way
 * the store does), and hashes the payload in fixed blocks aligned to the
 * payload start. It reports, per block size:
 *
 *   - bytes already covered by whole-object dedup (identical payloads),
 *   - bytes that block dedup could share on top of that, with owner
 *     scope (the default of --dedup) and with global scope.
 *
 * Block boundaries are aligned to the payload start because that is what
 * a reflink-based design can clone (FICLONERANGE needs 4 KiB-aligned file
 * offsets, and schema-4 headers are padded to 4 KiB when reflink is
 * available). Objects whose header isn't 4 KiB-aligned (ext4, pre-v4) are
 * hashed the same way and reported separately: they would need a rewrite
 * before their extents could be shared.
 *
 * Memory is capped (--max-mem). When the block index would exceed it, the
 * tool switches to content-based sampling: it keeps only block hashes
 * whose low bits are zero, so all copies of a block are kept or dropped
 * together and the duplicate ratio stays an unbiased estimate. Results are
 * scaled back up and marked as sampled.
 *
 * Skipped and counted: delete markers, SSE-C and other transformed
 * payloads (sealed with a per-object salt, never shareable), unreadable or
 * malformed files, temp files, symlinks (layout-2 current pointers; the
 * target is walked under versions/), and extra hard links of an inode
 * already seen (versioning's link-aside).
 *
 * The 64-bit block hash is xxHash64. At the block counts involved, the
 * collision probability is negligible for an estimate; nothing here is
 * used to share data.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ===================================================================== */
/* On-disk object header (mirror of src/store_fs.c; keep in sync)        */
/* ===================================================================== */

#define OBJ_MAGIC     "YS3OBJ\0"
#define OBJ_MAGIC_LEN 8
#define OBJ_SCHEMA_V2 2u
#define OBJ_SCHEMA_V3 3u
#define OBJ_SCHEMA_V4 4u
#define OBJ_MAX_TLV   (64 * 1024)
#define OBJ_MAX_PAD   4095
#define OBJ_MAX_CT    1024

#define OBJF_DELETE_MARKER (1u << 0)
#define OBJF_SSEC          (1u << 2)
#define OBJF_ZSTD          (1u << 3)

typedef struct __attribute__((packed)) {
    char     magic[OBJ_MAGIC_LEN];
    uint32_t schema;
    uint32_t header_size;
    uint64_t data_size;
    uint64_t mtime_ms;
    uint8_t  etag[16];
    uint16_t ct_len;
    uint16_t key_len;
    uint16_t part_count;
    uint8_t  reserved[6];
} obj_header_t;
_Static_assert(sizeof(obj_header_t) == 60, "obj_header_t layout");

typedef struct __attribute__((packed)) {
    uint8_t  version_id[16];
    uint32_t flags;
    uint8_t  cksum_algo;
    uint8_t  cksum_type;
    uint16_t cksum_parts;
    uint8_t  cksum[32];
    uint8_t  reserved[8];
} obj_ext_v3_t;
_Static_assert(sizeof(obj_ext_v3_t) == 64, "obj_ext_v3_t layout");

typedef struct __attribute__((packed)) {
    uint64_t stored_size;
    uint8_t  payload_crc64[8];
    uint32_t tlv_len;
    uint32_t pad_len;
    uint8_t  reserved[8];
} obj_ext_v4_t;
_Static_assert(sizeof(obj_ext_v4_t) == 32, "obj_ext_v4_t layout");

/* ===================================================================== */
/* xxHash64                                                              */
/* ===================================================================== */

static const uint64_t P1 = 11400714785074694791ULL, P2 = 14029467366897019727ULL,
                      P3 = 1609587929392839161ULL,  P4 = 9650029242287828579ULL,
                      P5 = 2870177450012600261ULL;

static inline uint64_t rotl64(uint64_t x, int r) { return (x << r) | (x >> (64 - r)); }
static inline uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static inline uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static inline uint64_t xround(uint64_t acc, uint64_t in) {
    acc += in * P2; acc = rotl64(acc, 31); return acc * P1;
}
static inline uint64_t xmerge(uint64_t acc, uint64_t v) {
    acc ^= xround(0, v); return acc * P1 + P4;
}

static uint64_t xxh64(const void *data, size_t len, uint64_t seed) {
    const uint8_t *p = data, *end = p + len;
    uint64_t h;
    if (len >= 32) {
        const uint8_t *lim = end - 32;
        uint64_t v1 = seed + P1 + P2, v2 = seed + P2, v3 = seed, v4 = seed - P1;
        do {
            v1 = xround(v1, rd64(p)); v2 = xround(v2, rd64(p + 8));
            v3 = xround(v3, rd64(p + 16)); v4 = xround(v4, rd64(p + 24));
            p += 32;
        } while (p <= lim);
        h = rotl64(v1, 1) + rotl64(v2, 7) + rotl64(v3, 12) + rotl64(v4, 18);
        h = xmerge(h, v1); h = xmerge(h, v2); h = xmerge(h, v3); h = xmerge(h, v4);
    } else {
        h = seed + P5;
    }
    h += (uint64_t)len;
    while (p + 8 <= end) { h ^= xround(0, rd64(p)); h = rotl64(h, 27) * P1 + P4; p += 8; }
    if (p + 4 <= end) { h ^= (uint64_t)rd32(p) * P1; h = rotl64(h, 23) * P2 + P3; p += 4; }
    while (p < end) { h ^= (*p) * P5; h = rotl64(h, 11) * P1; p++; }
    h ^= h >> 33; h *= P2; h ^= h >> 29; h *= P3; h ^= h >> 32;
    return h;
}

/* ===================================================================== */
/* Small containers                                                      */
/* ===================================================================== */

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { fprintf(stderr, "fs3-dedup-estimate: out of memory\n"); exit(2); }
    return q;
}

/* Open-addressing set of 128-bit keys (a, b); a == b == 0 is "empty", so
 * callers set the top bit of b. */
typedef struct { uint64_t *k; size_t cap, n; } set128_t;

static uint64_t mix64(uint64_t x) {
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL; x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL; x ^= x >> 33; return x;
}

static int set128_add(set128_t *s, uint64_t a, uint64_t b);   /* 1 = new */

static void set128_grow(set128_t *s) {
    set128_t t = { calloc(2 * (s->cap ? s->cap * 2 : 1024), sizeof(uint64_t)),
                   s->cap ? s->cap * 2 : 1024, 0 };
    if (!t.k) { fprintf(stderr, "fs3-dedup-estimate: out of memory\n"); exit(2); }
    for (size_t i = 0; i < s->cap; i++)
        if (s->k[2 * i] | s->k[2 * i + 1]) set128_add(&t, s->k[2 * i], s->k[2 * i + 1]);
    free(s->k);
    *s = t;
}

static int set128_add(set128_t *s, uint64_t a, uint64_t b) {
    if ((s->n + 1) * 4 >= s->cap * 3) set128_grow(s);
    size_t m = s->cap - 1, i = (size_t)(mix64(a ^ mix64(b)) & m);
    for (;;) {
        uint64_t *e = &s->k[2 * i];
        if (!(e[0] | e[1])) { e[0] = a; e[1] = b; s->n++; return 1; }
        if (e[0] == a && e[1] == b) return 0;
        i = (i + 1) & m;
    }
}

/* ===================================================================== */
/* State                                                                 */
/* ===================================================================== */

#define MAX_SIZES 4

typedef struct { uint64_t h; uint32_t bucket; uint32_t len; } entry_t;  /* 16 B */
typedef struct { entry_t *v; size_t n, cap; } vec_t;

typedef struct {
    char    *name;
    int      owner;            /* index into owners[] */
    uint64_t objects, versions, bytes, whole_dup_bytes;
    uint64_t dup_owner[MAX_SIZES], dup_global[MAX_SIZES];
} bucket_t;

static struct {
    /* options */
    uint32_t sizes[MAX_SIZES];
    int      nsizes;
    uint64_t max_mem;
    double   rate;             /* bytes/s, 0 = unlimited */
    int      json, no_versions, quiet;
    const char *only_bucket;

    /* results */
    bucket_t *b;  size_t nb;
    char    **owners; size_t nowners;
    vec_t     idx[MAX_SIZES];  /* block index per size */
    vec_t     cur[MAX_SIZES];  /* blocks of the object being read */
    unsigned  shift;           /* sampling: keep h with low `shift` bits zero */
    set128_t  objects, inodes;

    uint64_t files, objs, bytes_logical, bytes_unaligned, whole_dup_bytes, whole_dup_objs;
    uint64_t markers, transformed, transformed_bytes, unreadable, skipped_links, empty;
    uint64_t bytes_read;
    struct timespec t0;
    time_t   last_progress;
    uint8_t *buf;
    size_t   bufsz;
} G;

static double now_s(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)(t.tv_sec - G.t0.tv_sec) + (double)(t.tv_nsec - G.t0.tv_nsec) / 1e9;
}

static void vec_push(vec_t *v, entry_t e) {
    if (v->n == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 4096;
        v->v = xrealloc(v->v, v->cap * sizeof(entry_t));
    }
    v->v[v->n++] = e;
}

static uint64_t index_bytes(void) {
    uint64_t t = 0;
    for (int i = 0; i < G.nsizes; i++) t += (uint64_t)(G.idx[i].cap + G.cur[i].cap) * sizeof(entry_t);
    return t + (uint64_t)(G.objects.cap + G.inodes.cap) * 16;
}

static inline int sampled(uint64_t h) {
    return G.shift == 0 || (h & ((1ULL << G.shift) - 1)) == 0;
}

/* Raise the sampling rate until the index fits again. */
static void enforce_mem(void) {
    while (index_bytes() > G.max_mem && G.shift < 20) {
        G.shift++;
        for (int i = 0; i < G.nsizes; i++) {
            vec_t *v = &G.idx[i];
            size_t w = 0;
            for (size_t r = 0; r < v->n; r++) if (sampled(v->v[r].h)) v->v[w++] = v->v[r];
            v->n = w;
            if (v->cap > 2 * w + 4096) {          /* give memory back */
                v->cap = w + 4096;
                v->v = xrealloc(v->v, v->cap * sizeof(entry_t));
            }
        }
    }
}

/* ===================================================================== */
/* Buckets and owners                                                    */
/* ===================================================================== */

static int owner_index(const char *o) {
    for (size_t i = 0; i < G.nowners; i++) if (!strcmp(G.owners[i], o)) return (int)i;
    G.owners = xrealloc(G.owners, (G.nowners + 1) * sizeof(char *));
    G.owners[G.nowners] = strdup(o);
    if (!G.owners[G.nowners]) exit(2);
    return (int)G.nowners++;
}

static int read_owner(const char *root, const char *bucket) {
    char p[4200], line[512], owner[300] = "";
    snprintf(p, sizeof(p), "%s/buckets/%s/meta", root, bucket);
    FILE *f = fopen(p, "r");
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            if (!strncmp(line, "owner=", 6)) {
                size_t n = strcspn(line + 6, "\r\n");
                if (n >= sizeof(owner)) n = sizeof(owner) - 1;
                memcpy(owner, line + 6, n); owner[n] = 0;
            }
        }
        fclose(f);
    }
    /* Ownerless buckets each count as their own scope. */
    if (!owner[0]) snprintf(owner, sizeof(owner), "\x01bucket:%s", bucket);
    return owner_index(owner);
}

static int cmp_str(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* Bucket names: union of data/ and versions/ children, sorted. */
static void collect_buckets(const char *root) {
    char **names = NULL; size_t n = 0;
    const char *sub[2] = { "data", "versions" };
    for (int s = 0; s < 2; s++) {
        char p[4200];
        snprintf(p, sizeof(p), "%s/%s", root, sub[s]);
        DIR *d = opendir(p);
        if (!d) continue;
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            if (G.only_bucket && strcmp(G.only_bucket, e->d_name)) continue;
            int dup = 0;
            for (size_t i = 0; i < n; i++) if (!strcmp(names[i], e->d_name)) { dup = 1; break; }
            if (dup) continue;
            names = xrealloc(names, (n + 1) * sizeof(char *));
            names[n++] = strdup(e->d_name);
        }
        closedir(d);
    }
    if (n) qsort(names, n, sizeof(char *), cmp_str);
    G.b = calloc(n ? n : 1, sizeof(bucket_t));
    if (!G.b) exit(2);
    for (size_t i = 0; i < n; i++) {
        G.b[i].name = names[i];
        G.b[i].owner = read_owner(root, names[i]);
    }
    G.nb = n;
    free(names);
}

/* ===================================================================== */
/* One object file                                                       */
/* ===================================================================== */

static void progress(void) {
    if (G.quiet) return;
    time_t t = time(NULL);
    if (t - G.last_progress < 5) return;
    G.last_progress = t;
    fprintf(stderr, "  … %" PRIu64 " objects, %.1f GiB read, %.0f s%s\n",
            G.objs, (double)G.bytes_read / (1ULL << 30), now_s(),
            G.shift ? " (sampling)" : "");
}

static void throttle(void) {
    if (G.rate <= 0) return;
    double want = (double)G.bytes_read / G.rate, have = now_s();
    if (want > have) {
        double d = want - have;
        struct timespec ts = { (time_t)d, (long)((d - (double)(time_t)d) * 1e9) };
        nanosleep(&ts, NULL);
    }
}

/* Header parse, mirroring obj_read_hdr4() in store_fs.c (without TLV
 * content checks, which don't affect where the payload is). */
static int parse_header(int fd, const struct stat *st, uint64_t *payload_off,
                        uint64_t *payload_len, uint32_t *flags) {
    obj_header_t h; obj_ext_v3_t x; obj_ext_v4_t x4;
    memset(&x, 0, sizeof(x)); memset(&x4, 0, sizeof(x4));
    if (pread(fd, &h, sizeof(h), 0) != (ssize_t)sizeof(h)) return -1;
    if (memcmp(h.magic, OBJ_MAGIC, OBJ_MAGIC_LEN)) return -1;
    uint64_t fixed = sizeof(h);
    if (h.schema == OBJ_SCHEMA_V3 || h.schema == OBJ_SCHEMA_V4) {
        if (pread(fd, &x, sizeof(x), (off_t)fixed) != (ssize_t)sizeof(x)) return -1;
        fixed += sizeof(x);
        if (h.schema == OBJ_SCHEMA_V4) {
            if (pread(fd, &x4, sizeof(x4), (off_t)fixed) != (ssize_t)sizeof(x4)) return -1;
            fixed += sizeof(x4);
            if (x4.tlv_len > OBJ_MAX_TLV || x4.pad_len > OBJ_MAX_PAD) return -1;
        }
    } else if (h.schema != OBJ_SCHEMA_V2) {
        return -1;
    }
    if (h.ct_len > OBJ_MAX_CT || h.key_len == 0 || h.key_len > 1024) return -1;
    if ((uint64_t)h.header_size != fixed + h.ct_len + h.key_len + x4.tlv_len + x4.pad_len)
        return -1;
    uint64_t stored = h.schema == OBJ_SCHEMA_V4 ? x4.stored_size : h.data_size;
    if ((uint64_t)st->st_size < h.header_size
        || (uint64_t)st->st_size - h.header_size != stored) return -1;
    *payload_off = h.header_size;
    *payload_len = stored;
    *flags = x.flags;
    return 0;
}

static void hash_object(bucket_t *bk, size_t bidx, int fd, uint64_t off, uint64_t len) {
    for (int i = 0; i < G.nsizes; i++) G.cur[i].n = 0;
    uint64_t objh = 0x9e3779b97f4a7c15ULL ^ len;
    uint64_t pos = 0;
    while (pos < len) {
        size_t want = (size_t)(len - pos < G.bufsz ? len - pos : G.bufsz);
        size_t got = 0;
        while (got < want) {
            ssize_t r = pread(fd, G.buf + got, want - got, (off_t)(off + pos + got));
            if (r < 0 && errno == EINTR) continue;
            if (r <= 0) { G.unreadable++; return; }   /* truncated under us */
            got += (size_t)r;
        }
        for (int i = 0; i < G.nsizes; i++) {
            uint32_t bs = G.sizes[i];
            for (size_t o = 0; o < got; o += bs) {
                uint32_t n = (uint32_t)(got - o < bs ? got - o : bs);
                /* Mix the length in so a short tail never matches a full block. */
                uint64_t h = xxh64(G.buf + o, n, n);
                if (i == 0) objh = xxh64(&h, 8, objh);
                if (sampled(h)) vec_push(&G.cur[i], (entry_t){ h, (uint32_t)bidx, n });
            }
        }
        pos += got;
        G.bytes_read += got;
        throttle();
        progress();
    }
#ifdef POSIX_FADV_DONTNEED
    posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED);
#endif
    /* Whole-object duplicate (same length, same block-hash sequence)? */
    /* Keyed by owner too: --dedup owner (the default) never shares
     * objects across owners, so neither does this figure. */
    if (!set128_add(&G.objects, objh,
                    (mix64(len) + (uint64_t)bk->owner) | (1ULL << 63))) {
        G.whole_dup_bytes += len; G.whole_dup_objs++;
        bk->whole_dup_bytes += len;
        return;
    }
    G.bytes_logical += len;
    bk->bytes += len;
    for (int i = 0; i < G.nsizes; i++)
        for (size_t k = 0; k < G.cur[i].n; k++) vec_push(&G.idx[i], G.cur[i].v[k]);
    enforce_mem();
}

static void visit_file(const char *path, size_t bidx, int is_version) {
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    if (strstr(base, ".tmp.") || base[0] == '.') return;
    struct stat st;
    if (lstat(path, &st) < 0) { G.unreadable++; return; }
    if (S_ISLNK(st.st_mode)) { G.skipped_links++; return; }
    if (!S_ISREG(st.st_mode)) return;
    if (!set128_add(&G.inodes, (uint64_t)st.st_ino, (uint64_t)st.st_dev | (1ULL << 63))) {
        G.skipped_links++;                    /* link-aside: same inode seen */
        return;
    }
    G.files++;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { G.unreadable++; return; }
    uint64_t off, len; uint32_t flags;
    if (fstat(fd, &st) < 0 || parse_header(fd, &st, &off, &len, &flags) < 0) {
        G.unreadable++; close(fd); return;
    }
    bucket_t *bk = &G.b[bidx];
    if (flags & OBJF_DELETE_MARKER) { G.markers++; close(fd); return; }
    G.objs++;
    if (is_version) bk->versions++; else bk->objects++;
    if (flags & (OBJF_SSEC | OBJF_ZSTD)) {
        G.transformed++; G.transformed_bytes += len; close(fd); return;
    }
    if (len == 0) { G.empty++; close(fd); return; }
    if (off % 4096) G.bytes_unaligned += len;
    hash_object(bk, bidx, fd, off, len);
    close(fd);
}

/* Walk `depth` levels of directories under dir, visiting regular files at
 * the leaves (and symlinks, to count them). Sorted for stable output. */
static void walk(const char *dir, int depth, size_t bidx, int is_version) {
    DIR *d = opendir(dir);
    if (!d) return;
    char **names = NULL; size_t n = 0;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        names = xrealloc(names, (n + 1) * sizeof(char *));
        names[n++] = strdup(e->d_name);
    }
    closedir(d);
    if (n) qsort(names, n, sizeof(char *), cmp_str);
    for (size_t i = 0; i < n; i++) {
        char p[4200];
        if (snprintf(p, sizeof(p), "%s/%s", dir, names[i]) < (int)sizeof(p)) {
            if (depth > 0) {
                struct stat st;
                if (lstat(p, &st) == 0 && S_ISDIR(st.st_mode)) walk(p, depth - 1, bidx, is_version);
            } else {
                visit_file(p, bidx, is_version);
            }
        }
        free(names[i]);
    }
    free(names);
}

/* ===================================================================== */
/* Analysis                                                              */
/* ===================================================================== */

static int cmp_entry(const void *a, const void *b) {
    const entry_t *x = a, *y = b;
    if (x->h != y->h) return x->h < y->h ? -1 : 1;
    if (x->len != y->len) return x->len < y->len ? -1 : 1;
    int ox = G.b[x->bucket].owner, oy = G.b[y->bucket].owner;
    if (ox != oy) return ox < oy ? -1 : 1;
    return x->bucket < y->bucket ? -1 : (x->bucket > y->bucket);
}

typedef struct { uint64_t hashed, dup_owner, dup_global, blocks; } size_res_t;

static size_res_t analyse(int si) {
    size_res_t r = { 0, 0, 0, 0 };
    vec_t *v = &G.idx[si];
    if (v->n) qsort(v->v, v->n, sizeof(entry_t), cmp_entry);
    uint64_t scale = (uint64_t)1 << G.shift;
    for (size_t i = 0; i < v->n; ) {
        size_t j = i;
        while (j < v->n && v->v[j].h == v->v[i].h && v->v[j].len == v->v[i].len) j++;
        for (size_t k = i; k < j; k++) {
            uint64_t bytes = (uint64_t)v->v[k].len * scale;
            r.hashed += bytes;
            r.blocks += scale;
            if (k > i) {                                   /* a later copy */
                r.dup_global += bytes;
                G.b[v->v[k].bucket].dup_global[si] += bytes;
                if (G.b[v->v[k].bucket].owner == G.b[v->v[k - 1].bucket].owner) {
                    r.dup_owner += bytes;
                    G.b[v->v[k].bucket].dup_owner[si] += bytes;
                }
            }
        }
        i = j;
    }
    return r;
}

/* ===================================================================== */
/* Output                                                                */
/* ===================================================================== */

static const char *human(uint64_t b, char *out, size_t cap) {
    const char *u[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB" };
    double v = (double)b; int i = 0;
    while (v >= 1024 && i < 5) { v /= 1024; i++; }
    snprintf(out, cap, i ? "%.1f %s" : "%.0f %s", v, u[i]);
    return out;
}

static double pct(uint64_t a, uint64_t b) { return b ? 100.0 * (double)a / (double)b : 0.0; }

static void json_str(const char *s) {
    putchar('"');
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') printf("\\%c", c);
        else if (c < 0x20) printf("\\u%04x", c);
        else putchar(c);
    }
    putchar('"');
}

static void report(size_res_t *res) {
    uint64_t total = G.bytes_logical + G.whole_dup_bytes;
    char a[32], b[32], c[32];
    if (G.json) {
        printf("{\"objects\":%" PRIu64 ",\"files\":%" PRIu64 ",\"logical_bytes\":%" PRIu64
               ",\"whole_object_dup_bytes\":%" PRIu64 ",\"whole_object_dup_objects\":%" PRIu64
               ",\"unique_bytes_hashed\":%" PRIu64 ",\"unaligned_bytes\":%" PRIu64
               ",\"delete_markers\":%" PRIu64 ",\"transformed_objects\":%" PRIu64
               ",\"transformed_bytes\":%" PRIu64 ",\"empty_objects\":%" PRIu64
               ",\"unreadable\":%" PRIu64 ",\"skipped_links\":%" PRIu64
               ",\"sample_rate\":%" PRIu64 ",\"seconds\":%.1f,\"block_sizes\":[",
               G.objs, G.files, total, G.whole_dup_bytes, G.whole_dup_objs, G.bytes_logical,
               G.bytes_unaligned, G.markers, G.transformed, G.transformed_bytes, G.empty,
               G.unreadable, G.skipped_links, (uint64_t)1 << G.shift, now_s());
        for (int i = 0; i < G.nsizes; i++)
            printf("%s{\"block_size\":%u,\"dup_bytes_owner\":%" PRIu64
                   ",\"dup_bytes_global\":%" PRIu64 "}", i ? "," : "",
                   G.sizes[i], res[i].dup_owner, res[i].dup_global);
        printf("],\"buckets\":[");
        for (size_t k = 0; k < G.nb; k++) {
            bucket_t *bk = &G.b[k];
            printf("%s{\"name\":", k ? "," : ""); json_str(bk->name);
            printf(",\"objects\":%" PRIu64 ",\"versions\":%" PRIu64 ",\"bytes\":%" PRIu64
                   ",\"whole_object_dup_bytes\":%" PRIu64 ",\"dup_bytes_owner\":{",
                   bk->objects, bk->versions, bk->bytes + bk->whole_dup_bytes, bk->whole_dup_bytes);
            for (int i = 0; i < G.nsizes; i++)
                printf("%s\"%u\":%" PRIu64, i ? "," : "", G.sizes[i], bk->dup_owner[i]);
            printf("},\"dup_bytes_global\":{");
            for (int i = 0; i < G.nsizes; i++)
                printf("%s\"%u\":%" PRIu64, i ? "," : "", G.sizes[i], bk->dup_global[i]);
            printf("}}");
        }
        printf("]}\n");
        return;
    }

    printf("fs3-dedup-estimate — %" PRIu64 " objects in %zu bucket(s), %.1f s\n\n",
           G.objs, G.nb, now_s());
    printf("  logical payload            %12s\n", human(total, a, sizeof(a)));
    printf("  whole-object duplicates    %12s  (%5.1f%%, %" PRIu64 " objects, same owner; --dedup owner covers this)\n",
           human(G.whole_dup_bytes, a, sizeof(a)), pct(G.whole_dup_bytes, total), G.whole_dup_objs);
    printf("  remaining unique objects   %12s\n", human(G.bytes_logical, a, sizeof(a)));
    if (G.transformed)
        printf("  SSE-C/transformed (skipped)%12s  (%" PRIu64 " objects, never shareable)\n",
               human(G.transformed_bytes, a, sizeof(a)), G.transformed);
    printf("\n  Block dedup on top of whole-object dedup (blocks aligned to the payload start):\n\n");
    printf("    %-8s %23s %23s\n", "block", "owner scope", "global scope");
    for (int i = 0; i < G.nsizes; i++) {
        char sz[16];
        if (G.sizes[i] >= 1024 * 1024) snprintf(sz, sizeof(sz), "%u MiB", G.sizes[i] >> 20);
        else snprintf(sz, sizeof(sz), "%u KiB", G.sizes[i] >> 10);
        printf("    %-8s %14s %7.1f%% %14s %7.1f%%\n", sz,
               human(res[i].dup_owner, b, sizeof(b)), pct(res[i].dup_owner, total),
               human(res[i].dup_global, c, sizeof(c)), pct(res[i].dup_global, total));
    }
    if (G.nb > 1 || G.only_bucket) {
        int si = G.nsizes - 1;
        printf("\n  Per bucket (owner scope, %u KiB blocks):\n\n", G.sizes[si] >> 10);
        printf("    %-32s %9s %12s %8s %8s\n", "bucket", "objects", "bytes", "whole", "block");
        for (size_t k = 0; k < G.nb; k++) {
            bucket_t *bk = &G.b[k];
            uint64_t bb = bk->bytes + bk->whole_dup_bytes;
            printf("    %-32.32s %9" PRIu64 " %12s %7.1f%% %7.1f%%\n", bk->name,
                   bk->objects + bk->versions, human(bb, a, sizeof(a)),
                   pct(bk->whole_dup_bytes, bb), pct(bk->dup_owner[si], bb));
        }
    }
    printf("\n");
    if (G.shift)
        printf("  note: sampled 1/%" PRIu64 " of blocks to stay under --max-mem; block figures are estimates\n",
               (uint64_t)1 << G.shift);
    if (G.bytes_unaligned)
        printf("  note: %s (%.1f%%) sits in objects without a 4 KiB-aligned header (ext4 or pre-schema-4);\n"
               "        they would need rewriting before their extents could be shared\n",
               human(G.bytes_unaligned, a, sizeof(a)), pct(G.bytes_unaligned, total));
    if (G.unreadable)
        printf("  note: %" PRIu64 " file(s) skipped as unreadable or malformed\n", G.unreadable);
    printf("  note: figures are logical duplicate bytes. On Btrfs, space is freed per extent, so\n"
           "        real savings depend on extent layout (docs/block-dedup-plan.md, section 3.4)\n");

    /* Verdict at the largest block size (the planned design's granularity). */
    double best = pct(res[G.nsizes - 1].dup_owner, total);
    printf("\n  verdict: block dedup would save about %.1f%% beyond whole-object dedup (owner scope, %u KiB). %s\n",
           best, G.sizes[G.nsizes - 1] >> 10,
           best < 10.0 ? "Below 10%: probably not worth building."
                       : "10% or more: worth considering.");
}

/* ===================================================================== */
/* main                                                                  */
/* ===================================================================== */

static uint64_t parse_size(const char *s) {
    char *end; errno = 0;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno || end == s) return 0;
    switch (*end) {
    case 'k': case 'K': v <<= 10; end++; break;
    case 'm': case 'M': v <<= 20; end++; break;
    case 'g': case 'G': v <<= 30; end++; break;
    default: break;
    }
    if (*end == 'i' || *end == 'I') end++;
    if (*end == 'b' || *end == 'B') end++;
    return *end ? 0 : (uint64_t)v;
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

static void usage(FILE *f) {
    fprintf(f,
"usage: fs3-dedup-estimate [options] DATA_ROOT\n"
"\n"
"Read-only estimate of what block-level dedup would save on an fs3 data\n"
"root (the directory given to fs3 -d). Safe to run while fs3 is serving.\n"
"\n"
"  --block-sizes LIST  comma-separated, powers of two from 4k to 1m\n"
"                      (default 4k,64k,128k; at most %d)\n"
"  --max-mem SIZE      memory for the block index before sampling kicks in\n"
"                      (default 256m)\n"
"  --rate SIZE         read at most SIZE per second (e.g. 20m; default unlimited)\n"
"  --sample N          keep only 1/N of block hashes from the start (power of\n"
"                      two); faster first look, block figures become estimates\n"
"  --bucket NAME       only this bucket\n"
"  --no-versions       current objects only (skip versions/)\n"
"  --json              machine-readable output\n"
"  -q, --quiet         no progress on stderr\n"
"  -h, --help\n", MAX_SIZES);
}

int main(int argc, char **argv) {
    static const struct option opts[] = {
        { "block-sizes", required_argument, 0, 'b' },
        { "max-mem",     required_argument, 0, 'm' },
        { "rate",        required_argument, 0, 'r' },
        { "bucket",      required_argument, 0, 'B' },
        { "sample",      required_argument, 0, 's' },
        { "no-versions", no_argument,       0, 'V' },
        { "json",        no_argument,       0, 'j' },
        { "quiet",       no_argument,       0, 'q' },
        { "help",        no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    const char *sizes = "4k,64k,128k";
    G.max_mem = 256ULL << 20;
    int c;
    while ((c = getopt_long(argc, argv, "qh", opts, NULL)) != -1) {
        switch (c) {
        case 'b': sizes = optarg; break;
        case 'm': if (!(G.max_mem = parse_size(optarg))) { usage(stderr); return 2; } break;
        case 'r': { uint64_t r = parse_size(optarg); if (!r) { usage(stderr); return 2; }
                    G.rate = (double)r; break; }
        case 'B': G.only_bucket = optarg; break;
        case 's': { uint64_t n = parse_size(optarg);
                    if (!n || (n & (n - 1)) || n > (1u << 20)) { usage(stderr); return 2; }
                    while ((1ULL << G.shift) < n) G.shift++;
                    break; }
        case 'V': G.no_versions = 1; break;
        case 'j': G.json = 1; break;
        case 'q': G.quiet = 1; break;
        case 'h': usage(stdout); return 0;
        default:  usage(stderr); return 2;
        }
    }
    if (optind + 1 != argc) { usage(stderr); return 2; }
    const char *root = argv[optind];

    char *list = strdup(sizes), *save = NULL;
    for (char *t = strtok_r(list, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        uint64_t v = parse_size(t);
        if (G.nsizes == MAX_SIZES || v < 4096 || v > (1u << 20) || (v & (v - 1))) {
            fprintf(stderr, "fs3-dedup-estimate: bad --block-sizes '%s'\n", sizes);
            free(list);
            return 2;
        }
        G.sizes[G.nsizes++] = (uint32_t)v;
    }
    free(list);
    if (!G.nsizes) { usage(stderr); return 2; }
    qsort(G.sizes, (size_t)G.nsizes, sizeof(uint32_t), cmp_u32);
    for (int i = 1; i < G.nsizes; i++)
        if (G.sizes[i] == G.sizes[i - 1]) { fprintf(stderr, "fs3-dedup-estimate: duplicate block size\n"); return 2; }
    if (G.max_mem < (16ULL << 20)) G.max_mem = 16ULL << 20;

    char p[4200];
    struct stat st;
    snprintf(p, sizeof(p), "%s/data", root);
    if (stat(p, &st) < 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "fs3-dedup-estimate: %s is not an fs3 data root (no data/ directory)\n", root);
        return 2;
    }

    G.bufsz = 1u << 20;                  /* multiple of every allowed block size */
    G.buf = malloc(G.bufsz);
    if (!G.buf) return 2;
    clock_gettime(CLOCK_MONOTONIC, &G.t0);
    G.last_progress = time(NULL);

    collect_buckets(root);
    if (G.only_bucket && G.nb == 0) {
        fprintf(stderr, "fs3-dedup-estimate: no bucket '%s' under %s\n", G.only_bucket, root);
        return 2;
    }
    for (size_t k = 0; k < G.nb; k++) {
        snprintf(p, sizeof(p), "%s/data/%s", root, G.b[k].name);
        walk(p, 2, k, 0);                               /* data/<b>/NN/NN/<hex> */
        if (!G.no_versions) {
            snprintf(p, sizeof(p), "%s/versions/%s", root, G.b[k].name);
            walk(p, 3, k, 1);                           /* versions/<b>/NN/NN/<hex>/<entry> */
        }
    }

    size_res_t res[MAX_SIZES];
    for (int i = 0; i < G.nsizes; i++) res[i] = analyse(i);
    report(res);
    return 0;
}
