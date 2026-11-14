/* tests/test_objmeta.c — user metadata / standard header TLVs (round 2,
 * item 1e), plus a fuzz run of objmeta_walk / objmeta_copy_filter over
 * random and mutated areas: `./tests/test_objmeta [iterations]`. */
#include "objmeta.h"
#include "store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pass, fail;
#define CHECK(c, msg) do { if (c) pass++; else { fail++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); } } while (0)
#define H(k, v) { { k, sizeof(k) - 1 }, { v, sizeof(v) - 1 } }

typedef struct { char out[8192]; size_t n; int count; } acc_t;
static int acc(void *ctx, int id, const char *name, const char *value) {
    (void)id;
    acc_t *a = ctx;
    a->n += (size_t)snprintf(a->out + a->n, sizeof(a->out) - a->n, "%s: %s\n", name, value);
    a->count++;
    return 0;
}

static void t_roundtrip(void) {
    objmeta_hdr_t h[] = {
        H("x-amz-meta-Color", "red"), H("content-type", "text/plain"),
        H("cache-control", "max-age=60"), H("x-amz-meta-color", "blue"),
        H("content-encoding", "aws-chunked, gzip"), H("x-amz-meta-mtime", "1700000000.5"),
        H("content-disposition", "attachment; filename=\"a b.txt\""),
        H("expires", "Wed, 21 Oct 2026 07:28:00 GMT"), H("content-language", "ro"),
        H("x-amz-meta-utf", "\xc8\x99"),
    };
    uint8_t *t; size_t n;
    CHECK(objmeta_from_headers(h, sizeof(h)/sizeof(h[0]), &t, &n) == S3_OK, "build");
    acc_t a = { .n = 0 };
    CHECK(objmeta_walk(t, n, 1, ~0u, acc, &a) == 0, "walk");
    CHECK(strstr(a.out, "x-amz-meta-color: red,blue\n") != NULL, "dup joined, name lower-cased");
    CHECK(strstr(a.out, "x-amz-meta-mtime: 1700000000.5\n") != NULL, "mtime");
    CHECK(strstr(a.out, "x-amz-meta-utf: \xc8\x99\n") != NULL, "utf-8 unchanged");
    CHECK(strstr(a.out, "Cache-Control: max-age=60\n") != NULL, "cache-control");
    CHECK(strstr(a.out, "Content-Encoding: gzip\n") != NULL, "aws-chunked stripped");
    CHECK(strstr(a.out, "Content-Disposition: attachment; filename=\"a b.txt\"\n") != NULL, "cd");
    CHECK(strstr(a.out, "Expires: Wed, 21 Oct 2026 07:28:00 GMT\n") != NULL, "expires");
    CHECK(strstr(a.out, "Content-Language: ro\n") != NULL, "lang");
    CHECK(a.count == 8, "count");
    /* Website subset: no user meta, no Content-Disposition. */
    acc_t w = { .n = 0 };
    unsigned mask = 1u << OBJMETA_CACHE_CONTROL | 1u << OBJMETA_CONTENT_ENCODING
                  | 1u << OBJMETA_CONTENT_LANGUAGE | 1u << OBJMETA_EXPIRES;
    objmeta_walk(t, n, 0, mask, acc, &w);
    CHECK(w.count == 4 && !strstr(w.out, "x-amz-meta") && !strstr(w.out, "Disposition"), "website subset");
    /* Copy filter keeps metadata and unknown types, drops byte-describing ones. */
    uint8_t ext[512]; size_t en = 0;
    memcpy(ext, t, n); en = n;
    uint8_t sha[6 + 32] = { S3_TLV_CONTENT_SHA256, 0, 32, 0, 0, 0 };
    memcpy(ext + en, sha, sizeof(sha)); en += sizeof(sha);
    uint8_t unk[6 + 3] = { 0x77, 0, 3, 0, 0, 0, 'a', 'b', 'c' };
    memcpy(ext + en, unk, sizeof(unk)); en += sizeof(unk);
    uint8_t *f; size_t fn;
    CHECK(objmeta_copy_filter(ext, en, &f, &fn) == 0, "filter");
    CHECK(fn == n + sizeof(unk) && memcmp(f, t, n) == 0 && memcmp(f + n, unk, sizeof(unk)) == 0, "filter result");
    free(f);
    free(t);
}

static void t_limits(void) {
    static char big[4096];
    memset(big, 'v', sizeof(big));
    /* name "k" (1) + value 2047 = 2048: exactly at the limit. */
    objmeta_hdr_t h1[] = { { { "x-amz-meta-k", 12 }, { big, 2047 } } };
    uint8_t *t; size_t n;
    CHECK(objmeta_from_headers(h1, 1, &t, &n) == S3_OK, "2048 ok");
    free(t);
    objmeta_hdr_t h2[] = { { { "x-amz-meta-k", 12 }, { big, 2048 } } };
    CHECK(objmeta_from_headers(h2, 1, &t, &n) == S3_ERR_METADATA_TOO_LARGE, "2049 refused");
    objmeta_hdr_t h3[] = { H("x-amz-meta-a", "x\r\nSet-Cookie: y") };
    CHECK(objmeta_from_headers(h3, 1, &t, &n) == S3_ERR_INVALID_ARGUMENT, "CRLF refused");
    objmeta_hdr_t h4[] = { { { "x-amz-meta-a", 12 }, { "x\0y", 3 } } };
    CHECK(objmeta_from_headers(h4, 1, &t, &n) == S3_ERR_INVALID_ARGUMENT, "NUL refused");
    objmeta_hdr_t h5[] = { H("x-amz-meta-a b", "x") };
    CHECK(objmeta_from_headers(h5, 1, &t, &n) == S3_ERR_INVALID_ARGUMENT, "bad name");
    objmeta_hdr_t h6[] = { H("cache-control", "a\x01") };
    CHECK(objmeta_from_headers(h6, 1, &t, &n) == S3_ERR_INVALID_ARGUMENT, "ctl char");
    objmeta_hdr_t h7[] = { H("x-amz-meta-a", "\xc0\x80") };
    CHECK(objmeta_from_headers(h7, 1, &t, &n) == S3_ERR_INVALID_ARGUMENT, "overlong utf-8");
    objmeta_hdr_t h8[] = { H("x-amz-meta-a", "tab\there") };
    CHECK(objmeta_from_headers(h8, 1, &t, &n) == S3_OK, "HTAB ok");
    free(t);
    objmeta_hdr_t h9[] = { H("content-encoding", "aws-chunked") };
    CHECK(objmeta_from_headers(h9, 1, &t, &n) == S3_OK && t == NULL && n == 0, "only aws-chunked → nothing");
    CHECK(objmeta_from_headers(NULL, 0, &t, &n) == S3_OK && t == NULL, "empty");
}

static void t_disk_untrusted(void) {
    /* A record whose value carries CR LF must emit nothing at all. */
    uint8_t bad[] = { S3_TLV_USER_META, 0, 9, 0, 0, 0, 1, 0, 4, 0, 'a', 'x', '\r', '\n', 'y' };
    acc_t a = { .n = 0 };
    CHECK(objmeta_walk(bad, sizeof(bad), 1, ~0u, acc, &a) == -1 && a.count == 0, "CRLF on disk");
    /* Valid first record, corrupt second: still nothing. */
    uint8_t mix[] = { S3_TLV_USER_META, 0, 6, 0, 0, 0, 1, 0, 1, 0, 'a', 'b',
                      S3_TLV_STD_HEADERS, 0, 3, 0, 0, 0, 9, 0, 0 };
    a.count = 0;
    CHECK(objmeta_walk(mix, sizeof(mix), 1, ~0u, acc, &a) == -1 && a.count == 0, "atomic emit");
    uint8_t upper[] = { S3_TLV_USER_META, 0, 6, 0, 0, 0, 1, 0, 1, 0, 'A', 'b' };
    CHECK(objmeta_walk(upper, sizeof(upper), 1, ~0u, acc, &a) == -1, "upper-case name on disk");
}

static uint64_t rng = 0x9E3779B97F4A7C15ull;
static uint32_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (uint32_t)rng; }

static int fuzz_cb(void *ctx, int id, const char *name, const char *value) {
    (void)ctx; (void)id;
    /* Whatever reaches the response must be header-safe. */
    if (strpbrk(name, "\r\n: ") || strpbrk(value, "\r\n")) abort();
    return 0;
}

static void fuzz(long iters) {
    uint8_t seed[256]; size_t sn;
    {
        objmeta_hdr_t h[] = { H("x-amz-meta-a", "1"), H("cache-control", "no-cache"),
                              H("x-amz-meta-bb", "22") };
        uint8_t *t;
        objmeta_from_headers(h, 3, &t, &sn);
        memcpy(seed, t, sn);
        free(t);
    }
    uint8_t buf[512];
    for (long i = 0; i < iters; i++) {
        size_t n;
        if (rnd() & 1) {
            n = sn;
            memcpy(buf, seed, sn);
            int muts = 1 + (int)(rnd() % 4);
            for (int m = 0; m < muts; m++) buf[rnd() % n] = (uint8_t)rnd();
            if (rnd() % 4 == 0) n = rnd() % (n + 1);
        } else {
            n = rnd() % sizeof(buf);
            for (size_t k = 0; k < n; k++) buf[k] = (uint8_t)rnd();
            if (n >= 6 && rnd() & 1) { buf[0] = (uint8_t)(1 + rnd() % 2); buf[1] = 0; }
        }
        uint8_t *heap = malloc(n ? n : 1);     /* exact size: ASan sees overreads */
        memcpy(heap, buf, n);
        objmeta_walk(heap, n, 1, ~0u, fuzz_cb, NULL);
        uint8_t *f; size_t fn;
        if (objmeta_copy_filter(heap, n, &f, &fn) == 0) free(f);
        free(heap);
        /* And random request headers through the builder. */
        char kv[64], vv[64];
        size_t kn = rnd() % 20, vn = rnd() % 60;
        memcpy(kv, "x-amz-meta-", 11);
        for (size_t k = 11; k < 11 + kn; k++) kv[k] = (char)(rnd() & 0xff);
        for (size_t k = 0; k < vn; k++) vv[k] = (char)(rnd() & 0xff);
        objmeta_hdr_t hh[1] = { { { kv, 11 + kn }, { vv, vn } } };
        uint8_t *t; size_t tn;
        if (objmeta_from_headers(hh, 1, &t, &tn) == S3_OK) {
            if (objmeta_walk(t, tn, 1, ~0u, fuzz_cb, NULL) != 0) abort();   /* built ⇒ walkable */
            free(t);
        }
    }
    pass++;
}

int main(int argc, char **argv) {
    t_roundtrip();
    t_limits();
    t_disk_untrusted();
    fuzz(argc > 1 ? atol(argv[1]) : 2000);
    printf("%d passed, %d failed\n", pass, fail);
    if (fail) return 1;
    printf("ALL TESTS PASSED\n");
    return 0;
}
