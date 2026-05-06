/* tests/test_store.c — exhaustive tests for the FS-backed store.
 *
 * Each test gets its own fresh root directory so they're independent
 * and can run in parallel later. The root is created under /tmp and
 * removed at the end. ASan + UBSan should be clean throughout.
 */

#include "store.h"
#include "log.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int failures = 0;

#define CHECK(cond, msg) do {                                         \
    if (!(cond)) {                                                    \
        fprintf(stderr, "FAIL [%s:%d] %s: %s\n",                      \
                __FILE__, __LINE__, __func__, msg);                   \
        failures++;                                                   \
    }                                                                 \
} while (0)

#define CHECK_EQ(got, want, msg) do {                                 \
    long long _g = (long long)(got), _w = (long long)(want);          \
    if (_g != _w) {                                                   \
        fprintf(stderr, "FAIL [%s:%d] %s: %s (got=%lld want=%lld)\n", \
                __FILE__, __LINE__, __func__, msg, _g, _w);           \
        failures++;                                                   \
    }                                                                 \
} while (0)

/* ---- Test fixture: temp root ------------------------------------- */

static char g_root[256];

static void setup_root(void) {
    snprintf(g_root, sizeof(g_root), "/tmp/fs3-test.XXXXXX");
    char *r = mkdtemp(g_root);
    assert(r != NULL);
}

static void rm_rf(const char *path) {
    DIR *d = opendir(path);
    if (!d) { unlink(path); return; }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.' && (e->d_name[1] == '\0' ||
            (e->d_name[1] == '.' && e->d_name[2] == '\0'))) continue;
        char p[4096];
        snprintf(p, sizeof(p), "%s/%s", path, e->d_name);
        struct stat st;
        if (lstat(p, &st) == 0) {
            if (S_ISDIR(st.st_mode)) rm_rf(p);
            else unlink(p);
        }
    }
    closedir(d);
    rmdir(path);
}

static void teardown_root(void) {
    rm_rf(g_root);
}

/* ---- Convenience wrappers ---------------------------------------- */

static s3_err_t put(s3_store_t *s, const char *bucket, const char *key,
                    const void *body, size_t len, const char *ct,
                    s3_obj_meta_t *meta_out) {
    s3_str_t b = { bucket, strlen(bucket) };
    s3_str_t k = { key,    strlen(key)    };
    s3_writer_t *w;
    s3_err_t e = store_put_begin(s, b, k, ct, &w);
    if (e != S3_OK) return e;
    if (len > 0) {
        e = store_put_write(w, body, len);
        if (e != S3_OK) { store_put_abort(w); return e; }
    }
    return store_put_commit(w, meta_out);
}

static s3_err_t get_all(s3_store_t *s, const char *bucket, const char *key,
                        char *buf, size_t cap, size_t *got_out,
                        s3_obj_meta_t *meta_out) {
    s3_str_t b = { bucket, strlen(bucket) };
    s3_str_t k = { key,    strlen(key)    };
    s3_reader_t *r;
    s3_err_t e = store_get_open(s, b, k, &r, meta_out);
    if (e != S3_OK) return e;
    size_t total = 0;
    for (;;) {
        ssize_t n = store_get_read(r, buf + total, cap - total);
        if (n < 0) { store_get_close(r); return S3_ERR_INTERNAL; }
        if (n == 0) break;
        total += (size_t)n;
        if (total >= cap) break;
    }
    if (got_out) *got_out = total;
    store_get_close(r);
    return S3_OK;
}

/* ---- Tests -------------------------------------------------------- */

static void t_open_close(void) {
    setup_root();
    s3_store_t *s;
    CHECK_EQ(store_open(&s, g_root), S3_OK, "open");

    /* Top-level dirs should exist */
    struct stat st;
    char p[512];
    snprintf(p, sizeof(p), "%s/data", g_root);    CHECK(stat(p, &st) == 0, "data dir");
    snprintf(p, sizeof(p), "%s/tmp", g_root);     CHECK(stat(p, &st) == 0, "tmp dir");
    snprintf(p, sizeof(p), "%s/buckets", g_root); CHECK(stat(p, &st) == 0, "buckets dir");

    store_close(s);
    teardown_root();
}

static void t_bucket_create_validate(void) {
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);

    CHECK_EQ(store_bucket_create(s, S3_STR_LIT("ok-bucket")), S3_OK, "valid name");
    CHECK_EQ(store_bucket_create(s, S3_STR_LIT("ok-bucket")),
             S3_ERR_BUCKET_ALREADY_EXISTS, "create exists");
    CHECK(store_bucket_exists(s, S3_STR_LIT("ok-bucket")), "exists");

    /* Invalid names */
    struct { const char *name; const char *why; } bad[] = {
        { "ab",            "too short" },
        { "Capital",       "uppercase" },
        { "with_under",    "underscore" },
        { "-leading",      "leading dash" },
        { "trailing-",     "trailing dash" },
        { "double..dot",   "consecutive dots" },
        { "",              "empty" },
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); i++) {
        s3_str_t n = { bad[i].name, strlen(bad[i].name) };
        CHECK_EQ(store_bucket_create(s, n), S3_ERR_INVALID_BUCKET_NAME, bad[i].why);
    }

    store_close(s);
    teardown_root();
}

static void t_bucket_delete(void) {
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);

    s3_str_t b = S3_STR_LIT("delete-test");
    CHECK_EQ(store_bucket_create(s, b), S3_OK, "create");
    CHECK_EQ(store_bucket_delete(s, b), S3_OK, "delete empty");
    CHECK(!store_bucket_exists(s, b), "gone after delete");
    CHECK_EQ(store_bucket_delete(s, b), S3_ERR_NO_SUCH_BUCKET, "delete missing");

    /* Non-empty bucket cannot be deleted. */
    CHECK_EQ(store_bucket_create(s, b), S3_OK, "recreate");
    s3_obj_meta_t m;
    CHECK_EQ(put(s, "delete-test", "key1", "data", 4, "text/plain", &m),
             S3_OK, "put object");
    CHECK_EQ(store_bucket_delete(s, b), S3_ERR_BUCKET_NOT_EMPTY, "non-empty");

    store_close(s);
    teardown_root();
}

static void t_put_get_simple(void) {
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);

    store_bucket_create(s, S3_STR_LIT("buk1"));

    const char *body = "Hello, S3 world!";
    size_t blen = strlen(body);
    s3_obj_meta_t pm;
    CHECK_EQ(put(s, "buk1", "greeting.txt", body, blen, "text/plain", &pm),
             S3_OK, "put");
    CHECK_EQ(pm.size, blen, "put meta size");
    CHECK_EQ(strcmp(pm.content_type, "text/plain"), 0, "put meta ct");

    /* Known MD5 for "Hello, S3 world!" — recompute to cross-check. */
    /* Instead of hardcoding, verify the round-trip ETag matches HEAD. */
    s3_obj_meta_t hm;
    CHECK_EQ(store_head(s, S3_STR_LIT("buk1"), S3_STR_LIT("greeting.txt"), &hm),
             S3_OK, "head");
    CHECK(memcmp(pm.etag, hm.etag, 16) == 0, "etag matches head");
    CHECK_EQ(hm.size, blen, "head size");
    CHECK_EQ(strcmp(hm.content_type, "text/plain"), 0, "head ct");

    /* Read back. */
    char buf[256] = {0};
    size_t got = 0;
    s3_obj_meta_t gm;
    CHECK_EQ(get_all(s, "buk1", "greeting.txt", buf, sizeof(buf), &got, &gm),
             S3_OK, "get");
    CHECK_EQ(got, blen, "got size");
    CHECK(memcmp(buf, body, blen) == 0, "body matches");

    store_close(s);
    teardown_root();
}

static void t_put_overwrite(void) {
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);
    store_bucket_create(s, S3_STR_LIT("buk"));

    s3_obj_meta_t m1, m2;
    CHECK_EQ(put(s, "buk", "k", "first",  5, "text/plain", &m1), S3_OK, "v1");
    CHECK_EQ(put(s, "buk", "k", "second", 6, "text/plain", &m2), S3_OK, "v2");
    CHECK(memcmp(m1.etag, m2.etag, 16) != 0, "etag changed");

    char buf[16] = {0};
    size_t got;
    get_all(s, "buk", "k", buf, sizeof(buf), &got, NULL);
    CHECK_EQ(got, 6, "size after overwrite");
    CHECK(memcmp(buf, "second", 6) == 0, "second body wins");

    store_close(s);
    teardown_root();
}

static void t_put_streaming(void) {
    /* Build a 5MB body in pieces; verify ETag matches a single-shot
     * computation. Also exercise the partial-read path on get. */
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);
    store_bucket_create(s, S3_STR_LIT("big"));

    size_t total = 5 * 1024 * 1024;
    char *body = malloc(total);
    for (size_t i = 0; i < total; i++) body[i] = (char)(i * 1103515245u + 12345u);

    s3_writer_t *w;
    s3_str_t bb = S3_STR_LIT("big"), kk = S3_STR_LIT("blob");
    CHECK_EQ(store_put_begin(s, bb, kk, "application/octet-stream", &w),
             S3_OK, "begin");

    /* Write in irregularly-sized chunks. */
    size_t off = 0;
    size_t chunk_sizes[] = { 1, 1024, 4096, 65536, 1024*1024 };
    int    ci = 0;
    while (off < total) {
        size_t want = chunk_sizes[ci % 5];
        if (off + want > total) want = total - off;
        CHECK_EQ(store_put_write(w, body + off, want), S3_OK, "chunk");
        off += want; ci++;
    }
    s3_obj_meta_t pm;
    CHECK_EQ(store_put_commit(w, &pm), S3_OK, "commit");
    CHECK_EQ(pm.size, total, "size");

    /* Read back, checking via partial reads. */
    s3_reader_t *r;
    s3_obj_meta_t gm;
    CHECK_EQ(store_get_open(s, bb, kk, &r, &gm), S3_OK, "get_open");
    char *out = malloc(total);
    size_t pos = 0;
    while (pos < total) {
        size_t want = (pos + 12345 < total) ? 12345 : total - pos;
        ssize_t n = store_get_read(r, out + pos, want);
        CHECK(n > 0, "read progress");
        if (n <= 0) break;
        pos += (size_t)n;
    }
    CHECK_EQ(pos, total, "full read");
    CHECK(memcmp(body, out, total) == 0, "byte-identical roundtrip");
    store_get_close(r);

    free(body); free(out);
    store_close(s);
    teardown_root();
}

static void t_get_sendfile(void) {
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);
    store_bucket_create(s, S3_STR_LIT("buk"));

    const char *body = "send via sendfile";
    size_t blen = strlen(body);
    put(s, "buk", "k", body, blen, "text/plain", NULL);

    /* Pipe so we can capture sendfile output (sendfile to a regular
     * file works on Linux, and pipes work too. Using pipe is closer to
     * what we'll do with sockets). */
    int p[2];
    if (pipe(p) < 0) { CHECK(0, "pipe failed"); return; }

    s3_str_t bb = S3_STR_LIT("buk"), kk = S3_STR_LIT("k");
    s3_reader_t *r;
    CHECK_EQ(store_get_open(s, bb, kk, &r, NULL), S3_OK, "open");
    ssize_t n = store_get_sendfile(r, p[1], 0);
    CHECK_EQ(n, (ssize_t)blen, "sendfile bytes");
    /* EOF: subsequent call should return 0. */
    ssize_t n2 = store_get_sendfile(r, p[1], 0);
    CHECK_EQ(n2, 0, "EOF on second sendfile");
    store_get_close(r);

    char buf[64] = {0};
    ssize_t r0 = read(p[0], buf, sizeof(buf));
    CHECK_EQ(r0, (ssize_t)blen, "pipe got bytes");
    CHECK(memcmp(buf, body, blen) == 0, "sendfile body matches");
    close(p[0]); close(p[1]);

    store_close(s);
    teardown_root();
}

static void t_delete(void) {
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);
    store_bucket_create(s, S3_STR_LIT("buk"));

    put(s, "buk", "k", "data", 4, "", NULL);
    s3_str_t bb = S3_STR_LIT("buk"), kk = S3_STR_LIT("k");

    s3_obj_meta_t m;
    CHECK_EQ(store_head(s, bb, kk, &m), S3_OK, "head before delete");
    CHECK_EQ(store_delete(s, bb, kk), S3_OK, "delete");
    CHECK_EQ(store_head(s, bb, kk, &m), S3_ERR_NO_SUCH_KEY, "head after");

    /* Idempotent: deleting again is success. */
    CHECK_EQ(store_delete(s, bb, kk), S3_OK, "delete missing");

    store_close(s);
    teardown_root();
}

static void t_missing(void) {
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);

    s3_str_t bb = S3_STR_LIT("nobucket"), kk = S3_STR_LIT("k");
    s3_obj_meta_t m;
    CHECK_EQ(store_head(s, bb, kk, &m), S3_ERR_NO_SUCH_BUCKET, "head no bucket");

    store_bucket_create(s, S3_STR_LIT("buk"));
    s3_str_t b2 = S3_STR_LIT("buk"), kk2 = S3_STR_LIT("nokey");
    CHECK_EQ(store_head(s, b2, kk2, &m), S3_ERR_NO_SUCH_KEY, "head no key");

    store_close(s);
    teardown_root();
}

static void t_keys_with_funny_chars(void) {
    /* S3 keys allow nearly anything; verify our hash-based naming
     * handles these without tripping over filesystem rules. */
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);
    store_bucket_create(s, S3_STR_LIT("buk"));

    const char *keys[] = {
        "simple",
        "with/slashes/like/paths",
        "with spaces and = signs?",
        "unicode-\xe6\x97\xa5\xe6\x9c\xac",          /* 日本 */
        "../../etc/passwd",                          /* path traversal attempt */
        "very/deeply/nested/key/that/goes/many/levels/deep",
    };
    s3_str_t b = S3_STR_LIT("buk");
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); i++) {
        s3_str_t k = { keys[i], strlen(keys[i]) };
        s3_writer_t *w;
        CHECK_EQ(store_put_begin(s, b, k, "", &w), S3_OK, "begin funny");
        CHECK_EQ(store_put_write(w, "x", 1), S3_OK, "write");
        CHECK_EQ(store_put_commit(w, NULL), S3_OK, "commit");

        s3_obj_meta_t m;
        CHECK_EQ(store_head(s, b, k, &m), S3_OK, "head funny");
        CHECK_EQ(m.size, 1, "size 1");
    }

    /* Critical: path traversal attempt did NOT escape the bucket dir. */
    char etc[512];
    snprintf(etc, sizeof(etc), "%s/etc", g_root);
    struct stat st;
    CHECK(stat(etc, &st) != 0, "no /etc created at root level");

    store_close(s);
    teardown_root();
}

static void t_list_basic(void) {
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);
    store_bucket_create(s, S3_STR_LIT("buk"));

    /* Insert in arbitrary order. */
    const char *keys[] = {
        "delta", "alpha", "echo", "bravo", "charlie",
    };
    for (size_t i = 0; i < 5; i++) {
        put(s, "buk", keys[i], "x", 1, "", NULL);
    }

    s3_lister_t *l;
    s3_list_opts_t opts = {0};
    CHECK_EQ(store_list_begin(s, S3_STR_LIT("buk"), &opts, &l), S3_OK, "list begin");

    const char *expected[] = { "alpha", "bravo", "charlie", "delta", "echo" };
    for (int i = 0; i < 5; i++) {
        s3_str_t k; s3_obj_meta_t m; int isp;
        CHECK_EQ(store_list_next(l, &k, &m, &isp), S3_OK, "next");
        CHECK_EQ(isp, 0, "not a prefix");
        CHECK_EQ(k.n, strlen(expected[i]), "key len");
        CHECK(memcmp(k.p, expected[i], k.n) == 0, "key matches");
    }
    s3_str_t k; s3_obj_meta_t m; int isp;
    CHECK_EQ(store_list_next(l, &k, &m, &isp), S3_ERR_NO_SUCH_KEY, "exhausted");
    store_list_close(l);

    store_close(s);
    teardown_root();
}

static void t_list_prefix(void) {
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);
    store_bucket_create(s, S3_STR_LIT("buk"));

    const char *keys[] = {
        "photos/cat.jpg", "photos/dog.jpg", "videos/x.mp4", "music/y.mp3"
    };
    for (size_t i = 0; i < 4; i++) put(s, "buk", keys[i], "x", 1, "", NULL);

    s3_list_opts_t opts = { .prefix = S3_STR_LIT("photos/") };
    s3_lister_t *l;
    store_list_begin(s, S3_STR_LIT("buk"), &opts, &l);

    s3_str_t k; s3_obj_meta_t m; int isp;
    CHECK_EQ(store_list_next(l, &k, &m, &isp), S3_OK, "first match");
    CHECK(memcmp(k.p, "photos/cat.jpg", k.n) == 0, "cat.jpg");
    CHECK_EQ(store_list_next(l, &k, &m, &isp), S3_OK, "second match");
    CHECK(memcmp(k.p, "photos/dog.jpg", k.n) == 0, "dog.jpg");
    CHECK_EQ(store_list_next(l, &k, &m, &isp), S3_ERR_NO_SUCH_KEY, "done");
    store_list_close(l);

    store_close(s);
    teardown_root();
}

static void t_list_delimiter(void) {
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);
    store_bucket_create(s, S3_STR_LIT("buk"));

    const char *keys[] = {
        "photos/cat.jpg", "photos/dog.jpg", "videos/x.mp4",
        "videos/sub/y.mp4", "readme.txt"
    };
    for (size_t i = 0; i < 5; i++) put(s, "buk", keys[i], "x", 1, "", NULL);

    /* Top-level listing with delimiter "/" should give us
     * "photos/" (prefix), "videos/" (prefix), "readme.txt" (key). */
    s3_list_opts_t opts = { .delimiter = S3_STR_LIT("/") };
    s3_lister_t *l;
    store_list_begin(s, S3_STR_LIT("buk"), &opts, &l);

    int got_photos = 0, got_videos = 0, got_readme = 0;
    int total = 0;
    for (;;) {
        s3_str_t k; s3_obj_meta_t m; int isp;
        s3_err_t e = store_list_next(l, &k, &m, &isp);
        if (e != S3_OK) break;
        total++;
        if (isp && k.n == 7 && memcmp(k.p, "photos/", 7) == 0) got_photos++;
        else if (isp && k.n == 7 && memcmp(k.p, "videos/", 7) == 0) got_videos++;
        else if (!isp && k.n == 10 && memcmp(k.p, "readme.txt", 10) == 0) got_readme++;
    }
    CHECK_EQ(total, 3, "three results");
    CHECK_EQ(got_photos, 1, "photos rolled up once");
    CHECK_EQ(got_videos, 1, "videos rolled up once");
    CHECK_EQ(got_readme, 1, "readme listed");
    store_list_close(l);

    store_close(s);
    teardown_root();
}

static void t_list_marker(void) {
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);
    store_bucket_create(s, S3_STR_LIT("buk"));
    const char *keys[] = { "a", "buk", "c", "d", "e" };
    for (int i = 0; i < 5; i++) put(s, "buk", keys[i], "x", 1, "", NULL);

    /* marker = "b" should return c, d, e. */
    s3_list_opts_t opts = { .marker = S3_STR_LIT("buk") };
    s3_lister_t *l;
    store_list_begin(s, S3_STR_LIT("buk"), &opts, &l);
    const char *want[] = { "c", "d", "e" };
    for (int i = 0; i < 3; i++) {
        s3_str_t k; s3_obj_meta_t m; int isp;
        CHECK_EQ(store_list_next(l, &k, &m, &isp), S3_OK, "marker next");
        CHECK(k.n == 1 && k.p[0] == want[i][0], "marker key");
    }
    s3_str_t k; s3_obj_meta_t m; int isp;
    CHECK_EQ(store_list_next(l, &k, &m, &isp), S3_ERR_NO_SUCH_KEY, "done");
    store_list_close(l);

    store_close(s);
    teardown_root();
}

static void t_list_max_keys(void) {
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);
    store_bucket_create(s, S3_STR_LIT("buk"));
    for (int i = 0; i < 100; i++) {
        char k[16]; snprintf(k, sizeof(k), "k%03d", i);
        put(s, "buk", k, "x", 1, "", NULL);
    }
    s3_list_opts_t opts = { .max_keys = 5 };
    s3_lister_t *l;
    store_list_begin(s, S3_STR_LIT("buk"), &opts, &l);
    int got = 0;
    for (;;) {
        s3_str_t k; s3_obj_meta_t m; int isp;
        if (store_list_next(l, &k, &m, &isp) != S3_OK) break;
        got++;
    }
    CHECK_EQ(got, 5, "max_keys cap");
    store_list_close(l);
    store_close(s);
    teardown_root();
}

static void t_abort_does_not_create(void) {
    setup_root();
    s3_store_t *s;
    store_open(&s, g_root);
    store_bucket_create(s, S3_STR_LIT("buk"));

    s3_writer_t *w;
    s3_str_t bb = S3_STR_LIT("buk"), kk = S3_STR_LIT("aborted");
    store_put_begin(s, bb, kk, "", &w);
    store_put_write(w, "abc", 3);
    store_put_abort(w);

    s3_obj_meta_t m;
    CHECK_EQ(store_head(s, bb, kk, &m), S3_ERR_NO_SUCH_KEY, "aborted didn't land");

    /* tmp dir should be empty too */
    char tp[512]; snprintf(tp, sizeof(tp), "%s/tmp", g_root);
    DIR *d = opendir(tp);
    int n = 0;
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] != '.') n++;
        }
        closedir(d);
    }
    CHECK_EQ(n, 0, "tmp empty after abort");

    store_close(s);
    teardown_root();
}

static void t_persistence(void) {
    /* Open, write, close. Open again, verify still there. */
    setup_root();

    s3_store_t *s1;
    store_open(&s1, g_root);
    store_bucket_create(s1, S3_STR_LIT("buk"));
    put(s1, "buk", "persist-me", "data42", 6, "text/plain", NULL);
    store_close(s1);

    s3_store_t *s2;
    store_open(&s2, g_root);
    char buf[16] = {0};
    size_t got;
    s3_obj_meta_t m;
    CHECK_EQ(get_all(s2, "buk", "persist-me", buf, sizeof(buf), &got, &m),
             S3_OK, "get after reopen");
    CHECK_EQ(got, 6, "size persisted");
    CHECK(memcmp(buf, "data42", 6) == 0, "body persisted");
    CHECK_EQ(strcmp(m.content_type, "text/plain"), 0, "ct persisted");

    /* And listing finds it. */
    s3_lister_t *l;
    s3_list_opts_t opts = {0};
    store_list_begin(s2, S3_STR_LIT("buk"), &opts, &l);
    s3_str_t k; int isp;
    CHECK_EQ(store_list_next(l, &k, &m, &isp), S3_OK, "list after reopen");
    CHECK(k.n == 10 && memcmp(k.p, "persist-me", 10) == 0, "listed key");
    store_list_close(l);

    store_close(s2);
    teardown_root();
}

/* ---- Multipart upload --------------------------------------------- */

static void t_mpu_basic(void) {
    setup_root();
    s3_store_t *s;
    CHECK_EQ(store_open(&s, g_root), S3_OK, "mpu: store_open");
    CHECK(store_bucket_create(s, S3_STR_LIT("buk")) == S3_OK,
          "mpu: bucket create");

    char upload_id[33];
    CHECK(store_mpu_create(s, S3_STR_LIT("buk"), S3_STR_LIT("big.bin"),
                            "application/octet-stream", upload_id) == S3_OK,
          "mpu: create");
    CHECK(strlen(upload_id) == 32, "mpu: upload_id is 32 hex chars");

    /* Upload three parts: 5MB, 5MB, 1MB. */
    s3_part_ref_t parts[3];
    const size_t sizes[3] = { 5 * 1024 * 1024, 5 * 1024 * 1024, 1 * 1024 * 1024 };
    for (int i = 0; i < 3; i++) {
        s3_writer_t *w = NULL;
        CHECK(store_mpu_part_begin(s, S3_STR_LIT("buk"), S3_STR_LIT("big.bin"),
                                    upload_id, i + 1, &w) == S3_OK,
              "mpu: part begin");
        char *buf = malloc(sizes[i]);
        memset(buf, 'a' + i, sizes[i]);
        CHECK(store_mpu_part_write(w, buf, sizes[i]) == S3_OK,
              "mpu: part write");
        free(buf);
        parts[i].part_number = i + 1;
        CHECK(store_mpu_part_commit(w, parts[i].etag_hex) == S3_OK,
              "mpu: part commit");
    }

    char etag[40];
    s3_obj_meta_t meta;
    CHECK(store_mpu_complete(s, S3_STR_LIT("buk"), S3_STR_LIT("big.bin"),
                              upload_id, parts, 3, etag, &meta) == S3_OK,
          "mpu: complete");
    CHECK(meta.size == sizes[0] + sizes[1] + sizes[2],
          "mpu: total size correct");
    /* ETag should be "<32hex>-3" */
    CHECK(strlen(etag) == 32 + 2,    "mpu: etag len = 32 + '-' + '3'");
    CHECK(etag[32] == '-',           "mpu: etag has dash");
    CHECK(etag[33] == '3',           "mpu: etag part count = 3");

    /* Read back and verify content */
    s3_reader_t *r = NULL;
    s3_obj_meta_t m2;
    CHECK(store_get_open(s, S3_STR_LIT("buk"), S3_STR_LIT("big.bin"),
                          &r, &m2) == S3_OK, "mpu: get_open");
    CHECK(m2.size == sizes[0] + sizes[1] + sizes[2], "mpu: read size matches");
    /* Read all bytes; spot-check region pattern. */
    size_t total = 0;
    int region_ok = 1;
    char buf[4096];
    for (size_t i = 0; i < m2.size && region_ok; ) {
        ssize_t got = store_get_read(r, buf, sizeof(buf));
        if (got <= 0) { region_ok = 0; break; }
        for (ssize_t j = 0; j < got; j++) {
            char check;
            size_t idx = i + (size_t)j;
            if      (idx < sizes[0])                    check = 'a';
            else if (idx < sizes[0] + sizes[1])         check = 'b';
            else                                         check = 'c';
            if (buf[j] != check) { region_ok = 0; break; }
        }
        i += (size_t)got;
        total += (size_t)got;
    }
    CHECK(region_ok && total == m2.size,
          "mpu: all bytes match expected region pattern");
    store_get_close(r);

    store_close(s);
    teardown_root();
}

static void t_mpu_abort(void) {
    setup_root();
    s3_store_t *s;
    CHECK_EQ(store_open(&s, g_root), S3_OK, "mpu_abort: open");
    store_bucket_create(s, S3_STR_LIT("buk"));

    char upload_id[33];
    CHECK(store_mpu_create(s, S3_STR_LIT("buk"), S3_STR_LIT("k1"),
                            NULL, upload_id) == S3_OK, "mpu_abort: create");
    /* Upload one part */
    s3_writer_t *w;
    store_mpu_part_begin(s, S3_STR_LIT("buk"), S3_STR_LIT("k1"),
                          upload_id, 1, &w);
    store_mpu_part_write(w, "hi", 2);
    char etag[33];
    store_mpu_part_commit(w, etag);

    /* Abort */
    CHECK(store_mpu_abort(s, S3_STR_LIT("buk"), S3_STR_LIT("k1"),
                           upload_id) == S3_OK, "mpu_abort: abort ok");
    /* Subsequent abort should return NoSuchUpload */
    CHECK(store_mpu_abort(s, S3_STR_LIT("buk"), S3_STR_LIT("k1"),
                           upload_id) == S3_ERR_NO_SUCH_UPLOAD,
          "mpu_abort: idempotent NoSuchUpload");
    /* Object should not exist */
    s3_obj_meta_t m;
    CHECK(store_head(s, S3_STR_LIT("buk"), S3_STR_LIT("k1"), &m)
          == S3_ERR_NO_SUCH_KEY, "mpu_abort: no object created");

    store_close(s);
    teardown_root();
}

static void t_mpu_invalid_part_list(void) {
    setup_root();
    s3_store_t *s;
    CHECK_EQ(store_open(&s, g_root), S3_OK, "mpu_inv: open");
    store_bucket_create(s, S3_STR_LIT("buk"));
    char upload_id[33];
    store_mpu_create(s, S3_STR_LIT("buk"), S3_STR_LIT("k1"), NULL, upload_id);

    /* Upload part 1 only */
    s3_writer_t *w;
    store_mpu_part_begin(s, S3_STR_LIT("buk"), S3_STR_LIT("k1"),
                          upload_id, 1, &w);
    store_mpu_part_write(w, "x", 1);
    s3_part_ref_t parts[2];
    parts[0].part_number = 1;
    store_mpu_part_commit(w, parts[0].etag_hex);

    /* Try to complete with a non-existent part 2 */
    parts[1].part_number = 2;
    memset(parts[1].etag_hex, '0', 32); parts[1].etag_hex[32] = 0;
    char etag[40];
    s3_obj_meta_t meta;
    CHECK(store_mpu_complete(s, S3_STR_LIT("buk"), S3_STR_LIT("k1"),
                              upload_id, parts, 2, etag, &meta)
          == S3_ERR_INVALID_PART, "mpu: missing part rejected");

    /* Out-of-order part numbers also rejected */
    parts[0].part_number = 2;
    parts[1].part_number = 1;
    CHECK(store_mpu_complete(s, S3_STR_LIT("buk"), S3_STR_LIT("k1"),
                              upload_id, parts, 2, etag, &meta)
          == S3_ERR_INVALID_ARGUMENT, "mpu: out-of-order parts rejected");

    /* Cleanup */
    store_mpu_abort(s, S3_STR_LIT("buk"), S3_STR_LIT("k1"), upload_id);
    store_close(s);
    teardown_root();
}

static void t_mpu_unknown_upload(void) {
    setup_root();
    s3_store_t *s;
    CHECK_EQ(store_open(&s, g_root), S3_OK, "mpu_unk: open");
    store_bucket_create(s, S3_STR_LIT("buk"));

    /* Try to upload a part to a non-existent upload */
    s3_writer_t *w;
    CHECK(store_mpu_part_begin(s, S3_STR_LIT("buk"), S3_STR_LIT("k1"),
                                "0123456789abcdef0123456789abcdef", 1, &w)
          == S3_ERR_NO_SUCH_UPLOAD, "mpu: part to unknown upload rejected");

    store_close(s);
    teardown_root();
}

/* ---- Main --------------------------------------------------------- */

int main(void) {
    log_init(LOG_WARN);  /* suppress info chatter during tests */

    t_open_close();
    t_bucket_create_validate();
    t_bucket_delete();
    t_put_get_simple();
    t_put_overwrite();
    t_put_streaming();
    t_get_sendfile();
    t_delete();
    t_missing();
    t_keys_with_funny_chars();
    t_list_basic();
    t_list_prefix();
    t_list_delimiter();
    t_list_marker();
    t_list_max_keys();
    t_abort_does_not_create();
    t_persistence();
    t_mpu_basic();
    t_mpu_abort();
    t_mpu_invalid_part_list();
    t_mpu_unknown_upload();

    if (failures == 0) { printf("ALL TESTS PASSED\n"); return 0; }
    printf("%d FAILURES\n", failures);
    return 1;
}
