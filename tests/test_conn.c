/* tests/test_conn.c — per-connection read path.
 *
 * Drives conn_on_readable() directly over a pipe (it only uses read(),
 * and a pipe's capacity can be raised past CONN_READ_BUDGET, unlike
 * socket buffers whose size depends on sysctls). The event loop isn't
 * involved: each conn_on_readable() call stands for one EPOLLIN event.
 */
#include "conn.h"
#include "log.h"
#include "store.h"

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
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

/* ---- Fixture: temp store + pipe carrying one request -------------- */

static char g_root[256];

static void rm_rf(const char *path) {
    DIR *d = opendir(path);
    if (!d) { unlink(path); return; }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char p[4096];
        snprintf(p, sizeof(p), "%s/%s", path, e->d_name);
        rm_rf(p);
    }
    closedir(d);
    rmdir(path);
}

static s3_store_t *setup_store(void) {
    snprintf(g_root, sizeof(g_root), "/tmp/fs3-conn-test.XXXXXX");
    char *r = mkdtemp(g_root);
    assert(r != NULL);
    s3_store_t *s = NULL;
    assert(store_open(&s, g_root) == S3_OK);
    assert(store_bucket_create(s, S3_STR_LIT("bkt")) == S3_OK);
    return s;
}

static void teardown_store(s3_store_t *s) {
    store_close(s);
    rm_rf(g_root);
}

/* Write "PUT /bkt/<key>" with a body_len-byte body into a fresh pipe and
 * return its read end (non-blocking). The whole request must fit in the
 * pipe so nothing is left for a writer thread to push later. */
static int pipe_with_put(const char *key, size_t body_len, size_t *total_out) {
    int fds[2];
    assert(pipe2(fds, O_NONBLOCK | O_CLOEXEC) == 0);
    int cap = fcntl(fds[1], F_SETPIPE_SZ, 1 << 20);
    assert(cap >= (1 << 20));

    char hdr[256];
    int hn = snprintf(hdr, sizeof(hdr),
                      "PUT /bkt/%s HTTP/1.1\r\nHost: x\r\n"
                      "Content-Length: %zu\r\n\r\n", key, body_len);
    size_t total = (size_t)hn + body_len;
    assert(total <= (size_t)cap);

    char *req = malloc(total);
    assert(req);
    memcpy(req, hdr, (size_t)hn);
    memset(req + hn, 'z', body_len);
    assert(write(fds[1], req, total) == (ssize_t)total);
    free(req);
    close(fds[1]);   /* peer done sending: EOF follows the request */

    *total_out = total;
    return fds[0];
}

static int pending(int fd) {
    int n = -1;
    assert(ioctl(fd, FIONREAD, &n) == 0);
    return n;
}

/* ---- Tests --------------------------------------------------------- */

/* A request bigger than the budget is consumed over several readable
 * events, each reading exactly CONN_READ_BUDGET, and still completes. */
static void t_read_budget_yields(void) {
    s3_store_t *s = setup_store();
    const size_t body = 3 * CONN_READ_BUDGET;
    size_t total;
    int fd = pipe_with_put("big", body, &total);
    conn_t *c = conn_create(fd, "test", s, NULL, 0, 0, NULL);

    CHECK_EQ(conn_on_readable(c), 0, "first event keeps conn open");
    CHECK(c->read_yielded, "first event yields at budget");
    CHECK_EQ(pending(fd), total - CONN_READ_BUDGET,
             "exactly one budget consumed from the fd");
    CHECK_EQ(c->state, CST_READ_BODY, "still mid-body");

    /* The peer has already closed its end. The server's hangup check
     * must not drop the connection with request bytes still unread. */
    CHECK_EQ(c->rlen, 0, "nothing left in rbuf (so only the flag holds it)");
    CHECK(!conn_hup_can_close(c), "hangup does not close a yielded conn");

    int events = 1;
    while (c->state != CST_WRITE_RESPONSE && events < 16) {
        CHECK_EQ(conn_on_readable(c), 0, "later events keep conn open");
        events++;
    }
    CHECK_EQ(c->state, CST_WRITE_RESPONSE, "request completes");
    CHECK_EQ(events, 4, "3 budgets of body + header remainder = 4 events");
    CHECK(!c->read_yielded, "final event did not yield");

    s3_obj_meta_t m;
    CHECK_EQ(store_head(s, S3_STR_LIT("bkt"), S3_STR_LIT("big"), &m), S3_OK,
             "object committed");
    CHECK_EQ(m.size, body, "full body stored");

    conn_destroy(c);
    close(fd);
    teardown_store(s);
}

/* A request under the budget is handled in one event, as before. */
static void t_small_request_one_event(void) {
    s3_store_t *s = setup_store();
    size_t total;
    int fd = pipe_with_put("small", 1000, &total);
    conn_t *c = conn_create(fd, "test", s, NULL, 0, 0, NULL);

    CHECK_EQ(conn_on_readable(c), 0, "event keeps conn open");
    CHECK(!c->read_yielded, "no yield under budget");
    CHECK_EQ(c->state, CST_WRITE_RESPONSE, "complete in one event");

    conn_destroy(c);
    close(fd);
    teardown_store(s);
}

int main(void) {
    log_init(LOG_WARN);

    t_read_budget_yields();
    t_small_request_one_event();

    if (failures) {
        fprintf(stderr, "%d FAILURES\n", failures);
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
