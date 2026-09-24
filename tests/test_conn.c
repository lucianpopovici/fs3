/* tests/test_conn.c — per-connection request path.
 *
 * Drives conn_on_readable() directly over a pipe (it only uses read(),
 * and a pipe's capacity can be raised past CONN_READ_BUDGET, unlike
 * socket buffers whose size depends on sysctls). The event loop isn't
 * involved: each conn_on_readable() call stands for one EPOLLIN event,
 * and the test thread plays the loop thread for iopool_reap().
 */
#include "conn.h"
#include "iopool.h"
#include "log.h"
#include "store.h"

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <time.h>
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

/* Put `n` bytes of `req` into a fresh 1 MB pipe, close the write end,
 * and return the (non-blocking) read end. */
static int pipe_with(const char *req, size_t n) {
    int fds[2];
    assert(pipe2(fds, O_NONBLOCK | O_CLOEXEC) == 0);
    int cap = fcntl(fds[1], F_SETPIPE_SZ, 1 << 20);
    assert(cap >= (1 << 20) && n <= (size_t)cap);
    assert(write(fds[1], req, n) == (ssize_t)n);
    close(fds[1]);
    return fds[0];
}

/* Write "PUT /bkt/<key>" with a body_len-byte body into a fresh pipe and
 * return its read end (non-blocking). The whole request must fit in the
 * pipe so nothing is left for a writer thread to push later. */
static int pipe_with_put(const char *key, size_t body_len, size_t *total_out) {
    int cap = 1 << 20;

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
    int fd = pipe_with(req, total);   /* peer done sending: EOF follows */
    free(req);

    *total_out = total;
    return fd;
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
    conn_t *c = conn_create(fd, "test", s, NULL, NULL, 0, 0, NULL);

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
    conn_t *c = conn_create(fd, "test", s, NULL, NULL, 0, 0, NULL);

    CHECK_EQ(conn_on_readable(c), 0, "event keeps conn open");
    CHECK(!c->read_yielded, "no yield under budget");
    CHECK_EQ(c->state, CST_WRITE_RESPONSE, "complete in one event");

    conn_destroy(c);
    close(fd);
    teardown_store(s);
}

/* ---- iopool: blocking work runs off the loop thread ---------------- */

/* fsync hook that parks the calling (worker) thread until released, so a
 * test can observe the loop thread while a commit is mid-fsync. */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_cv = PTHREAD_COND_INITIALIZER;
static int             g_block;
static int             g_entered;
static pthread_t       g_loop_thread;
static int             g_fsync_on_loop;

static int blocking_fsync(int fd) {
    pthread_mutex_lock(&g_mu);
    if (pthread_equal(pthread_self(), g_loop_thread)) {
        /* Regression: fsync on the loop. Record it; blocking here would
         * deadlock the test instead of failing it. */
        g_fsync_on_loop = 1;
        pthread_mutex_unlock(&g_mu);
        return fsync(fd);
    }
    g_entered++;
    pthread_cond_broadcast(&g_cv);
    while (g_block) pthread_cond_wait(&g_cv, &g_mu);
    pthread_mutex_unlock(&g_mu);
    return fsync(fd);
}

static void hook_arm(void) {
    pthread_mutex_lock(&g_mu);
    g_block = 1; g_entered = 0; g_fsync_on_loop = 0;
    g_loop_thread = pthread_self();
    pthread_mutex_unlock(&g_mu);
    s3_store_fsync_hook = blocking_fsync;
}

/* Wait (≤5 s) until a worker is inside the hook. */
static int hook_wait_entered(void) {
    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += 5;
    pthread_mutex_lock(&g_mu);
    while (g_entered == 0) {
        if (pthread_cond_timedwait(&g_cv, &g_mu, &dl) != 0) break;
    }
    int n = g_entered;
    pthread_mutex_unlock(&g_mu);
    return n;
}

static void hook_release(void) {
    pthread_mutex_lock(&g_mu);
    g_block = 0;
    pthread_cond_broadcast(&g_cv);
    pthread_mutex_unlock(&g_mu);
    s3_store_fsync_hook = NULL;
}

/* Wait (≤5 s) for the pool to report completions, then reap them. */
static int reap_one(iopool_t *pool) {
    struct pollfd pfd = { .fd = iopool_fd(pool), .events = POLLIN };
    if (poll(&pfd, 1, 5000) != 1) return 0;
    return iopool_reap(pool, NULL, NULL);
}

/* Feed `req` to a conn using `pool`. The request's blocking step must
 * park the conn in CST_WAIT_JOB and run on a worker, with the loop thread
 * (this one) already back in control; once released and reaped, the
 * response must start with `want_status`. The response head is copied
 * to resp (if non-NULL, 512 bytes). */
static void check_runs_off_loop(s3_store_t *s, iopool_t *pool,
                                const char *what, const char *req,
                                size_t req_n, const char *want_status,
                                char *resp) {
    int fd = pipe_with(req, req_n);
    conn_t *c = conn_create(fd, "test", s, pool, NULL, 0, 0, NULL);

    hook_arm();
    int rc = conn_on_readable(c);
    CHECK_EQ(rc, 0, what);
    CHECK_EQ(c->state, CST_WAIT_JOB, what);
    CHECK(!conn_hup_can_close(c), what);

    CHECK(hook_wait_entered() > 0, what);    /* a worker is in fsync... */
    CHECK(!g_fsync_on_loop, what);           /* ...and not on this thread */
    CHECK_EQ(c->state, CST_WAIT_JOB, what);  /* no response yet */

    hook_release();
    CHECK_EQ(reap_one(pool), 1, what);
    CHECK_EQ(c->state, CST_WRITE_RESPONSE, what);
    CHECK(c->job == NULL, what);
    if (strncmp(c->wbuf, want_status, strlen(want_status)) != 0) {
        fprintf(stderr, "FAIL %s: response %.40s\n", what, c->wbuf);
        failures++;
    }
    if (resp) snprintf(resp, 512, "%.*s", (int)c->wlen, c->wbuf);
    conn_destroy(c);
    close(fd);
}

static void t_blocking_work_runs_off_loop(void) {
    s3_store_t *s = setup_store();
    iopool_t *pool = iopool_create(2);
    assert(pool);
    char req[1024];
    int n;

    /* 1. Streamed PUT: commit fsync. */
    n = snprintf(req, sizeof(req),
                 "PUT /bkt/src HTTP/1.1\r\nHost: x\r\n"
                 "Content-Length: 5\r\n\r\nhello");
    check_runs_off_loop(s, pool, "put commit", req, (size_t)n,
                        "HTTP/1.1 200", NULL);

    /* 2. Server-side copy of that object. */
    n = snprintf(req, sizeof(req),
                 "PUT /bkt/dst HTTP/1.1\r\nHost: x\r\n"
                 "x-amz-copy-source: /bkt/src\r\n"
                 "Content-Length: 0\r\n\r\n");
    check_runs_off_loop(s, pool, "copy", req, (size_t)n, "HTTP/1.1 200",
                        NULL);
    s3_obj_meta_t m;
    CHECK_EQ(store_head(s, S3_STR_LIT("bkt"), S3_STR_LIT("dst"), &m), S3_OK,
             "copy: dst exists");
    CHECK_EQ(m.size, 5, "copy: dst size");

    /* 3. MPU part upload: part commit fsync. */
    char upload_id[33];
    CHECK_EQ(store_mpu_create(s, S3_STR_LIT("bkt"), S3_STR_LIT("mk"), NULL,
                              upload_id), S3_OK, "mpu create");
    n = snprintf(req, sizeof(req),
                 "PUT /bkt/mk?partNumber=1&uploadId=%s HTTP/1.1\r\n"
                 "Host: x\r\nContent-Length: 4\r\n\r\npart",
                 upload_id);
    char resp[512];
    check_runs_off_loop(s, pool, "mpu part", req, (size_t)n, "HTTP/1.1 200",
                        resp);
    const char *et = strstr(resp, "ETag: \"");
    CHECK(et != NULL, "mpu part: ETag header");
    char etag[33] = {0};
    if (et) memcpy(etag, et + 7, 32);

    /* 4. CompleteMultipartUpload: concatenation + fsync. */
    char body[256];
    int bn = snprintf(body, sizeof(body),
                      "<CompleteMultipartUpload><Part><PartNumber>1"
                      "</PartNumber><ETag>\"%s\"</ETag></Part>"
                      "</CompleteMultipartUpload>", etag);
    n = snprintf(req, sizeof(req),
                 "POST /bkt/mk?uploadId=%s HTTP/1.1\r\nHost: x\r\n"
                 "Content-Length: %d\r\n\r\n%s", upload_id, bn, body);
    check_runs_off_loop(s, pool, "mpu complete", req, (size_t)n,
                        "HTTP/1.1 200", NULL);
    CHECK_EQ(store_head(s, S3_STR_LIT("bkt"), S3_STR_LIT("mk"), &m), S3_OK,
             "mpu complete: object exists");
    CHECK_EQ(m.size, 4, "mpu complete: size");

    iopool_destroy(pool);
    teardown_store(s);
}

/* The client disconnects while its commit is running: the conn is freed
 * (orphaning the job), the commit still completes, and reaping the
 * orphan touches nothing freed (ASan build checks that). */
static void t_orphaned_job(void) {
    s3_store_t *s = setup_store();
    iopool_t *pool = iopool_create(1);
    assert(pool);
    const char *req = "PUT /bkt/orphan HTTP/1.1\r\nHost: x\r\n"
                      "Content-Length: 3\r\n\r\nabc";
    int fd = pipe_with(req, strlen(req));
    conn_t *c = conn_create(fd, "test", s, pool, NULL, 0, 0, NULL);

    hook_arm();
    CHECK_EQ(conn_on_readable(c), 0, "orphan: readable");
    CHECK_EQ(c->state, CST_WAIT_JOB, "orphan: parked");
    CHECK(hook_wait_entered() > 0, "orphan: worker in fsync");
    conn_destroy(c);                          /* client went away */
    close(fd);
    hook_release();
    CHECK_EQ(reap_one(pool), 1, "orphan: job reaped");

    s3_obj_meta_t m;
    CHECK_EQ(store_head(s, S3_STR_LIT("bkt"), S3_STR_LIT("orphan"), &m),
             S3_OK, "orphan: commit still landed");
    iopool_destroy(pool);
    teardown_store(s);
}

/* iopool_destroy with a job still queued: it runs to completion and its
 * done() is called (as an orphan, like server shutdown). */
static void t_pool_destroy_drains(void) {
    s3_store_t *s = setup_store();
    iopool_t *pool = iopool_create(1);
    assert(pool);
    const char *req = "PUT /bkt/drain HTTP/1.1\r\nHost: x\r\n"
                      "Content-Length: 3\r\n\r\nxyz";
    int fd = pipe_with(req, strlen(req));
    conn_t *c = conn_create(fd, "test", s, pool, NULL, 0, 0, NULL);
    CHECK_EQ(conn_on_readable(c), 0, "drain: readable");
    CHECK_EQ(c->state, CST_WAIT_JOB, "drain: parked");
    conn_destroy(c);                          /* server shutdown order */
    close(fd);
    iopool_destroy(pool);

    s3_obj_meta_t m;
    CHECK_EQ(store_head(s, S3_STR_LIT("bkt"), S3_STR_LIT("drain"), &m),
             S3_OK, "drain: queued commit ran before destroy returned");
    teardown_store(s);
}

int main(void) {
    log_init(LOG_WARN);

    t_read_budget_yields();
    t_small_request_one_event();
    t_blocking_work_runs_off_loop();
    t_orphaned_job();
    t_pool_destroy_drains();

    if (failures) {
        fprintf(stderr, "%d FAILURES\n", failures);
        return 1;
    }
    printf("ALL TESTS PASSED\n");
    return 0;
}
