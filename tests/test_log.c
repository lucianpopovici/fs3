/* tests/test_log.c — logfile_t rotation, log_msg formatting, concurrency. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "log.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_pass, g_fail;
#define CHECK(cond, ...) do { if (cond) { g_pass++; } else { g_fail++; \
    fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); fprintf(stderr, __VA_ARGS__); \
    fputc('\n', stderr); } } while (0)

static char g_dir[256];

static off_t fsize(const char *p) {
    struct stat st;
    return stat(p, &st) == 0 ? st.st_size : -1;
}
static int exists(const char *p) { return access(p, F_OK) == 0; }

static char *slurp(const char *p, size_t *n) {
    FILE *f = fopen(p, "r");
    if (!f) return NULL;
    char *buf = NULL; size_t cap = 0, len = 0;
    for (;;) {
        if (len + 4096 + 1 > cap) { cap = cap * 2 + 8192; buf = realloc(buf, cap); }
        size_t r = fread(buf + len, 1, 4096, f);
        len += r;
        if (r == 0) break;
    }
    fclose(f);
    buf[len] = 0;
    if (n) *n = len;
    return buf;
}

/* Every line in the file has the given prefix and ends with '\n'. */
static int lines_ok(const char *p, const char *prefix, int *count) {
    size_t n; char *b = slurp(p, &n);
    if (!b) return 0;
    int ok = 1, c = 0;
    size_t pl = strlen(prefix);
    char *s = b;
    while (*s) {
        char *nl = strchr(s, '\n');
        if (!nl) { ok = 0; break; }               /* torn last line */
        if ((size_t)(nl - s) < pl || strncmp(s, prefix, pl)) { ok = 0; break; }
        c++;
        s = nl + 1;
    }
    free(b);
    if (count) *count += c;
    return ok;
}

static void t_rotation(void) {
    char path[300], p1[310], p3[310], p4[310];
    snprintf(path, sizeof(path), "%s/r.log", g_dir);
    snprintf(p1, sizeof(p1), "%s.1", path);
    snprintf(p3, sizeof(p3), "%s.3", path);
    snprintf(p4, sizeof(p4), "%s.4", path);
    logfile_t *lf = logfile_open(path, 0640, 1000, 3);
    CHECK(lf != NULL, "open");
    char line[101];
    memset(line, 'x', 99); line[99] = '\n'; line[100] = 0;
    for (int i = 0; i < 100; i++) logfile_write(lf, line, 100);   /* 10 000 bytes */
    CHECK(exists(path) && exists(p1) && exists(p3), "rotated files exist");
    CHECK(!exists(p4), "no more than keep=3 rotated files");
    CHECK(fsize(path) <= 1000 && fsize(p1) <= 1000 && fsize(p3) <= 1000,
          "each file <= max (%lld %lld %lld)", (long long)fsize(path),
          (long long)fsize(p1), (long long)fsize(p3));
    CHECK(fsize(p1) == 1000, "full files are exactly max for 100-byte lines");
    struct stat st;
    CHECK(stat(path, &st) == 0 && (st.st_mode & 0777) == 0640, "mode 0640");
    CHECK(stat(p1, &st) == 0 && (st.st_mode & 0777) == 0640, "rotated keeps mode");
    logfile_close(lf);

    /* Re-open appends and counts the existing size. */
    off_t before = fsize(path);
    lf = logfile_open(path, 0640, 1000, 3);
    CHECK(lf && (off_t)logfile_size(lf) == before, "size picked up at open");
    logfile_close(lf);

    /* max 0 = never rotate. */
    char q[300], q1[310];
    snprintf(q, sizeof(q), "%s/norot.log", g_dir);
    snprintf(q1, sizeof(q1), "%s.1", q);
    lf = logfile_open(q, 0600, 0, 3);
    for (int i = 0; i < 100; i++) logfile_write(lf, line, 100);
    CHECK(fsize(q) == 10000 && !exists(q1), "max 0 never rotates");
    logfile_close(lf);
}

static void t_reopen(void) {
    char path[300], moved[310];
    snprintf(path, sizeof(path), "%s/re.log", g_dir);
    snprintf(moved, sizeof(moved), "%s.ext", path);
    logfile_t *lf = logfile_open(path, 0600, 0, 2);
    logfile_write(lf, "a\n", 2);
    CHECK(rename(path, moved) == 0, "external move");
    logfile_write(lf, "b\n", 2);                 /* still the old inode */
    CHECK(fsize(moved) == 4 && !exists(path), "writes follow the old fd until reopen");
    CHECK(logfile_reopen(lf) == 0, "reopen");
    logfile_write(lf, "c\n", 2);
    CHECK(fsize(path) == 2 && logfile_size(lf) == 2, "new file after reopen");
    logfile_close(lf);
}

static void t_rotate_failure_body(void);

/* Root ignores directory permissions, so run the check as nobody in a
 * child process when the suite runs as root. */
static void t_rotate_failure(void) {
    if (geteuid() != 0) { t_rotate_failure_body(); return; }
    char sub[300];
    snprintf(sub, sizeof(sub), "%s/ro", g_dir);
    mkdir(sub, 0700);
    if (chown(sub, 65534, 65534) < 0 || chmod(g_dir, 0711) < 0) { g_fail++; return; }
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0) {
        if (setgid(65534) < 0 || setuid(65534) < 0) _exit(3);
        g_pass = g_fail = 0;
        t_rotate_failure_body();
        _exit(g_fail ? 1 : 0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0, "rotation failure handling (as nobody)");
}

static void t_rotate_failure_body(void) {
    char sub[300], path[320], p1[330];
    snprintf(sub, sizeof(sub), "%s/ro", g_dir);
    mkdir(sub, 0700);
    snprintf(path, sizeof(path), "%s/f.log", sub);
    snprintf(p1, sizeof(p1), "%s.1", path);
    logfile_t *lf = logfile_open(path, 0600, 100, 2);
    chmod(sub, 0500);                            /* renames now fail */
    char line[51]; memset(line, 'y', 49); line[49] = '\n';
    int rc = 0;
    for (int i = 0; i < 10; i++) rc |= logfile_write(lf, line, 50);
    CHECK(rc == 0, "writes keep succeeding when rotation fails");
    CHECK(fsize(path) == 500 && !exists(p1), "kept writing to the current file");
    chmod(sub, 0700);
    logfile_close(lf);
}

typedef struct { logfile_t *lf; int id; } thr_arg_t;
static void *writer(void *a) {
    thr_arg_t *t = a;
    char line[200];
    for (int i = 0; i < 2000; i++) {
        int n = snprintf(line, sizeof(line), "T%d %d %0*d\n", t->id, i, 60 + t->id * 7, 0);
        logfile_write(t->lf, line, (size_t)n);
    }
    return NULL;
}

static void t_concurrency(void) {
    char path[300];
    snprintf(path, sizeof(path), "%s/c.log", g_dir);
    logfile_t *lf = logfile_open(path, 0600, 8192, 50);
    pthread_t th[8]; thr_arg_t args[8];
    for (int i = 0; i < 8; i++) { args[i] = (thr_arg_t){ lf, i }; pthread_create(&th[i], NULL, writer, &args[i]); }
    for (int i = 0; i < 8; i++) pthread_join(th[i], NULL);
    logfile_close(lf);
    /* Every line, across the current and rotated files, is whole: "T<id> ". */
    int total = 0, ok = lines_ok(path, "T", &total);
    for (int i = 1; i <= 50; i++) {
        char p[320];
        snprintf(p, sizeof(p), "%s.%d", path, i);
        if (exists(p)) ok &= lines_ok(p, "T", &total);
    }
    CHECK(ok, "no torn or interleaved lines under 8 threads");
    /* 16 000 lines written; with keep=50 at 8 KiB, older ones may have
     * rotated away. At least the kept window must be full lines. */
    CHECK(total > 1000, "lines present (%d)", total);
}

static void t_log_msg(void) {
    char path[300];
    snprintf(path, sizeof(path), "%s/msg.log", g_dir);
    log_set_rotation(0, 3);
    CHECK(log_set_file(path) == 0, "log_set_file");
    log_init(LOG_INFO);
    LOG_D("debug suppressed");
    LOG_I("hello %d", 42);
    LOG_W("forged\n2026-01-01T00:00:00.000 [ERR] x.c:1 injected");
    char big[6000]; memset(big, 'z', sizeof(big) - 1); big[sizeof(big) - 1] = 0;
    LOG_E("%s", big);
    log_set_file(NULL);
    size_t n; char *b = slurp(path, &n);
    CHECK(b != NULL, "read back");
    int lines = 0;
    for (size_t i = 0; i < n; i++) if (b[i] == '\n') lines++;
    CHECK(lines == 3, "three lines (debug suppressed, newline neutralised): %d", lines);
    CHECK(strstr(b, "[INF] test_log.c:") && strstr(b, "hello 42"), "format");
    CHECK(strstr(b, "forged 2026-01-01") != NULL, "embedded newline replaced by a space");
    CHECK(strstr(b, "zzz...\n") != NULL, "long line truncated with a marker");
    free(b);
    errno = 0;
    CHECK(log_set_file("/nonexistent-dir/x.log") == -1 && errno != 0, "bad path fails");
}

int main(void) {
    snprintf(g_dir, sizeof(g_dir), "/tmp/fs3-test-log-%d", (int)getpid());
    mkdir(g_dir, 0700);
    t_rotation();
    t_reopen();
    t_rotate_failure();
    t_concurrency();
    t_log_msg();
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", g_dir);
    (void)!system(cmd);
    printf("test_log: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
