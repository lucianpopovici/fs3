/* src/log.c — leveled logging and size-rotated log files. See log.h. */
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static log_level_t g_min = LOG_INFO;

static const char *lvl_name(log_level_t l) {
    switch (l) {
        case LOG_DEBUG: return "DBG";
        case LOG_INFO:  return "INF";
        case LOG_WARN:  return "WRN";
        case LOG_ERROR: return "ERR";
    }
    return "???";
}

void log_init(log_level_t min_level) { g_min = min_level; }

/* ===================================================================== */
/* logfile_t                                                             */
/* ===================================================================== */

struct logfile {
    pthread_mutex_t mu;
    int             fd;
    char           *path;
    mode_t          mode;
    uint64_t        size;
    uint64_t        max;
    int             keep;
    time_t          last_fail;     /* last failed rotation, for the 60 s retry gap */
};

static int lf_open_fd(const char *path, mode_t mode, uint64_t *size_out) {
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, mode);
    if (fd < 0) return -1;
    struct stat st;
    *size_out = (fstat(fd, &st) == 0 && st.st_size > 0) ? (uint64_t)st.st_size : 0;
    return fd;
}

logfile_t *logfile_open(const char *path, mode_t mode, uint64_t max_size, int keep) {
    if (!path || !*path || strlen(path) > PATH_MAX - 8) { errno = EINVAL; return NULL; }
    logfile_t *lf = calloc(1, sizeof(*lf));
    if (!lf) return NULL;
    lf->path = strdup(path);
    if (!lf->path) { free(lf); errno = ENOMEM; return NULL; }
    lf->mode = mode;
    lf->max  = max_size;
    lf->keep = keep < 1 ? 1 : (keep > LOG_MAX_KEEP ? LOG_MAX_KEEP : keep);
    lf->fd   = lf_open_fd(path, mode, &lf->size);
    if (lf->fd < 0) {
        int e = errno;
        free(lf->path); free(lf);
        errno = e;
        return NULL;
    }
    pthread_mutex_init(&lf->mu, NULL);
    return lf;
}

/* Called with lf->mu held. Never logs through log_msg (it would recurse
 * into this file's mutex); diagnostics go straight to stderr. */
static void lf_rotate(logfile_t *lf) {
    time_t now = time(NULL);
    if (lf->last_fail && now - lf->last_fail < 60) return;

    char from[PATH_MAX], to[PATH_MAX];
    for (int i = lf->keep - 1; i >= 1; i--) {
        snprintf(from, sizeof(from), "%s.%d", lf->path, i);
        snprintf(to,   sizeof(to),   "%s.%d", lf->path, i + 1);
        if (rename(from, to) < 0 && errno != ENOENT) goto fail;
    }
    snprintf(to, sizeof(to), "%s.1", lf->path);
    if (rename(lf->path, to) < 0) goto fail;

    uint64_t sz;
    int fd = lf_open_fd(lf->path, lf->mode, &sz);
    if (fd < 0) goto fail;             /* keep writing to the old fd (now path.1) */
    close(lf->fd);
    lf->fd = fd;
    lf->size = sz;
    lf->last_fail = 0;
    return;
fail:
    if (!lf->last_fail)
        fprintf(stderr, "fs3: cannot rotate %s: %s (will retry)\n", lf->path, strerror(errno));
    lf->last_fail = now;
}

int logfile_write(logfile_t *lf, const char *buf, size_t n) {
    if (!lf || !buf) return -1;
    int rc = 0;
    pthread_mutex_lock(&lf->mu);
    if (lf->max && lf->size > 0 && lf->size + n > lf->max) lf_rotate(lf);
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(lf->fd, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            rc = -1;
            break;
        }
        off += (size_t)w;
    }
    lf->size += off;
    pthread_mutex_unlock(&lf->mu);
    return rc;
}

int logfile_reopen(logfile_t *lf) {
    if (!lf) return -1;
    pthread_mutex_lock(&lf->mu);
    uint64_t sz;
    int fd = lf_open_fd(lf->path, lf->mode, &sz);
    int rc = -1;
    if (fd >= 0) {
        close(lf->fd);
        lf->fd = fd;
        lf->size = sz;
        lf->last_fail = 0;
        rc = 0;
    }
    pthread_mutex_unlock(&lf->mu);
    return rc;
}

uint64_t logfile_size(logfile_t *lf) {
    if (!lf) return 0;
    pthread_mutex_lock(&lf->mu);
    uint64_t s = lf->size;
    pthread_mutex_unlock(&lf->mu);
    return s;
}

void logfile_close(logfile_t *lf) {
    if (!lf) return;
    if (lf->fd >= 0) close(lf->fd);
    pthread_mutex_destroy(&lf->mu);
    free(lf->path);
    free(lf);
}

/* ===================================================================== */
/* Global rotation settings and the log file                             */
/* ===================================================================== */

static uint64_t   g_rot_max  = LOG_DEFAULT_MAX_SIZE;
static int        g_rot_keep = LOG_DEFAULT_KEEP;
static logfile_t *g_logfile;   /* set once at startup, before threads exist */

void log_set_rotation(uint64_t max_size, int keep) {
    g_rot_max  = max_size;
    g_rot_keep = keep < 1 ? 1 : (keep > LOG_MAX_KEEP ? LOG_MAX_KEEP : keep);
}
uint64_t log_rotation_max(void)  { return g_rot_max; }
int      log_rotation_keep(void) { return g_rot_keep; }

int log_set_file(const char *path) {
    if (!path) {
        logfile_close(g_logfile);
        g_logfile = NULL;
        return 0;
    }
    logfile_t *lf = logfile_open(path, 0640, g_rot_max, g_rot_keep);
    if (!lf) return -1;
    logfile_close(g_logfile);
    g_logfile = lf;
    return 0;
}

void log_reopen(void) {
    if (g_logfile && logfile_reopen(g_logfile) < 0)
        fprintf(stderr, "fs3: cannot reopen log file: %s\n", strerror(errno));
}

/* ===================================================================== */
/* log_msg                                                               */
/* ===================================================================== */

void log_msg(log_level_t lvl, const char *file, int line,
             const char *fmt, ...) {
    if (lvl < g_min) return;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);

    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%dT%H:%M:%S", &tm);

    /* Strip leading dirs from file for compactness */
    const char *base = file;
    for (const char *p = file; *p; p++) if (*p == '/') base = p + 1;

    /* Format the whole line first, so it goes out as one write(). */
    char buf[4096];
    int n = snprintf(buf, sizeof(buf), "%s.%03ld [%s] %s:%d ", tbuf,
                     ts.tv_nsec / 1000000L, lvl_name(lvl), base, line);
    if (n < 0) return;
    size_t o = (size_t)n < sizeof(buf) ? (size_t)n : sizeof(buf) - 1;

    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(buf + o, sizeof(buf) - o, fmt, ap);
    va_end(ap);
    if (m > 0) o += (size_t)m < sizeof(buf) - o ? (size_t)m : sizeof(buf) - o - 1;
    if (o >= sizeof(buf) - 1) {             /* truncated: mark it, keep one line */
        o = sizeof(buf) - 5;
        memcpy(buf + o, "...", 3);
        o += 3;
    }
    /* A log line is one line: a message containing a newline (e.g. from a
     * client-supplied string) must not be able to forge another line. */
    for (size_t i = (size_t)n; i < o; i++)
        if (buf[i] == '\n' || buf[i] == '\r') buf[i] = ' ';
    buf[o++] = '\n';

    if (g_logfile) {
        logfile_write(g_logfile, buf, o);
        return;
    }
    /* Hold the stream so lines from iopool worker threads don't interleave. */
    flockfile(stderr);
    fwrite(buf, 1, o, stderr);
    funlockfile(stderr);
}
