/* src/log.c */
#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

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

    fprintf(stderr, "%s.%03ld [%s] %s:%d ", tbuf,
            ts.tv_nsec / 1000000L, lvl_name(lvl), base, line);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
}
