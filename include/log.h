/* include/log.h — minimal leveled logging, with optional size-rotated
 * log files.
 *
 * By default log lines go to stderr. log_set_file() sends them to a file
 * instead; the audit log (src/audit.c) uses the same logfile_t, so both
 * rotate the same way:
 *
 *   - every write is one write(2) of a whole line under the file's mutex,
 *     so lines from iopool threads never interleave or tear;
 *   - when the file reaches max_size bytes it is rotated: path.(keep-1)
 *     → path.keep, …, path → path.1, then a fresh path is opened and
 *     swapped in. The oldest file beyond `keep` is overwritten by the
 *     rename;
 *   - if rotation fails (no space, permissions), writing continues on the
 *     current fd, one diagnostic goes to stderr, and rotation is retried
 *     at most once a minute;
 *   - logfile_reopen() (SIGHUP) re-opens the path, for external rotation.
 *
 * max_size 0 disables rotation for that file.
 */
#ifndef FS3_LOG_H
#define FS3_LOG_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR
} log_level_t;

void log_init(log_level_t min_level);
void log_msg(log_level_t lvl, const char *file, int line,
             const char *fmt, ...) __attribute__((format(printf, 4, 5)));

#define LOG_D(...) log_msg(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_I(...) log_msg(LOG_INFO,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_W(...) log_msg(LOG_WARN,  __FILE__, __LINE__, __VA_ARGS__)
#define LOG_E(...) log_msg(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)

/* ---- rotated log files -------------------------------------------- */

#define LOG_DEFAULT_MAX_SIZE (10ull * 1024 * 1024)
#define LOG_DEFAULT_KEEP     5
#define LOG_MAX_KEEP         50

typedef struct logfile logfile_t;

/* Open (append, create with `mode`). NULL with errno set on failure. */
logfile_t *logfile_open(const char *path, mode_t mode, uint64_t max_size, int keep);
/* Append one complete record (should end in '\n'). 0 ok, -1 on error. */
int  logfile_write(logfile_t *lf, const char *buf, size_t n);
/* Re-open the path (after external rotation). Keeps the old fd on error. */
int  logfile_reopen(logfile_t *lf);
void logfile_close(logfile_t *lf);
/* Bytes written to the current file (including what was there at open). */
uint64_t logfile_size(logfile_t *lf);

/* Rotation settings for files opened after the call (log file and audit
 * log). Defaults: LOG_DEFAULT_MAX_SIZE, LOG_DEFAULT_KEEP. */
void log_set_rotation(uint64_t max_size, int keep);
uint64_t log_rotation_max(void);
int      log_rotation_keep(void);

/* Send log lines to `path` (mode 0640) instead of stderr. 0 ok, -1 with
 * errno set (logging stays on stderr). NULL path returns to stderr. */
int  log_set_file(const char *path);
/* SIGHUP: re-open the log file, if any. */
void log_reopen(void);

#endif
