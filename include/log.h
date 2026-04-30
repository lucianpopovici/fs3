/* include/log.h — minimal leveled logging */
#ifndef FS3_LOG_H
#define FS3_LOG_H

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

#endif
