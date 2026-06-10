/* include/metrics.h — request counters + Prometheus text rendering
 *
 * SINGLE-THREADED BY DESIGN: the epoll loop is the only thread that
 * ever touches these counters, so plain integer increments are safe and
 * no atomics are used. If fs3 ever grows worker threads, this module
 * must be revisited first.
 */
#ifndef FS3_METRICS_H
#define FS3_METRICS_H

#include <stddef.h>
#include <stdint.h>

#include "s3.h"

struct s3_store;

/* Label dimensions. Fixed, small cardinality: 6 methods x 4 status
 * classes = 24 series, all pre-allocated. */
typedef enum {
    FS3_M_GET, FS3_M_PUT, FS3_M_POST, FS3_M_DELETE, FS3_M_HEAD,
    FS3_M_OTHER, FS3_M_MAX
} fs3_metric_method_t;

typedef enum {
    FS3_S_2XX, FS3_S_3XX, FS3_S_4XX, FS3_S_5XX, FS3_S_MAX
} fs3_metric_status_t;

typedef struct fs3_metrics {
    uint64_t requests[FS3_M_MAX][FS3_S_MAX];
    uint64_t bytes_in_total;          /* request body bytes received */
    uint64_t bytes_out_total;         /* response bytes written (head + body) */
    double   duration_seconds_sum;    /* summary: _sum / _count */
    uint64_t duration_seconds_count;
} fs3_metrics_t;

/* Account one finished request. method is the request method token;
 * status the HTTP status sent; dur_s wall seconds from first parsed
 * byte to last byte written. */
void metrics_record(fs3_metrics_t *m, s3_str_t method, int status,
                    double dur_s, uint64_t bytes_in, uint64_t bytes_out);

/* Render Prometheus text exposition into buf. The store is consulted
 * for point-in-time gauges (bucket count, in-flight MPUs, volume
 * usage via statvfs) — per scrape, not per request. Returns the number
 * of bytes written, or -1 if cap was too small. */
int metrics_render(const fs3_metrics_t *m, struct s3_store *store,
                   char *buf, size_t cap);

#endif
