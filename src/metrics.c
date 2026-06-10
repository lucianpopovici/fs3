/* src/metrics.c — request counters + Prometheus text rendering.
 *
 * See the header for the single-threaded invariant: no atomics here,
 * on purpose. */

#include "metrics.h"
#include "store.h"

#include <stdio.h>
#include <string.h>

static const char *METHOD_LABEL[FS3_M_MAX] = {
    "GET", "PUT", "POST", "DELETE", "HEAD", "other",
};
static const char *STATUS_LABEL[FS3_S_MAX] = {
    "2xx", "3xx", "4xx", "5xx",
};

static fs3_metric_method_t method_index(s3_str_t m) {
    if (s3_str_eq_lit(m, "GET"))    return FS3_M_GET;
    if (s3_str_eq_lit(m, "PUT"))    return FS3_M_PUT;
    if (s3_str_eq_lit(m, "POST"))   return FS3_M_POST;
    if (s3_str_eq_lit(m, "DELETE")) return FS3_M_DELETE;
    if (s3_str_eq_lit(m, "HEAD"))   return FS3_M_HEAD;
    return FS3_M_OTHER;
}

static fs3_metric_status_t status_index(int status) {
    if (status >= 500) return FS3_S_5XX;
    if (status >= 400) return FS3_S_4XX;
    if (status >= 300) return FS3_S_3XX;
    return FS3_S_2XX;
}

void metrics_record(fs3_metrics_t *m, s3_str_t method, int status,
                    double dur_s, uint64_t bytes_in, uint64_t bytes_out) {
    if (!m) return;
    m->requests[method_index(method)][status_index(status)]++;
    m->bytes_in_total  += bytes_in;
    m->bytes_out_total += bytes_out;
    if (dur_s >= 0) {
        m->duration_seconds_sum   += dur_s;
        m->duration_seconds_count += 1;
    }
}

int metrics_render(const fs3_metrics_t *m, struct s3_store *store,
                   char *buf, size_t cap) {
    size_t off = 0;
#define EMIT(...) do {                                                  \
        int _n = snprintf(buf + off, cap - off, __VA_ARGS__);           \
        if (_n < 0 || (size_t)_n >= cap - off) return -1;               \
        off += (size_t)_n;                                              \
    } while (0)

    EMIT("# HELP fs3_up 1 while the server is running.\n"
         "# TYPE fs3_up gauge\n"
         "fs3_up 1\n");

    EMIT("# HELP fs3_requests_total Requests served, by method and status class.\n"
         "# TYPE fs3_requests_total counter\n");
    for (int mi = 0; mi < FS3_M_MAX; mi++) {
        for (int si = 0; si < FS3_S_MAX; si++) {
            EMIT("fs3_requests_total{method=\"%s\",status=\"%s\"} %llu\n",
                 METHOD_LABEL[mi], STATUS_LABEL[si],
                 (unsigned long long)m->requests[mi][si]);
        }
    }

    EMIT("# HELP fs3_bytes_in_total Request body bytes received.\n"
         "# TYPE fs3_bytes_in_total counter\n"
         "fs3_bytes_in_total %llu\n",
         (unsigned long long)m->bytes_in_total);
    EMIT("# HELP fs3_bytes_out_total Response bytes written (head + body).\n"
         "# TYPE fs3_bytes_out_total counter\n"
         "fs3_bytes_out_total %llu\n",
         (unsigned long long)m->bytes_out_total);

    EMIT("# HELP fs3_request_duration_seconds Request wall time, first parsed byte to last byte written.\n"
         "# TYPE fs3_request_duration_seconds summary\n"
         "fs3_request_duration_seconds_sum %.6f\n"
         "fs3_request_duration_seconds_count %llu\n",
         m->duration_seconds_sum,
         (unsigned long long)m->duration_seconds_count);

    s3_admin_stats_t st;
    store_admin_stats((s3_store_t *)store, &st);
    EMIT("# HELP fs3_buckets_total Buckets currently present.\n"
         "# TYPE fs3_buckets_total gauge\n"
         "fs3_buckets_total %llu\n",
         (unsigned long long)st.buckets);
    EMIT("# HELP fs3_mpu_inflight Multipart uploads currently staged.\n"
         "# TYPE fs3_mpu_inflight gauge\n"
         "fs3_mpu_inflight %llu\n",
         (unsigned long long)st.mpu_inflight);
    EMIT("# HELP fs3_storage_used_bytes Bytes used on the data volume (statvfs, whole volume).\n"
         "# TYPE fs3_storage_used_bytes gauge\n"
         "fs3_storage_used_bytes %llu\n",
         (unsigned long long)st.volume_used_bytes);
    EMIT("# HELP fs3_storage_free_bytes Bytes available on the data volume.\n"
         "# TYPE fs3_storage_free_bytes gauge\n"
         "fs3_storage_free_bytes %llu\n",
         (unsigned long long)st.volume_free_bytes);

#undef EMIT
    return (int)off;
}
