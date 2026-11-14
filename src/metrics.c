/* src/metrics.c — request counters + Prometheus text rendering.
 *
 * See the header for the single-threaded invariant: no atomics here,
 * on purpose. */

#include "metrics.h"
#include "response.h"
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

void metrics_error(fs3_metrics_t *m, s3_err_t e) {
    if (m && e > S3_OK && e < S3_ERR_MAX) m->errors[e]++;
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

    EMIT("# HELP fs3_errors_total S3 error responses, by error.\n"
         "# TYPE fs3_errors_total counter\n");
    for (int e = 1; e < S3_ERR_MAX; e++) {
        if (!m->errors[e]) continue;
        EMIT("fs3_errors_total{error=\"%s\",status=\"%d\"} %llu\n",
             s3_err_name((s3_err_t)e), rsp_status_for_err((s3_err_t)e),
             (unsigned long long)m->errors[e]);
    }
    EMIT("# HELP fs3_lifecycle_expired_total Objects deleted by lifecycle rules.\n"
         "# TYPE fs3_lifecycle_expired_total counter\n"
         "fs3_lifecycle_expired_total %llu\n"
         "# HELP fs3_lifecycle_aborted_mpu_total Multipart uploads aborted by lifecycle rules.\n"
         "# TYPE fs3_lifecycle_aborted_mpu_total counter\n"
         "fs3_lifecycle_aborted_mpu_total %llu\n"
         "# HELP fs3_lifecycle_runs_total Completed lifecycle sweeps.\n"
         "# TYPE fs3_lifecycle_runs_total counter\n"
         "fs3_lifecycle_runs_total %llu\n",
         (unsigned long long)__atomic_load_n(&m->lifecycle_expired_total, __ATOMIC_RELAXED),
         (unsigned long long)__atomic_load_n(&m->lifecycle_aborted_mpu_total, __ATOMIC_RELAXED),
         (unsigned long long)__atomic_load_n(&m->lifecycle_runs_total, __ATOMIC_RELAXED));

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

    EMIT("# HELP fs3_quota_rejections_total Writes refused because a bucket or user quota was reached.\n"
         "# TYPE fs3_quota_rejections_total counter\n"
         "fs3_quota_rejections_total %llu\n",
         (unsigned long long)store_quota_rejections((s3_store_t *)store));
    /* Per-bucket usage and limits (logical bytes, all versions and
     * in-flight parts). Bucket names are label-safe ([a-z0-9.-]). */
    s3_bucket_info_t *bl = NULL;
    size_t nb = 0;
    if (store_list_buckets((s3_store_t *)store, &bl, &nb) == S3_OK) {
        EMIT("# HELP fs3_bucket_bytes Logical bytes stored in a bucket (quota usage).\n"
             "# TYPE fs3_bucket_bytes gauge\n");
        for (size_t i = 0; i < nb; i++) {
            s3_quota_usage_t u;
            if (store_bucket_usage((s3_store_t *)store, (s3_str_t){ bl[i].name, strlen(bl[i].name) },
                                   &u) != S3_OK) continue;
            if (off + 256 > cap) break;
            EMIT("fs3_bucket_bytes{bucket=\"%s\"} %llu\n", bl[i].name, (unsigned long long)u.bytes);
        }
        EMIT("# HELP fs3_bucket_quota_bytes Byte limit of a bucket (0 = unlimited).\n"
             "# TYPE fs3_bucket_quota_bytes gauge\n");
        for (size_t i = 0; i < nb; i++) {
            s3_quota_usage_t u;
            if (store_bucket_usage((s3_store_t *)store, (s3_str_t){ bl[i].name, strlen(bl[i].name) },
                                   &u) != S3_OK) continue;
            if (off + 256 > cap) break;
            EMIT("fs3_bucket_quota_bytes{bucket=\"%s\"} %llu\n", bl[i].name,
                 (unsigned long long)u.max_bytes);
        }
        store_buckets_free(bl, nb);
    }

#undef EMIT
    return (int)off;
}
