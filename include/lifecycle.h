/* include/lifecycle.h — bucket lifecycle rules (item 5)
 *
 * PUT/GET/DELETE /bucket?lifecycle store a validated
 * LifecycleConfiguration as buckets/<b>/lifecycle.xml. Supported:
 * Filter/Prefix (and Filter/And/Prefix, legacy Rule/Prefix),
 * Expiration/Days|Date, AbortIncompleteMultipartUpload/
 * DaysAfterInitiation, NoncurrentVersionExpiration/NoncurrentDays and
 * Expiration/ExpiredObjectDeleteMarker (acted on once versioning is
 * enabled on the bucket). Transitions, tag and size filters are refused
 * with 501 rather than silently ignored.
 *
 * The sweeper (lc_sweep) walks every bucket on an iopool worker — never
 * on the event loop — and deletes through the store's guarded expiry
 * path, rate-limited.
 */
#ifndef FS3_LIFECYCLE_H
#define FS3_LIFECYCLE_H

#include <stddef.h>
#include <stdint.h>

#include "s3.h"

struct s3_store;

#define LC_MAX_RULES 1000
#define LC_MAX_BYTES (64 * 1024)

typedef struct {
    int      enabled;
    char    *prefix;              /* "" = whole bucket */
    long     exp_days;            /* 0 = unset */
    int64_t  exp_date_ms;         /* 0 = unset; midnight UTC */
    int      exp_delete_marker;   /* ExpiredObjectDeleteMarker */
    long     abort_days;          /* AbortIncompleteMultipartUpload */
    long     noncurrent_days;     /* NoncurrentVersionExpiration */
} lc_rule_t;

typedef struct {
    lc_rule_t *rules;
    size_t     n_rules;
} lc_config_t;

/* Parse + validate; NULL on error with *err set (MalformedXML,
 * InvalidArgument, NotImplemented). */
lc_config_t *lc_parse(const char *xml, size_t n, s3_err_t *err);
void         lc_free(lc_config_t *c);
void        *lc_parse_cb(const char *xml, size_t n);
void         lc_free_cb(void *o);

/* 1 if any enabled rule expires everything it matches at the next sweep
 * regardless of age (Expiration/Date not after now_ms). Security review
 * S9: such a PUT needs an explicit confirmation header. */
int lc_has_immediate_rule(const lc_config_t *c, int64_t now_ms);

/* When `key` (mtime_ms) expires under c, in ms; 0 = never. */
int64_t lc_expiry_ms(const lc_config_t *c, s3_str_t key, uint64_t mtime_ms);
/* Abort age (ms) for an upload of `key`; 0 = no rule. */
int64_t lc_abort_after_ms(const lc_config_t *c, s3_str_t key);

typedef struct {
    int64_t   now_ms;             /* wall clock (+ test offset) */
    int       rate_per_s;         /* deletions per second (0 = unlimited) */
    int       dry_run;            /* log what would happen, change nothing */
    uint64_t *expired_total;      /* counters (atomic adds), may be NULL */
    uint64_t *aborted_total;
} lc_opts_t;

typedef struct {
    uint64_t buckets, scanned, expired, aborted, skipped_changed;
} lc_stats_t;

/* Sweep every bucket. Safe to run on a worker thread. */
void lc_sweep(struct s3_store *s, const lc_opts_t *o, lc_stats_t *out);

/* store_set_mpu_gc_filter callback: 1 if a bucket lifecycle abort rule
 * covers the upload (the per-bucket rule overrides the global TTL). */
int lc_mpu_gc_filter(void *store, s3_str_t bucket, s3_str_t key);

#endif
