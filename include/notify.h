/* include/notify.h — bucket event notifications (webhooks).
 *
 * A bucket with a rule (buckets/<b>/notification.json, set through the
 * admin API) has an HTTP POST sent to its endpoint for every matching
 * object event, in S3's event-record JSON format:
 *
 *   {"Records":[{"eventVersion":"2.1","eventSource":"fs3:s3",
 *     "eventTime":"…Z","eventName":"ObjectCreated:Put",
 *     "s3":{"s3SchemaVersion":"1.0","bucket":{"name":"b"},
 *           "object":{"key":"url-encoded","size":N,"eTag":"…",
 *                     "versionId":"…","sequencer":"…"}}}]}
 *
 * Events: ObjectCreated:{Put,Copy,CompleteMultipartUpload},
 * ObjectRemoved:{Delete,DeleteMarkerCreated},
 * LifecycleExpiration:{Delete,DeleteMarkerCreated}; rules select them
 * with "s3:ObjectCreated:*"-style patterns plus key prefix/suffix.
 *
 * Delivery is at least once, in commit order per bucket, from a durable
 * per-bucket journal (notify/<bucket-id>/queue) written by the store's
 * change hook under the key's stripe lock and fdatasync'd in groups,
 * like the replication journal. Unlike replication, a record carries the
 * event itself (it can't be re-derived later). Failed deliveries back
 * off (1 s doubling to 10 min) and are dropped after max_age_hours
 * (default 24), counted and audited. With a secret, each POST carries
 * X-Fs3-Signature: sha256=<hex HMAC-SHA256(secret, body)>.
 */
#ifndef FS3_NOTIFY_H
#define FS3_NOTIFY_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct s3_store;

typedef struct {
    struct s3_store *store;
    const char      *root;          /* state in <root>/notify/ */
    int              enabled;       /* 0: rules refused (--notify off) */
    const char      *ca_file;       /* extra CA bundle (shared with replication) */
    int              timeout_s;
} notify_cfg_t;

typedef struct notify notify_t;

notify_t *notify_create(const notify_cfg_t *cfg);
int       notify_start(notify_t *n);        /* after seccomp */
void      notify_destroy(notify_t *n);      /* after the iopool, before store_close */
void      notify_tick(notify_t *n, time_t now);

/* Admin API: /v1/buckets/<b>/notification[/status|/test]. */
char     *notify_admin(notify_t *n, const char *method, const char *bucket, const char *sub,
                       const char *body, size_t body_n, int *status);
int       notify_metrics(notify_t *n, char *out, size_t cap);

/* ---- Exposed for tests and fuzzing ---- */

#define NOTIFY_EV_CREATED_PUT      (1u << 0)
#define NOTIFY_EV_CREATED_COPY     (1u << 1)
#define NOTIFY_EV_CREATED_MPU      (1u << 2)
#define NOTIFY_EV_REMOVED_DELETE   (1u << 3)
#define NOTIFY_EV_REMOVED_MARKER   (1u << 4)
#define NOTIFY_EV_LIFECYCLE_DELETE (1u << 5)
#define NOTIFY_EV_LIFECYCLE_MARKER (1u << 6)

typedef struct {
    char     url[1024];             /* as given */
    unsigned events;                /* NOTIFY_EV_* mask */
    char     prefix[1025], suffix[256];
    char     secret[257];
    int      verify_tls, allow_plain_http;
    int      max_age_hours;
} notify_rule_t;

/* Parse and validate a rule. old (may be NULL) supplies the secret when
 * the body omits it. 0, or -1 with a message. */
int  notify_rule_parse(const char *json, size_t n, const notify_rule_t *old, int tls,
                       notify_rule_t *out, char *err, size_t errcap);
/* Split a webhook URL into "scheme://host[:port]" and "/path?query". */
int  notify_split_url(const char *url, char *base, size_t bcap, char *target, size_t tcap);

#endif
