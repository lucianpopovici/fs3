/* include/repl.h — asynchronous one-way bucket replication.
 *
 * A bucket with a rule (buckets/<b>/replication.json, set through the
 * admin API) has its changes copied to a bucket on another S3 endpoint.
 * Design: docs/plan-logs-replication-compat.md, section 2.
 *
 * Durable queue: repl/<bucket-id>/queue, an append-only journal of
 * "key changed" records written by the store's change hook while the
 * key's stripe lock is held (so records for one key are in commit
 * order), fdatasync'd by a group-commit thread every 10 ms. A cursor
 * file holds the last replicated sequence number. Records only say which
 * key changed: the worker replicates the key's *current* local state
 * (upload it, or delete it remotely), so a lost or duplicated record
 * never makes the replica wrong, only late or redundant. After an
 * unclean shutdown a recovery scan re-queues objects newer than the
 * journal's high-water mark.
 *
 * Workers are dedicated threads (--repl-workers), created after the
 * seccomp filter is installed. Each takes one bucket at a time, reads a
 * batch of records, coalesces repeats of the same key and replicates
 * them over one keep-alive connection, throttled by --repl-rate.
 *
 * Errors: 5xx, timeouts, network errors and rule-level 4xx (bad
 * credentials, missing remote bucket, clock skew) keep the record and
 * back off (1 s doubling to 10 min). Other 4xx are permanent for that
 * record: it is logged, audited, kept in the status error ring and
 * skipped. SSE-C objects are skipped (fs3 doesn't have the key).
 */
#ifndef FS3_REPL_H
#define FS3_REPL_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct s3_store;

typedef struct {
    struct s3_store *store;
    const char      *root;          /* data root; state lives in <root>/repl/ */
    int              workers;       /* 0 = replication disabled */
    uint64_t         rate;          /* bytes/s across all buckets, 0 = unlimited */
    const char      *ca_file;       /* NULL = system bundle */
    uint64_t         part_size;     /* multipart part size; objects > 4x use multipart */
    int              timeout_s;     /* per network operation */
} repl_cfg_t;

typedef struct repl repl_t;

/* Loads every bucket's rule and journal and hooks into the store. NULL
 * on allocation failure; with workers == 0 returns a repl_t that refuses
 * configuration (the admin API reports it). */
repl_t *repl_create(const repl_cfg_t *cfg);
/* Starts the worker and group-commit threads (call after seccomp). */
int     repl_start(repl_t *r);
/* Stops threads, makes journals durable and marks a clean shutdown.
 * Call after the iopool has drained (no more commits) and before
 * store_close. */
void    repl_destroy(repl_t *r);

/* Loop tick (1 s): drops rules of deleted buckets. */
void    repl_tick(repl_t *r, time_t now);

/* Admin API: /v1/buckets/<bucket>/replication[/<sub>]. Returns a
 * malloc'd JSON body and sets *status (HTTP code). method is the HTTP
 * method; sub is "", "sync" or "status". */
char   *repl_admin(repl_t *r, const char *method, const char *bucket, const char *sub,
                   const char *body, size_t body_n, int *status);
/* One-line summary for GET /v1/buckets/<b>: appends
 * ,"replication":{...} or nothing. */
void    repl_bucket_summary(repl_t *r, const char *bucket, char *out, size_t cap, size_t *o);

/* Self-healing scrub (scrub_repair_fn): GET `key` from the bucket's
 * replica and hand it to store_repair_object, which verifies it against
 * the local header before swapping it in. 1 repaired, 0 no rule, -1
 * refused (why). */
int     repl_scrub_repair(void *repl, const char *bucket, const char *key, uint64_t ino,
                          uint64_t size, char *why, size_t whycap);

/* GET /replication on the localhost metrics listener (the DSM tile):
 * one line per rule, "<bucket> <queue> <failed> <lag-s> <target> <last error…>",
 * no credentials, no object keys. Returns bytes or -1 on overflow. */
int     repl_render_text(repl_t *r, char *out, size_t cap);

/* Prometheus text; returns bytes written or -1 on overflow. */
int     repl_metrics(repl_t *r, char *out, size_t cap);

/* ---- Exposed for tests and fuzzing ---- */

typedef struct {
    uint64_t seq, mtime_ms;
    int      op;                    /* STORE_CHANGE_* */
    char     key[1025];
    size_t   key_len;
} repl_rec_t;

#define REPL_REC_HDR   8            /* u32 body length, u32 CRC32C of the body */
#define REPL_REC_FIXED 19           /* u64 seq, u64 mtime, u8 op, u16 key length */
#define REPL_KEY_MAX   1024

/* Encode one record into out (cap >= REPL_REC_HDR + REPL_REC_FIXED + key_len).
 * Returns its size. */
size_t  repl_rec_encode(const repl_rec_t *rec, uint8_t *out, size_t cap);
/* Decode the record at buf. Returns its size, 0 if buf holds only part
 * of a record, -1 if the bytes are not a valid record. */
long    repl_rec_decode(const uint8_t *buf, size_t n, repl_rec_t *out);

typedef struct {
    char endpoint[300];             /* scheme://host[:port] as given */
    char region[64];
    char bucket[64];
    char access_key[129];
    char secret_key[257];
    char prefix[1025];
    int  virtual_host;              /* "addressing": "virtual" */
    int  verify_tls;
    int  deletes;
    int  allow_plain_http;
    char storage_class[32];         /* optional x-amz-storage-class */
} repl_rule_t;

/* Parse and validate a rule (the admin API's PUT body or the stored
 * sidecar). `old` (may be NULL) supplies secret_key when the body omits
 * it and keeps the same access key. tls: this build can do https.
 * Returns 0, or -1 with a message in err. */
int     repl_rule_parse(const char *json, size_t n, const repl_rule_t *old, int tls,
                        repl_rule_t *out, char *err, size_t errcap);

#endif
