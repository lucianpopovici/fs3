/* include/scrub.h — background integrity scrub (round 2, item 3)
 *
 * One pass walks data/, versions/ and mpu/ bucket by bucket, shard by
 * shard (the first hash-prefix level), on an iopool worker: never on the
 * event loop. The cursor (scrub/state) is saved after every shard, so a
 * restart resumes the pass. Corruption is reported (scrub/corrupt.log,
 * audit log, metrics) and never repaired or deleted. At the end of a pass
 * bucket quota counters are reconciled with what is on disk.
 */
#ifndef FS3_SCRUB_H
#define FS3_SCRUB_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

struct s3_store;
struct iopool;

typedef struct {
    struct s3_store *store;
    struct iopool   *pool;
    int              interval_days;   /* 0 = never scheduled (still on demand) */
    int              start_now;       /* --scrub-now */
    uint64_t         rate;            /* bytes/s, 0 = unthrottled */
    int              fail_reads;      /* --scrub-fail-reads */
} scrub_cfg_t;

typedef struct scrub scrub_t;

scrub_t *scrub_create(const scrub_cfg_t *cfg);
/* Event loop, once a second: start a due or interrupted pass. */
void     scrub_tick(scrub_t *sc, time_t now);
/* The worker pool, once created (it is created after seccomp). */
void     scrub_set_pool(scrub_t *sc, struct iopool *pool);
/* Admin API: start a pass now. 0 started, 1 already running, -1 no pool. */
int      scrub_request(scrub_t *sc);
/* Progress / last result as a JSON object (NUL-terminated). */
size_t   scrub_status_json(scrub_t *sc, char *out, size_t cap);
/* Prometheus lines. Returns bytes written or -1 if cap is too small. */
int      scrub_metrics(scrub_t *sc, char *out, size_t cap);
/* Before iopool_destroy: ask a running pass to stop at the next file
 * (its cursor is saved; the next start resumes). */
void     scrub_stop(scrub_t *sc);
void     scrub_destroy(scrub_t *sc);

#endif
