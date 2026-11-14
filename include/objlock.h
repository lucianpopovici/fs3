/* include/objlock.h — Object Lock (item 10)
 *
 * Buckets created with x-amz-bucket-object-lock-enabled: true are
 * versioned forever. ?object-lock sets a default retention; per-version
 * retention / legal hold live in store lock sidecars. Enforcement is in
 * the store (store_set_version_guard → olock_guard), so lifecycle and the
 * admin API cannot bypass it: permanently deleting a version that is
 * under legal hold or unexpired retention is refused. COMPLIANCE can
 * only be extended; GOVERNANCE can be shortened or removed by an admin
 * with x-amz-bypass-governance-retention: true.
 *
 * This is API-level WORM: root on the NAS can still delete files.
 */
#ifndef FS3_OBJLOCK_H
#define FS3_OBJLOCK_H

#include <stdint.h>
#include "store.h"

typedef struct {
    int  mode;   /* default retention mode, 0 = none */
    long days;
} olock_cfg_t;

olock_cfg_t *olock_cfg_parse(const char *xml, size_t n, s3_err_t *err);
void        *olock_cfg_parse_cb(const char *xml, size_t n);
void         olock_cfg_free(void *o);

int         olock_mode_parse(const char *s);       /* -1 if invalid */
const char *olock_mode_name(int mode);

/* Effective lock for a version (sidecar, else bucket default from
 * mtime; unreadable sidecar fails closed). 0 if the bucket has no lock. */
int olock_effective(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                    const s3_obj_meta_t *m, s3_lock_t *out);

/* store_version_guard_fn; user = the store. */
s3_err_t olock_guard(void *user, s3_str_t bucket, s3_str_t key,
                     const s3_obj_meta_t *m, int bypass);

/* May retention go from cur to next? max_ms caps how far ahead (S9). */
s3_err_t olock_check_retention_change(const s3_lock_t *cur, const s3_lock_t *next,
                                      int bypass, uint64_t max_ms);

int olock_parse_date(const char *iso, uint64_t *out_ms);
int olock_parse_retention(const char *xml, size_t n, s3_lock_t *out);
int olock_parse_legal_hold(const char *xml, size_t n, int *on);

#endif
