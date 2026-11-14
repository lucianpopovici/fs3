/* src/objlock.c — Object Lock policy (item 10). See include/objlock.h. */

#include "objlock.h"
#include "log.h"
#include "xml_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DAY_MS 86400000ULL

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static const char *txt(XMLNode *n) {
    return n && n->content ? n->content : "";
}

int olock_mode_parse(const char *s) {
    if (!strcmp(s, "GOVERNANCE")) return S3_LOCK_GOVERNANCE;
    if (!strcmp(s, "COMPLIANCE")) return S3_LOCK_COMPLIANCE;
    return -1;
}

const char *olock_mode_name(int m) {
    return m == S3_LOCK_COMPLIANCE ? "COMPLIANCE" : m == S3_LOCK_GOVERNANCE ? "GOVERNANCE" : "";
}

/* ---- Bucket default retention (?object-lock) ------------------------- */

void olock_cfg_free(void *o) { free(o); }

olock_cfg_t *olock_cfg_parse(const char *xml, size_t n, s3_err_t *err) {
    *err = S3_ERR_MALFORMED_XML;
    xml_parse_opts_t po = { .max_depth = 6, .max_nodes = 64 };
    XMLNode *root = parse_xml(xml, n, &po, NULL);
    if (!root || strcmp(root->local_name, "ObjectLockConfiguration")) { free_tree(root); return NULL; }
    olock_cfg_t *c = calloc(1, sizeof(*c));
    if (!c) { free_tree(root); return NULL; }
    if (strcmp(txt(find_child(root, "ObjectLockEnabled")), "Enabled")) goto bad;
    XMLNode *rule = find_child(root, "Rule");
    if (rule) {
        XMLNode *dr = find_child(rule, "DefaultRetention");
        if (!dr) goto bad;
        c->mode = olock_mode_parse(txt(find_child(dr, "Mode")));
        XMLNode *d = find_child(dr, "Days"), *y = find_child(dr, "Years");
        if (c->mode < 0 || !!d == !!y) { *err = S3_ERR_INVALID_ARGUMENT; goto bad; }
        long v = atol(txt(d ? d : y));
        if (v < 1 || v > 36500) { *err = S3_ERR_INVALID_ARGUMENT; goto bad; }
        c->days = d ? v : v * 365;
    }
    free_tree(root);
    *err = S3_OK;
    return c;
bad:
    free_tree(root);
    free(c);
    return NULL;
}

void *olock_cfg_parse_cb(const char *xml, size_t n) {
    s3_err_t e;
    return olock_cfg_parse(xml, n, &e);
}

/* ---- Effective lock of one version ----------------------------------- */

int olock_effective(s3_store_t *s, s3_str_t bucket, s3_str_t key,
                    const s3_obj_meta_t *m, s3_lock_t *out) {
    memset(out, 0, sizeof(*out));
    if (!store_bucket_object_lock(s, bucket)) return 0;
    int r = store_lock_read(s, bucket, key, m->version_id, out);
    if (r == 0) return 1;
    /* Absent → bucket default retention from mtime; unreadable → fail
     * closed (S9): treat as locked by the default, or, without one, as a
     * GOVERNANCE lock that only an admin bypass can lift. */
    store_cfg_ref_t *ref = store_sidecar_get(s, bucket, "object-lock.xml", 16384,
                                             olock_cfg_parse_cb, olock_cfg_free);
    const olock_cfg_t *c = store_cfg_obj(ref);
    if (c && c->mode) {
        out->mode = c->mode;
        out->until_ms = m->mtime_ms + (uint64_t)c->days * DAY_MS;
    } else if (r < 0) {
        out->mode = S3_LOCK_GOVERNANCE;
        out->until_ms = UINT64_MAX;
        LOG_W("object lock: unreadable lock record, treating version as locked");
    }
    store_sidecar_put(s, ref);
    return 1;
}

s3_err_t olock_guard(void *user, s3_str_t bucket, s3_str_t key,
                     const s3_obj_meta_t *m, int bypass) {
    s3_store_t *s = user;
    s3_lock_t l;
    if (!olock_effective(s, bucket, key, m, &l)) return S3_OK;
    if (l.legal_hold) return S3_ERR_LOCKED;
    if (l.until_ms <= now_ms() || l.mode == S3_LOCK_NONE) return S3_OK;
    if (l.mode == S3_LOCK_GOVERNANCE && bypass) return S3_OK;
    return S3_ERR_LOCKED;
}

/* ---- Retention changes ------------------------------------------------ */

s3_err_t olock_check_retention_change(const s3_lock_t *cur, const s3_lock_t *next,
                                      int bypass, uint64_t max_ms) {
    uint64_t now = now_ms();
    if (next->mode && next->until_ms <= now) return S3_ERR_INVALID_ARGUMENT;
    if (next->mode && max_ms && next->until_ms > now + max_ms) return S3_ERR_INVALID_ARGUMENT;
    int active = cur->mode && cur->until_ms > now;
    if (!active) return S3_OK;
    int shortening = !next->mode || next->until_ms < cur->until_ms;
    if (cur->mode == S3_LOCK_COMPLIANCE) {
        /* COMPLIANCE can be extended, never shortened, removed or
         * switched to GOVERNANCE. */
        if (shortening || next->mode != S3_LOCK_COMPLIANCE) return S3_ERR_LOCKED;
        return S3_OK;
    }
    if (shortening && !bypass) return S3_ERR_LOCKED;
    return S3_OK;
}

/* "2030-01-01T00:00:00Z" / ".000Z" → ms. */
int olock_parse_date(const char *t, uint64_t *out) {
    int Y, M, D, h, mi;
    double sec;
    char z = 0;
    if (sscanf(t, "%4d-%2d-%2dT%2d:%2d:%lf%c", &Y, &M, &D, &h, &mi, &sec, &z) < 7 || z != 'Z')
        return -1;
    if (M < 1 || M > 12 || D < 1 || D > 31 || h > 23 || mi > 59 || sec < 0 || sec >= 61) return -1;
    struct tm tm = { .tm_year = Y - 1900, .tm_mon = M - 1, .tm_mday = D,
                     .tm_hour = h, .tm_min = mi, .tm_sec = (int)sec };
    time_t tt = timegm(&tm);
    if (tt == (time_t)-1) return -1;
    *out = (uint64_t)tt * 1000 + (uint64_t)((sec - (int)sec) * 1000);
    return 0;
}

int olock_parse_retention(const char *xml, size_t n, s3_lock_t *out) {
    xml_parse_opts_t po = { .max_depth = 4, .max_nodes = 16 };
    XMLNode *root = parse_xml(xml, n, &po, NULL);
    if (!root || strcmp(root->local_name, "Retention")) { free_tree(root); return -1; }
    XMLNode *m = find_child(root, "Mode"), *d = find_child(root, "RetainUntilDate");
    int rc = 0;
    memset(out, 0, sizeof(*out));
    if (m || d) {
        out->mode = m ? olock_mode_parse(txt(m)) : -1;
        if (out->mode < 0 || !d || olock_parse_date(txt(d), &out->until_ms) < 0) rc = -1;
    }
    free_tree(root);
    return rc;
}

int olock_parse_legal_hold(const char *xml, size_t n, int *on) {
    xml_parse_opts_t po = { .max_depth = 4, .max_nodes = 8 };
    XMLNode *root = parse_xml(xml, n, &po, NULL);
    if (!root || strcmp(root->local_name, "LegalHold")) { free_tree(root); return -1; }
    const char *st = txt(find_child(root, "Status"));
    int rc = 0;
    if (!strcmp(st, "ON")) *on = 1;
    else if (!strcmp(st, "OFF")) *on = 0;
    else rc = -1;
    free_tree(root);
    return rc;
}
