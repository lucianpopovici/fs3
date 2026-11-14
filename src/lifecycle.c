/* src/lifecycle.c — LifecycleConfiguration parsing and the sweeper. */

#include "lifecycle.h"
#include "log.h"
#include "store.h"
#include "xml_parser.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DAY_MS 86400000LL

void lc_free(lc_config_t *c) {
    if (!c) return;
    for (size_t i = 0; i < c->n_rules; i++) free(c->rules[i].prefix);
    free(c->rules);
    free(c);
}
void lc_free_cb(void *o) { lc_free(o); }
void *lc_parse_cb(const char *xml, size_t n) {
    s3_err_t e;
    return lc_parse(xml, n, &e);
}

static const char *trimmed(const XMLNode *n, size_t *len) {
    const char *t = n->content ? n->content : "";
    while (*t == ' ' || *t == '\n' || *t == '\r' || *t == '\t') t++;
    size_t l = strlen(t);
    while (l && (t[l-1] == ' ' || t[l-1] == '\n' || t[l-1] == '\r' || t[l-1] == '\t')) l--;
    *len = l;
    return t;
}

static int parse_pos_long(const XMLNode *n, long max, long *out) {
    size_t l;
    const char *t = trimmed(n, &l);
    if (l == 0 || l > 9) return -1;
    long v = 0;
    for (size_t i = 0; i < l; i++) {
        if (t[i] < '0' || t[i] > '9') return -1;
        v = v * 10 + (t[i] - '0');
    }
    if (v < 1 || v > max) return -1;
    *out = v;
    return 0;
}

/* "YYYY-MM-DD" or "YYYY-MM-DDT00:00:00[.000]Z"; must be midnight UTC. */
static int parse_date_ms(const XMLNode *n, int64_t *out) {
    size_t l;
    const char *t = trimmed(n, &l);
    if (l < 10 || t[4] != '-' || t[7] != '-') return -1;
    for (int i = 0; i < 10; i++) {
        if (i == 4 || i == 7) continue;
        if (t[i] < '0' || t[i] > '9') return -1;
    }
    if (l > 10) {
        static const char *const ok[] = { "T00:00:00Z", "T00:00:00.000Z",
                                          "T00:00:00+00:00", "T00:00:00.000+00:00" };
        int match = 0;
        for (size_t i = 0; i < sizeof(ok) / sizeof(*ok); i++)
            if (l - 10 == strlen(ok[i]) && memcmp(t + 10, ok[i], l - 10) == 0) match = 1;
        if (!match) return -1;
    }
    struct tm tm = {0};
    tm.tm_year = (t[0]-'0')*1000 + (t[1]-'0')*100 + (t[2]-'0')*10 + (t[3]-'0') - 1900;
    tm.tm_mon  = (t[5]-'0')*10 + (t[6]-'0') - 1;
    tm.tm_mday = (t[8]-'0')*10 + (t[9]-'0');
    if (tm.tm_mon < 0 || tm.tm_mon > 11 || tm.tm_mday < 1 || tm.tm_mday > 31) return -1;
    time_t secs = timegm(&tm);
    if (secs == (time_t)-1) return -1;
    *out = (int64_t)secs * 1000;
    return 0;
}

static char *dup_text(const XMLNode *n) {
    size_t l;
    const char *t = trimmed(n, &l);
    if (l > 1024) return NULL;
    char *s = malloc(l + 1);
    if (!s) return NULL;
    memcpy(s, t, l);
    s[l] = '\0';
    return s;
}

/* Filter: empty | <Prefix> | <And><Prefix/></And>. Tags/sizes → 501. */
static s3_err_t parse_filter(const XMLNode *f, lc_rule_t *r) {
    for (int i = 0; i < f->child_count; i++) {
        const XMLNode *c = f->children[i];
        if (strcmp(c->local_name, "Prefix") == 0) {
            if (r->prefix) return S3_ERR_MALFORMED_XML;
            if (!(r->prefix = dup_text(c))) return S3_ERR_MALFORMED_XML;
        } else if (strcmp(c->local_name, "And") == 0) {
            for (int j = 0; j < c->child_count; j++) {
                const XMLNode *a = c->children[j];
                if (strcmp(a->local_name, "Prefix") == 0) {
                    if (r->prefix) return S3_ERR_MALFORMED_XML;
                    if (!(r->prefix = dup_text(a))) return S3_ERR_MALFORMED_XML;
                } else if (!strcmp(a->local_name, "Tag")
                           || !strncmp(a->local_name, "ObjectSize", 10)) {
                    return S3_ERR_NOT_IMPLEMENTED;
                } else {
                    return S3_ERR_MALFORMED_XML;
                }
            }
        } else if (!strcmp(c->local_name, "Tag")
                   || !strncmp(c->local_name, "ObjectSize", 10)) {
            return S3_ERR_NOT_IMPLEMENTED;
        } else {
            return S3_ERR_MALFORMED_XML;
        }
    }
    return S3_OK;
}

static s3_err_t parse_rule(const XMLNode *rn, lc_rule_t *r) {
    int have_status = 0, have_action = 0, have_filter = 0;
    for (int i = 0; i < rn->child_count; i++) {
        const XMLNode *c = rn->children[i];
        const char *nm = c->local_name;
        size_t l;
        if (!strcmp(nm, "ID")) {
            trimmed(c, &l);
            if (l > 255) return S3_ERR_INVALID_ARGUMENT;
        } else if (!strcmp(nm, "Status")) {
            const char *t = trimmed(c, &l);
            if (l == 7 && !memcmp(t, "Enabled", 7)) r->enabled = 1;
            else if (l == 8 && !memcmp(t, "Disabled", 8)) r->enabled = 0;
            else return S3_ERR_MALFORMED_XML;
            have_status = 1;
        } else if (!strcmp(nm, "Filter")) {
            if (have_filter) return S3_ERR_MALFORMED_XML;
            have_filter = 1;
            s3_err_t e = parse_filter(c, r);
            if (e != S3_OK) return e;
        } else if (!strcmp(nm, "Prefix")) {          /* legacy form */
            if (have_filter || r->prefix) return S3_ERR_MALFORMED_XML;
            if (!(r->prefix = dup_text(c))) return S3_ERR_MALFORMED_XML;
        } else if (!strcmp(nm, "Expiration")) {
            for (int j = 0; j < c->child_count; j++) {
                const XMLNode *e = c->children[j];
                if (!strcmp(e->local_name, "Days")) {
                    if (parse_pos_long(e, 100000, &r->exp_days) < 0)
                        return S3_ERR_INVALID_ARGUMENT;
                } else if (!strcmp(e->local_name, "Date")) {
                    if (parse_date_ms(e, &r->exp_date_ms) < 0)
                        return S3_ERR_INVALID_ARGUMENT;
                } else if (!strcmp(e->local_name, "ExpiredObjectDeleteMarker")) {
                    const char *t = trimmed(e, &l);
                    r->exp_delete_marker = (l == 4 && !memcmp(t, "true", 4));
                } else {
                    return S3_ERR_MALFORMED_XML;
                }
            }
            if ((r->exp_days && r->exp_date_ms)
                || (!r->exp_days && !r->exp_date_ms && !r->exp_delete_marker))
                return S3_ERR_INVALID_ARGUMENT;
            have_action = 1;
        } else if (!strcmp(nm, "AbortIncompleteMultipartUpload")) {
            const XMLNode *d = find_child((XMLNode *)c, "DaysAfterInitiation");
            if (!d || parse_pos_long(d, 100000, &r->abort_days) < 0)
                return S3_ERR_INVALID_ARGUMENT;
            have_action = 1;
        } else if (!strcmp(nm, "NoncurrentVersionExpiration")) {
            const XMLNode *d = find_child((XMLNode *)c, "NoncurrentDays");
            if (!d || parse_pos_long(d, 100000, &r->noncurrent_days) < 0)
                return S3_ERR_INVALID_ARGUMENT;
            have_action = 1;
        } else if (!strcmp(nm, "Transition") || !strcmp(nm, "NoncurrentVersionTransition")) {
            return S3_ERR_NOT_IMPLEMENTED;
        } else {
            return S3_ERR_MALFORMED_XML;
        }
    }
    if (!have_status || !have_action) return S3_ERR_MALFORMED_XML;
    if (!r->prefix && !(r->prefix = strdup(""))) return S3_ERR_INTERNAL;
    return S3_OK;
}

lc_config_t *lc_parse(const char *xml, size_t n, s3_err_t *err) {
    *err = S3_ERR_MALFORMED_XML;
    if (n > LC_MAX_BYTES) return NULL;
    xml_parse_opts_t po = { .max_depth = 8, .max_nodes = 32768 };
    XMLNode *root = parse_xml(xml, n, &po, NULL);
    if (!root) return NULL;
    lc_config_t *c = calloc(1, sizeof(*c));
    if (!c || strcmp(root->local_name, "LifecycleConfiguration") != 0
        || root->child_count == 0 || root->child_count > LC_MAX_RULES) {
        if (c && root->child_count > LC_MAX_RULES) *err = S3_ERR_INVALID_ARGUMENT;
        goto bad;
    }
    c->rules = calloc((size_t)root->child_count, sizeof(*c->rules));
    if (!c->rules) goto bad;
    for (int i = 0; i < root->child_count; i++) {
        if (strcmp(root->children[i]->local_name, "Rule") != 0) goto bad;
        c->n_rules++;
        s3_err_t e = parse_rule(root->children[i], &c->rules[i]);
        if (e != S3_OK) { *err = e; goto bad; }
    }
    free_tree(root);
    *err = S3_OK;
    return c;
bad:
    free_tree(root);
    lc_free(c);
    return NULL;
}

static int matches(const lc_rule_t *r, s3_str_t key) {
    size_t pn = strlen(r->prefix);
    return r->enabled && key.n >= pn && memcmp(key.p, r->prefix, pn) == 0;
}

int lc_has_immediate_rule(const lc_config_t *c, int64_t now_ms) {
    for (size_t i = 0; i < c->n_rules; i++)
        if (c->rules[i].enabled && c->rules[i].exp_date_ms
            && c->rules[i].exp_date_ms <= now_ms) return 1;
    return 0;
}

int64_t lc_expiry_ms(const lc_config_t *c, s3_str_t key, uint64_t mtime_ms) {
    int64_t best = 0;
    for (size_t i = 0; i < c->n_rules; i++) {
        const lc_rule_t *r = &c->rules[i];
        if (!matches(r, key)) continue;
        int64_t t = 0;
        if (r->exp_days) {
            /* AWS: midnight UTC after mtime + Days. */
            int64_t raw = (int64_t)mtime_ms + r->exp_days * DAY_MS;
            t = ((raw + DAY_MS - 1) / DAY_MS) * DAY_MS;
        } else if (r->exp_date_ms) {
            t = r->exp_date_ms;
        }
        if (t && (!best || t < best)) best = t;
    }
    return best;
}

int64_t lc_abort_after_ms(const lc_config_t *c, s3_str_t key) {
    int64_t best = 0;
    for (size_t i = 0; i < c->n_rules; i++) {
        const lc_rule_t *r = &c->rules[i];
        if (!matches(r, key) || !r->abort_days) continue;
        int64_t t = r->abort_days * DAY_MS;
        if (!best || t < best) best = t;
    }
    return best;
}

/* ---- Sweeper -------------------------------------------------------- */

typedef struct { char *key; size_t n; uint64_t mtime; int marker; uint8_t vid[16]; } victim_t;

typedef struct {
    const lc_config_t *cfg;
    int64_t now;
    victim_t *v;
    size_t n, cap;
    uint64_t scanned;
    int versioned;
    /* Keys whose noncurrent versions need checking. */
    char **keys; size_t *klen; size_t nk, kcap;
} collect_t;

static int any_rule(const lc_config_t *c, s3_str_t key, int what) {
    for (size_t i = 0; i < c->n_rules; i++) {
        const lc_rule_t *r = &c->rules[i];
        size_t pn = strlen(r->prefix);
        if (!r->enabled || key.n < pn || memcmp(key.p, r->prefix, pn)) continue;
        if (what == 0 && r->exp_delete_marker) return 1;
        if (what == 1 && r->noncurrent_days) return 1;
    }
    return 0;
}

static int64_t noncurrent_after_ms(const lc_config_t *c, s3_str_t key) {
    int64_t best = 0;
    for (size_t i = 0; i < c->n_rules; i++) {
        const lc_rule_t *r = &c->rules[i];
        size_t pn = strlen(r->prefix);
        if (!r->enabled || !r->noncurrent_days || key.n < pn || memcmp(key.p, r->prefix, pn))
            continue;
        int64_t t = r->noncurrent_days * DAY_MS;
        if (!best || t < best) best = t;
    }
    return best;
}

static int push_victim(collect_t *cl, s3_str_t key, uint64_t mtime, int marker,
                       const uint8_t *vid) {
    if (cl->n == cl->cap) {
        size_t nc = cl->cap ? cl->cap * 2 : 64;
        victim_t *nv = realloc(cl->v, nc * sizeof(*nv));
        if (!nv) return -1;
        cl->v = nv; cl->cap = nc;
    }
    char *k = malloc(key.n);
    if (!k) return -1;
    memcpy(k, key.p, key.n);
    victim_t *v = &cl->v[cl->n++];
    memset(v, 0, sizeof(*v));
    v->key = k; v->n = key.n; v->mtime = mtime; v->marker = marker;
    if (vid) memcpy(v->vid, vid, 16);
    return 0;
}

static int collect_cb(void *user, s3_str_t key, const s3_obj_meta_t *m) {
    collect_t *cl = user;
    cl->scanned++;
    if (cl->versioned && any_rule(cl->cfg, key, 1)) {
        if (cl->nk == cl->kcap) {
            size_t nc = cl->kcap ? cl->kcap * 2 : 64;
            char **nk = realloc(cl->keys, nc * sizeof(*nk));
            size_t *nl = realloc(cl->klen, nc * sizeof(*nl));
            if (nk) cl->keys = nk;
            if (nl) cl->klen = nl;
            if (!nk || !nl) return 1;
            cl->kcap = nc;
        }
        char *k = malloc(key.n);
        if (!k) return 1;
        memcpy(k, key.p, key.n);
        cl->keys[cl->nk] = k;
        cl->klen[cl->nk++] = key.n;
    }
    if (m->flags & S3_OBJF_DELETE_MARKER) {
        /* ExpiredObjectDeleteMarker: a marker with nothing behind it.
         * Checked again at delete time below. */
        if (any_rule(cl->cfg, key, 0))
            return push_victim(cl, key, m->mtime_ms, 1, m->version_id) < 0;
        return 0;
    }
    int64_t t = lc_expiry_ms(cl->cfg, key, m->mtime_ms);
    if (!t || t > cl->now) return 0;
    return push_victim(cl, key, m->mtime_ms, 0, NULL) < 0;
}

static void pace(int rate) {
    if (rate <= 0) return;
    struct timespec ts = { 0, 1000000000L / rate };
    if (rate == 1) { ts.tv_sec = 1; ts.tv_nsec = 0; }
    nanosleep(&ts, NULL);
}

void lc_sweep(struct s3_store *s, const lc_opts_t *o, lc_stats_t *out) {
    memset(out, 0, sizeof(*out));
    s3_bucket_info_t *bl = NULL;
    size_t nb = 0;
    if (store_list_buckets(s, &bl, &nb) != S3_OK) return;
    for (size_t b = 0; b < nb; b++) {
        s3_str_t bucket = { bl[b].name, strlen(bl[b].name) };
        store_cfg_ref_t *ref = store_sidecar_get(s, bucket, "lifecycle.xml",
                                                 LC_MAX_BYTES, lc_parse_cb, lc_free_cb);
        if (!ref) continue;
        const lc_config_t *cfg = store_cfg_obj(ref);
        out->buckets++;

        s3_bucket_meta_t bm;
        collect_t cl = { .cfg = cfg, .now = o->now_ms };
        cl.versioned = store_bucket_meta(s, bucket, &bm) == S3_OK && bm.versioning;
        store_walk_objects(s, bucket, collect_cb, &cl);
        out->scanned += cl.scanned;
        for (size_t i = 0; i < cl.n; i++) {
            s3_str_t k = { cl.v[i].key, cl.v[i].n };
            if (cl.v[i].marker) {
                s3_noncurrent_t *nc = NULL;
                size_t nn = 0;
                store_list_noncurrent(s, bucket, k, &nc, &nn);
                free(nc);
                if (nn == 0 && !o->dry_run
                    && store_delete_ex(s, bucket, k, cl.v[i].vid, NULL) == S3_OK) {
                    out->expired++;
                    if (o->expired_total)
                        __atomic_fetch_add(o->expired_total, 1, __ATOMIC_RELAXED);
                }
                free(cl.v[i].key);
                continue;
            }
            if (o->dry_run) {
                LOG_I("lifecycle (dry run): would expire %s/%.*s", bl[b].name,
                      (int)k.n, k.p);
            } else {
                s3_err_t e = store_expire_if_unchanged(s, bucket, k, cl.v[i].mtime);
                if (e == S3_OK) {
                    out->expired++;
                    if (o->expired_total)
                        __atomic_fetch_add(o->expired_total, 1, __ATOMIC_RELAXED);
                    pace(o->rate_per_s);
                } else if (e == S3_ERR_INVALID_REQUEST) {
                    out->skipped_changed++;      /* overwritten mid-sweep */
                }
            }
            free(cl.v[i].key);
        }
        free(cl.v);

        /* NoncurrentVersionExpiration: delete versions that have been
         * noncurrent for NoncurrentDays (object lock can veto). */
        for (size_t i = 0; i < cl.nk; i++) {
            s3_str_t k = { cl.keys[i], cl.klen[i] };
            int64_t after = noncurrent_after_ms(cfg, k);
            s3_noncurrent_t *nc = NULL;
            size_t nn = 0;
            if (after && store_list_noncurrent(s, bucket, k, &nc, &nn) == S3_OK) {
                for (size_t j = 0; j < nn; j++) {
                    if ((int64_t)nc[j].noncurrent_since_ms + after > o->now_ms) continue;
                    if (o->dry_run) {
                        LOG_I("lifecycle (dry run): would expire a noncurrent version of %s/%.*s",
                              bl[b].name, (int)k.n, k.p);
                        continue;
                    }
                    if (store_delete_ex(s, bucket, k, nc[j].vid, NULL) == S3_OK) {
                        out->expired++;
                        if (o->expired_total)
                            __atomic_fetch_add(o->expired_total, 1, __ATOMIC_RELAXED);
                        pace(o->rate_per_s);
                    }
                }
            }
            free(nc);
            free(cl.keys[i]);
        }
        free(cl.keys);
        free(cl.klen);

        s3_mpu_info_t *ups = NULL;
        size_t nu = 0;
        if (store_list_mpu_uploads(s, bucket, S3_STR_NULL, &ups, &nu) == S3_OK) {
            for (size_t i = 0; i < nu; i++) {
                s3_str_t k = { ups[i].key, strlen(ups[i].key) };
                int64_t after = lc_abort_after_ms(cfg, k);
                if (!after || (int64_t)ups[i].ctime_ms + after > o->now_ms) continue;
                if (o->dry_run) {
                    LOG_I("lifecycle (dry run): would abort upload %s in %s",
                          ups[i].upload_id, bl[b].name);
                    continue;
                }
                if (store_mpu_abort(s, bucket, k, ups[i].upload_id) == S3_OK) {
                    out->aborted++;
                    if (o->aborted_total)
                        __atomic_fetch_add(o->aborted_total, 1, __ATOMIC_RELAXED);
                }
            }
            store_mpu_uploads_free(ups, nu);
        }
        store_sidecar_put(s, ref);
    }
    store_buckets_free(bl, nb);
}

int lc_mpu_gc_filter(void *store, s3_str_t bucket, s3_str_t key) {
    store_cfg_ref_t *ref = store_sidecar_get(store, bucket, "lifecycle.xml",
                                             LC_MAX_BYTES, lc_parse_cb, lc_free_cb);
    if (!ref) return 0;
    int covered = lc_abort_after_ms(store_cfg_obj(ref), key) > 0;
    store_sidecar_put(store, ref);
    return covered;
}
