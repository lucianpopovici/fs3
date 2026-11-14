/* src/scrub.c — background integrity scrub (round 2, item 3). See
 * include/scrub.h. */
#include "scrub.h"
#include "audit.h"
#include "iopool.h"
#include "json.h"
#include "log.h"
#include "store.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

enum { TREE_DATA, TREE_VERSIONS, TREE_MPU, TREE_LOCKS, TREE_N };
static const char *TREE_NAME[TREE_N] = { "data", "versions", "mpu", "locks" };

typedef struct {
    uint64_t pass, started, finished, last_success;
    int      tree;
    char     bucket[64];
    int      shard;
    uint64_t objects, bytes, unverifiable, corrupt, gone;
} scrub_state_t;

struct scrub {
    scrub_cfg_t     cfg;
    pthread_mutex_t mu;
    scrub_state_t   st;              /* guarded by mu */
    int             running;         /* loop thread only */
    int             pending_now;     /* loop thread only */
    int             stop;            /* atomic */
    char            dir[4200], state_path[4300], log_path[4300];
    /* Prometheus counters (atomic). */
    uint64_t        m_objects, m_bytes, m_unverifiable, m_corrupt;
};

typedef struct { uint64_t dev, ino; } inode_t;

typedef struct {
    iojob_t   base;
    scrub_t  *sc;
    /* throttle */
    struct timespec t0;
    uint64_t  window_bytes;
    /* inodes with several links already verified this run */
    inode_t  *seen;
    size_t    seen_n, seen_cap;
} scrub_job_t;

static uint64_t now_s(void) { return (uint64_t)time(NULL); }

/* ---- state file ---------------------------------------------------------- */

static void state_load(scrub_t *sc) {
    FILE *f = fopen(sc->state_path, "re");
    if (!f) return;
    char line[256];
    scrub_state_t st;
    memset(&st, 0, sizeof(st));
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *v = eq + 1;
        v[strcspn(v, "\n")] = '\0';
        unsigned long long n = strtoull(v, NULL, 10);
        if      (!strcmp(line, "pass"))         st.pass = n;
        else if (!strcmp(line, "started"))      st.started = n;
        else if (!strcmp(line, "finished"))     st.finished = n;
        else if (!strcmp(line, "last_success")) st.last_success = n;
        else if (!strcmp(line, "tree"))         st.tree = n < TREE_N ? (int)n : TREE_N;
        else if (!strcmp(line, "shard"))        st.shard = n <= 256 ? (int)n : 256;
        else if (!strcmp(line, "objects"))      st.objects = n;
        else if (!strcmp(line, "bytes"))        st.bytes = n;
        else if (!strcmp(line, "unverifiable")) st.unverifiable = n;
        else if (!strcmp(line, "corrupt"))      st.corrupt = n;
        else if (!strcmp(line, "gone"))         st.gone = n;
        else if (!strcmp(line, "bucket") && strlen(v) < sizeof(st.bucket)
                 && store_valid_bucket_name((s3_str_t){ v, strlen(v) }))
            snprintf(st.bucket, sizeof(st.bucket), "%s", v);
    }
    fclose(f);
    sc->st = st;
}

/* tmp + fsync + rename + fsync(dir). Caller holds mu. */
static void state_save_locked(scrub_t *sc) {
    char tmp[4400], buf[1024];
    snprintf(tmp, sizeof(tmp), "%s.tmp", sc->state_path);
    const scrub_state_t *st = &sc->st;
    int n = snprintf(buf, sizeof(buf),
        "pass=%" PRIu64 "\nstarted=%" PRIu64 "\nfinished=%" PRIu64 "\nlast_success=%" PRIu64
        "\ntree=%d\nbucket=%s\nshard=%d\nobjects=%" PRIu64 "\nbytes=%" PRIu64
        "\nunverifiable=%" PRIu64 "\ncorrupt=%" PRIu64 "\ngone=%" PRIu64 "\n",
        st->pass, st->started, st->finished, st->last_success, st->tree, st->bucket,
        st->shard, st->objects, st->bytes, st->unverifiable, st->corrupt, st->gone);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) { LOG_W("scrub: cannot write %s: %s", tmp, strerror(errno)); return; }
    if (write(fd, buf, (size_t)n) != n || fsync(fd) < 0) {
        close(fd); unlink(tmp); return;
    }
    close(fd);
    if (rename(tmp, sc->state_path) < 0) { unlink(tmp); return; }
    int dfd = open(sc->dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) { fsync(dfd); close(dfd); }
}

/* Reload known-corrupt versions from the log (--scrub-fail-reads). */
static void corrupt_log_load(scrub_t *sc) {
    FILE *f = fopen(sc->log_path, "re");
    if (!f) return;
    char line[4096];
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        const char *d = strstr(line, "\"dev\":"), *i = strstr(line, "\"ino\":"),
                   *m = strstr(line, "\"mtime_ms\":");
        if (!d || !i || !m) continue;
        store_scrub_mark_corrupt(strtoull(d + 6, NULL, 10), strtoull(i + 6, NULL, 10),
                                 strtoull(m + 11, NULL, 10));
        n++;
    }
    fclose(f);
    if (n) LOG_I("scrub: %d known-corrupt version(s) loaded from %s", n, sc->log_path);
}

/* ---- create / destroy -------------------------------------------------------- */

scrub_t *scrub_create(const scrub_cfg_t *cfg) {
    scrub_t *sc = calloc(1, sizeof(*sc));
    if (!sc) return NULL;
    sc->cfg = *cfg;
    pthread_mutex_init(&sc->mu, NULL);
    snprintf(sc->dir, sizeof(sc->dir), "%s/scrub", store_root(cfg->store));
    snprintf(sc->state_path, sizeof(sc->state_path), "%s/state", sc->dir);
    snprintf(sc->log_path, sizeof(sc->log_path), "%s/corrupt.log", sc->dir);
    if (mkdir(sc->dir, 0700) < 0 && errno != EEXIST)
        LOG_W("scrub: mkdir %s: %s", sc->dir, strerror(errno));
    state_load(sc);
    if (!sc->st.pass && !sc->st.finished) {
        /* Fresh install: the first scheduled pass is one interval away. */
        sc->st.finished = now_s();
        pthread_mutex_lock(&sc->mu);
        state_save_locked(sc);
        pthread_mutex_unlock(&sc->mu);
    }
    sc->pending_now = cfg->start_now;
    store_scrub_fail_reads(cfg->fail_reads);
    if (cfg->fail_reads) corrupt_log_load(sc);
    return sc;
}

void scrub_stop(scrub_t *sc) { if (sc) __atomic_store_n(&sc->stop, 1, __ATOMIC_RELAXED); }

void scrub_destroy(scrub_t *sc) {
    if (!sc) return;
    pthread_mutex_destroy(&sc->mu);
    free(sc);
}

/* ---- the pass (iopool worker) --------------------------------------------- */

static int stopping(const scrub_t *sc) { return __atomic_load_n(&sc->stop, __ATOMIC_RELAXED); }

static void sleep_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) {}
}

/* Rate limit, and back off while request work is queued on the pool. */
static void throttle(void *ctx, uint64_t n) {
    scrub_job_t *j = ctx;
    scrub_t *sc = j->sc;
    for (int i = 0; i < 100 && !stopping(sc) && iopool_pending(sc->cfg.pool); i++) sleep_ms(20);
    if (!sc->cfg.rate) return;
    j->window_bytes += n;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double el = (double)(now.tv_sec - j->t0.tv_sec) + (double)(now.tv_nsec - j->t0.tv_nsec) / 1e9;
    double want = (double)j->window_bytes / (double)sc->cfg.rate;
    if (want > el) sleep_ms((long)((want - el) * 1000) + 1);
    if (el > 10) { j->t0 = now; j->window_bytes = 0; }     /* rolling window */
}

static int seen_inode(scrub_job_t *j, uint64_t dev, uint64_t ino) {
    for (size_t i = 0; i < j->seen_n; i++)
        if (j->seen[i].dev == dev && j->seen[i].ino == ino) return 1;
    if (j->seen_n == j->seen_cap) {
        size_t nc = j->seen_cap ? j->seen_cap * 2 : 64;
        inode_t *n = realloc(j->seen, nc * sizeof(*n));
        if (!n) return 0;
        j->seen = n; j->seen_cap = nc;
    }
    j->seen[j->seen_n++] = (inode_t){ dev, ino };
    return 0;
}

static void report_corrupt(scrub_t *sc, const char *bucket, const char *rel,
                           const store_scrub_result_t *r) {
    char vid[33] = "";
    int any = 0;
    for (int i = 0; i < 16; i++) any |= r->version_id[i];
    if (any) {
        static const char H[] = "0123456789abcdef";
        for (int i = 0; i < 16; i++) {
            vid[2*i] = H[r->version_id[i] >> 4];
            vid[2*i+1] = H[r->version_id[i] & 15];
        }
        vid[32] = '\0';
    }
    char line[4096], ts[32];
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);
    size_t o = (size_t)snprintf(line, sizeof(line), "{\"ts\":\"%s\",\"bucket\":", ts);
    json_put_str(line, sizeof(line), &o, bucket);
    o += (size_t)snprintf(line + o, sizeof(line) - o, ",\"key\":");
    json_put_str(line, sizeof(line), &o, r->key);
    o += (size_t)snprintf(line + o, sizeof(line) - o, ",\"version_id\":\"%s\",\"path\":", vid);
    json_put_str(line, sizeof(line), &o, rel);
    o += (size_t)snprintf(line + o, sizeof(line) - o, ",\"reason\":");
    json_put_str(line, sizeof(line), &o, r->reason);
    o += (size_t)snprintf(line + o, sizeof(line) - o,
        ",\"expected\":\"%s\",\"actual\":\"%s\",\"dev\":%" PRIu64 ",\"ino\":%" PRIu64
        ",\"mtime_ms\":%" PRIu64 "}\n", r->expected, r->actual, r->dev, r->ino, r->mtime_ms);
    int fd = open(sc->log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd >= 0) {
        if (write(fd, line, o) < 0) LOG_W("scrub: cannot append %s", sc->log_path);
        fsync(fd);
        close(fd);
    }
    LOG_E("scrub: CORRUPT %s (%s)", rel, r->reason);
    char ev[1400];
    snprintf(ev, sizeof(ev), "corrupt bucket=%s key=%.1024s version=%s path=%s reason=%s",
             bucket, r->key, vid[0] ? vid : "null", rel, r->reason);
    audit_event("scrub", ev);
    store_scrub_mark_corrupt(r->dev, r->ino, r->mtime_ms);
    __atomic_fetch_add(&sc->m_corrupt, 1, __ATOMIC_RELAXED);
}

/* Verify one file; re-confirm a failure under the key's stripe lock. */
static void check_file(scrub_job_t *j, const char *bucket, const char *path, int kind,
                       const char *lock_hex) {
    scrub_t *sc = j->sc;
    struct stat st;
    if (lstat(path, &st) < 0 || !S_ISREG(st.st_mode)) return;
    if (st.st_nlink > 1 && seen_inode(j, (uint64_t)st.st_dev, (uint64_t)st.st_ino)) return;
    store_scrub_result_t r;
    store_scrub_file(sc->cfg.store, path, kind, NULL, throttle, j, &r);
    if (r.verdict == SCRUB_CORRUPT) {
        store_scrub_result_t r2;
        store_scrub_file(sc->cfg.store, path, kind, lock_hex, NULL, NULL, &r2);
        if (r2.verdict != SCRUB_CORRUPT || r2.ino != r.ino) r.verdict = SCRUB_GONE;  /* replaced */
    }
    const char *rel = path + strlen(store_root(sc->cfg.store)) + 1;
    pthread_mutex_lock(&sc->mu);
    switch (r.verdict) {
    case SCRUB_OK:           sc->st.objects++; break;
    case SCRUB_UNVERIFIABLE: sc->st.objects++; sc->st.unverifiable++; break;
    case SCRUB_CORRUPT:      sc->st.objects++; sc->st.corrupt++; break;
    default:                 sc->st.gone++; break;
    }
    sc->st.bytes += r.bytes_read;
    pthread_mutex_unlock(&sc->mu);
    if (r.verdict != SCRUB_GONE) __atomic_fetch_add(&sc->m_objects, 1, __ATOMIC_RELAXED);
    if (r.verdict == SCRUB_UNVERIFIABLE) __atomic_fetch_add(&sc->m_unverifiable, 1, __ATOMIC_RELAXED);
    __atomic_fetch_add(&sc->m_bytes, r.bytes_read, __ATOMIC_RELAXED);
    if (r.verdict == SCRUB_CORRUPT) report_corrupt(sc, bucket, rel, &r);
}

static int is_hex64(const char *n) {
    if (strlen(n) != 64) return 0;
    for (const char *c = n; *c; c++)
        if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f'))) return 0;
    return 1;
}

static int is_hex32(const char *n) {
    if (strlen(n) != 32) return 0;
    for (const char *c = n; *c; c++)
        if (!((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f'))) return 0;
    return 1;
}

static int is_ventry(const char *n) {
    if (strlen(n) != 49 || n[16] != '-') return 0;
    for (int i = 0; i < 49; i++) {
        if (i == 16) continue;
        if (!((n[i] >= '0' && n[i] <= '9') || (n[i] >= 'a' && n[i] <= 'f'))) return 0;
    }
    return 1;
}

/* Files under dir: data shard → objects named <hex>; versions shard →
 * <hex>/<entry>; mpu → <upload>/part-NNNNN. */
static void scrub_shard(scrub_job_t *j, int tree, const char *bucket, int shard) {
    scrub_t *sc = j->sc;
    const char *root = store_root(sc->cfg.store);
    char base[4400];
    if (tree == TREE_MPU) snprintf(base, sizeof(base), "%s/mpu/%s", root, bucket);
    else snprintf(base, sizeof(base), "%s/%s/%s/%02x", root, TREE_NAME[tree], bucket, shard);
    DIR *d1 = opendir(base);
    if (!d1) return;
    struct dirent *e1;
    while ((e1 = readdir(d1)) != NULL && !stopping(sc)) {
        if (e1->d_name[0] == '.') continue;
        char p1[4700];
        snprintf(p1, sizeof(p1), "%s/%s", base, e1->d_name);
        DIR *d2 = opendir(p1);
        if (!d2) continue;
        struct dirent *e2;
        while ((e2 = readdir(d2)) != NULL && !stopping(sc)) {
            if (e2->d_name[0] == '.') continue;
            char p2[5000];
            snprintf(p2, sizeof(p2), "%s/%s", p1, e2->d_name);
            if (tree == TREE_DATA) {
                if (is_hex64(e2->d_name)) check_file(j, bucket, p2, STORE_SCRUB_OBJECT, e2->d_name);
            } else if (tree == TREE_MPU) {
                if (strlen(e2->d_name) == 10 && !strncmp(e2->d_name, "part-", 5))
                    check_file(j, bucket, p2, STORE_SCRUB_PART, NULL);
            } else if (is_hex64(e2->d_name)) {
                /* versions/…/<hex>/<entry>, locks/…/<hex>/<vid hex> */
                DIR *d3 = opendir(p2);
                if (!d3) continue;
                struct dirent *e3;
                while ((e3 = readdir(d3)) != NULL && !stopping(sc)) {
                    int lock = tree == TREE_LOCKS;
                    if (lock ? !is_hex32(e3->d_name) : !is_ventry(e3->d_name)) continue;
                    char p3[5400];
                    snprintf(p3, sizeof(p3), "%s/%s", p2, e3->d_name);
                    check_file(j, bucket, p3, lock ? STORE_SCRUB_LOCK : STORE_SCRUB_OBJECT,
                               e2->d_name);
                }
                closedir(d3);
            }
        }
        closedir(d2);
    }
    closedir(d1);
}

static int name_cmp(const void *a, const void *b) {
    return strcmp(((const s3_bucket_info_t *)a)->name, ((const s3_bucket_info_t *)b)->name);
}

static void scrub_run(iojob_t *jb) {
    scrub_job_t *j = (scrub_job_t *)jb;
    scrub_t *sc = j->sc;
    clock_gettime(CLOCK_MONOTONIC, &j->t0);
    /* Idle I/O class for this worker while the pass runs. */
    long old_prio = syscall(SYS_ioprio_get, 1 /* IOPRIO_WHO_PROCESS: this thread */, 0);
    syscall(SYS_ioprio_set, 1, 0, 3 << 13 /* IOPRIO_CLASS_IDLE */);

    pthread_mutex_lock(&sc->mu);
    if (!(sc->st.started && !sc->st.finished)) {
        uint64_t keep = sc->st.last_success;
        uint64_t pass = sc->st.pass + 1;
        memset(&sc->st, 0, sizeof(sc->st));
        sc->st.pass = pass;
        sc->st.last_success = keep;
        sc->st.started = now_s();
        LOG_I("scrub: pass %" PRIu64 " started", pass);
    } else {
        LOG_I("scrub: resuming pass %" PRIu64 " at %s/%s/%02x", sc->st.pass,
              sc->st.tree < TREE_N ? TREE_NAME[sc->st.tree] : "end", sc->st.bucket, sc->st.shard);
    }
    state_save_locked(sc);
    scrub_state_t cur = sc->st;
    pthread_mutex_unlock(&sc->mu);

    s3_bucket_info_t *bl = NULL;
    size_t nb = 0;
    if (store_list_buckets(sc->cfg.store, &bl, &nb) != S3_OK) { bl = NULL; nb = 0; }
    if (nb) qsort(bl, nb, sizeof(*bl), name_cmp);

    for (int tree = cur.tree; tree < TREE_N && !stopping(sc); tree++) {
        for (size_t bi = 0; bi < nb && !stopping(sc); bi++) {
            const char *b = bl[bi].name;
            int same = tree == cur.tree && cur.bucket[0];
            if (same && strcmp(b, cur.bucket) < 0) continue;
            int first = (same && !strcmp(b, cur.bucket)) ? cur.shard : 0;
            int nshards = tree == TREE_MPU ? 1 : 256;
            for (int sh = first; sh < nshards && !stopping(sc); sh++) {
                scrub_shard(j, tree, b, sh);
                if (stopping(sc)) break;     /* shard incomplete: redo it on resume */
                pthread_mutex_lock(&sc->mu);
                sc->st.tree = tree;
                snprintf(sc->st.bucket, sizeof(sc->st.bucket), "%s", b);
                sc->st.shard = sh + 1;
                state_save_locked(sc);
                pthread_mutex_unlock(&sc->mu);
            }
        }
        if (stopping(sc)) break;
        pthread_mutex_lock(&sc->mu);
        sc->st.tree = tree + 1;
        sc->st.bucket[0] = '\0';
        sc->st.shard = 0;
        state_save_locked(sc);
        pthread_mutex_unlock(&sc->mu);
        cur.bucket[0] = '\0';
    }

    if (!stopping(sc)) {
        /* Quota reconciliation: exact usage from disk; a bucket written
         * during its walk is left for the next pass. */
        for (size_t bi = 0; bi < nb && !stopping(sc); bi++) {
            int64_t drift = 0;
            s3_str_t bn = { bl[bi].name, strlen(bl[bi].name) };
            s3_err_t e = store_quota_recount(sc->cfg.store, bn, &drift);
            if (e == S3_OK && drift)
                LOG_W("scrub: bucket %s quota usage corrected by %+" PRId64 " bytes",
                      bl[bi].name, -drift);
        }
        pthread_mutex_lock(&sc->mu);
        sc->st.finished = now_s();
        if (!sc->st.corrupt) sc->st.last_success = sc->st.finished;
        state_save_locked(sc);
        LOG_I("scrub: pass %" PRIu64 " done: %" PRIu64 " file(s), %" PRIu64 " byte(s) read, %"
              PRIu64 " unverifiable, %" PRIu64 " corrupt", sc->st.pass, sc->st.objects,
              sc->st.bytes, sc->st.unverifiable, sc->st.corrupt);
        pthread_mutex_unlock(&sc->mu);
    } else {
        LOG_I("scrub: stopped; the pass resumes at the next start");
    }
    if (bl) store_buckets_free(bl, nb);
    if (old_prio >= 0) syscall(SYS_ioprio_set, 1, 0, old_prio);
}

static void scrub_done(iojob_t *jb) {
    scrub_job_t *j = (scrub_job_t *)jb;
    j->sc->running = 0;
    free(j->seen);
    free(j);
}

static int scrub_start(scrub_t *sc) {
    if (sc->running) return 1;
    if (!sc->cfg.pool) {
        LOG_W("scrub: --io-threads 0, scrub skipped (would block the loop)");
        return -1;
    }
    scrub_job_t *j = calloc(1, sizeof(*j));
    if (!j) return -1;
    j->base.run = scrub_run;
    j->base.done = scrub_done;
    j->sc = sc;
    sc->running = 1;
    __atomic_store_n(&sc->stop, 0, __ATOMIC_RELAXED);
    iopool_submit(sc->cfg.pool, &j->base);
    return 0;
}

void scrub_tick(scrub_t *sc, time_t now) {
    if (!sc || sc->running || stopping(sc) || !sc->cfg.pool) return;
    pthread_mutex_lock(&sc->mu);
    int interrupted = sc->st.started && !sc->st.finished;
    int due = sc->cfg.interval_days > 0
           && (uint64_t)now >= sc->st.finished + (uint64_t)sc->cfg.interval_days * 86400;
    pthread_mutex_unlock(&sc->mu);
    if (sc->pending_now || interrupted || due) {
        sc->pending_now = 0;
        scrub_start(sc);
    }
}

int scrub_request(scrub_t *sc) {
    if (!sc) return -1;
    return scrub_start(sc);
}

size_t scrub_status_json(scrub_t *sc, char *out, size_t cap) {
    pthread_mutex_lock(&sc->mu);
    scrub_state_t st = sc->st;
    pthread_mutex_unlock(&sc->mu);
    int n = snprintf(out, cap,
        "{\"running\":%s,\"pass\":%" PRIu64 ",\"started\":%" PRIu64 ",\"finished\":%" PRIu64
        ",\"last_success\":%" PRIu64 ",\"cursor\":{\"tree\":\"%s\",\"bucket\":\"%s\",\"shard\":%d},"
        "\"files\":%" PRIu64 ",\"bytes\":%" PRIu64 ",\"unverifiable\":%" PRIu64
        ",\"corrupt\":%" PRIu64 ",\"gone\":%" PRIu64 ",\"interval_days\":%d,\"rate\":%" PRIu64 "}",
        sc->running ? "true" : "false", st.pass, st.started, st.finished, st.last_success,
        st.tree < TREE_N ? TREE_NAME[st.tree] : "end", st.bucket, st.shard, st.objects, st.bytes,
        st.unverifiable, st.corrupt, st.gone, sc->cfg.interval_days, sc->cfg.rate);
    return n > 0 && (size_t)n < cap ? (size_t)n : 0;
}

int scrub_metrics(scrub_t *sc, char *out, size_t cap) {
    if (!sc) return 0;
    pthread_mutex_lock(&sc->mu);
    uint64_t last = sc->st.last_success;
    pthread_mutex_unlock(&sc->mu);
    int n = snprintf(out, cap,
        "# HELP fs3_scrub_objects_total Files verified by the integrity scrub.\n"
        "# TYPE fs3_scrub_objects_total counter\nfs3_scrub_objects_total %" PRIu64 "\n"
        "# HELP fs3_scrub_bytes_total Bytes read by the integrity scrub.\n"
        "# TYPE fs3_scrub_bytes_total counter\nfs3_scrub_bytes_total %" PRIu64 "\n"
        "# HELP fs3_scrub_unverifiable_total Files with nothing to verify against.\n"
        "# TYPE fs3_scrub_unverifiable_total counter\nfs3_scrub_unverifiable_total %" PRIu64 "\n"
        "# HELP fs3_scrub_corrupt_total Corrupt files found by the integrity scrub.\n"
        "# TYPE fs3_scrub_corrupt_total counter\nfs3_scrub_corrupt_total %" PRIu64 "\n"
        "# HELP fs3_scrub_last_success_timestamp End of the last pass that found no corruption.\n"
        "# TYPE fs3_scrub_last_success_timestamp gauge\nfs3_scrub_last_success_timestamp %" PRIu64 "\n",
        __atomic_load_n(&sc->m_objects, __ATOMIC_RELAXED),
        __atomic_load_n(&sc->m_bytes, __ATOMIC_RELAXED),
        __atomic_load_n(&sc->m_unverifiable, __ATOMIC_RELAXED),
        __atomic_load_n(&sc->m_corrupt, __ATOMIC_RELAXED), last);
    return n > 0 && (size_t)n < cap ? n : -1;
}
