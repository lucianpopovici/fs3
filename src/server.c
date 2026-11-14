/* src/server.c — epoll accept loop + connection dispatch
 *
 * Single-threaded for Phase 0. The hot path:
 *   epoll_wait → accept new conns or deliver readable/writable events
 *   to existing conn_t objects, which run their own state machine.
 *
 * Connections are tracked via a flat array indexed by epoll event data;
 * we store the conn_t pointer directly in epoll_event.data.ptr. The
 * listening fd is distinguished by data.ptr == NULL.
 */

#include "server.h"
#include "action.h"
#include "lifecycle.h"
#include "admin.h"
#include "conn.h"
#include "iopool.h"
#include "log.h"
#include "metrics.h"
#include "store.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define MAX_EVENTS 64

struct server {
    server_cfg_t  cfg;
    int           listen_fd;
    int           web_fd;       /* website listener, -1 if off */
    int           admin_fd;     /* -1 unless cfg.metrics_port > 0 */
    int           admin_uds_fd; /* -1 unless cfg.admin_socket */
    admin_ctx_t  *admin;
    int           epoll_fd;
    fs3_metrics_t metrics;      /* plain counters; single-threaded loop */
    volatile int  stop;
    int           n_conns;
    conn_t       *conns_head;   /* intrusive doubly-linked list */
    s3_store_t   *store;        /* shared object store */
    iopool_t     *pool;         /* NULL when cfg.io_threads == 0 */
    /* Periodic multipart-upload GC. We piggyback on the epoll_wait
     * timeout — once every gc_interval_ms of wall clock, sweep the MPU
     * staging area and reap any upload older than gc_max_age_ms. */
    time_t        gc_last_run;       /* monotonic seconds */
    int           lc_running;        /* a sweep job is in flight */
    int           lc_last_yday;      /* day of year of the last scheduled run */
    int           lc_pending_now;    /* run at the first tick (--lifecycle-now) */
    int           gc_interval_s;     /* sweep cadence */
    uint64_t      gc_max_age_ms;     /* TTL */
    /* Idle-connection sweep (cfg.idle_timeout_s > 0). Runs at most once
     * per second, after the event batch is processed — never before,
     * since the events array may hold pointers into conns we'd free. */
    time_t        idle_last_sweep;
    time_t        tick_last;         /* cfg.tick_cb cadence limiter */
};

static void list_push(conn_t **head, conn_t *c) {
    c->list_prev = NULL;
    c->list_next = *head;
    if (*head) (*head)->list_prev = c;
    *head = c;
}

static void list_remove(conn_t **head, conn_t *c) {
    if (c->list_prev) c->list_prev->list_next = c->list_next;
    else              *head = c->list_next;
    if (c->list_next) c->list_next->list_prev = c->list_prev;
    c->list_prev = c->list_next = NULL;
}

static int listen_socket(const char *addr, uint16_t port, int backlog) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    /* SO_REUSEPORT later, when we go multi-threaded */

    struct sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(port);
    if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
        LOG_E("invalid bind address: %s", addr);
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        LOG_E("bind %s:%u: %s", addr, port, strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, backlog) < 0) {
        LOG_E("listen: %s", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/* ------------------------------------------------------------------- */
/* Admin listener: GET /healthz + GET /metrics on 127.0.0.1 only.      */
/*                                                                     */
/* Deliberately not wired into the conn_t/llhttp machinery: requests   */
/* are two fixed paths from local monitoring agents. The socket is     */
/* handled synchronously with short send/recv timeouts — worst case a  */
/* local client stalls the loop for ~200 ms, which is an acceptable    */
/* trade for keeping the admin path ~60 lines with no state machine.   */
/* ------------------------------------------------------------------- */

static void admin_respond(int fd, const char *status, const char *ctype,
                          const char *body, size_t blen) {
    char head[256];
    int n = snprintf(head, sizeof(head),
                     "HTTP/1.1 %s\r\n"
                     "Server: fs3/0.2\r\n"
                     "Content-Type: %s\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     status, ctype, blen);
    if (n < 0 || n >= (int)sizeof(head)) return;
    (void)!write(fd, head, (size_t)n);
    if (blen) (void)!write(fd, body, blen);
}

/* Render bucket stats as plain text, one bucket per line:
 *   <name> <objects> <bytes>\n
 * Easy to consume from shell (the DSM tile's CGI) and from scripts.
 * Returns bytes written, or -1 if cap was too small. */
static int admin_render_buckets(struct s3_store *store,
                                char *buf, size_t cap) {
    s3_bucket_info_t *list = NULL;
    size_t n = 0;
    if (store_list_buckets(store, &list, &n) != S3_OK) return -1;

    size_t off = 0;
    int rc = 0;
    for (size_t i = 0; i < n; i++) {
        s3_bucket_stats_t bs;
        s3_str_t name = { list[i].name, strlen(list[i].name) };
        if (store_bucket_stats(store, name, &bs) != S3_OK) continue;
        int w = snprintf(buf + off, cap - off, "%s %llu %llu\n",
                         list[i].name,
                         (unsigned long long)bs.objects,
                         (unsigned long long)bs.bytes);
        if (w < 0 || (size_t)w >= cap - off) { rc = -1; break; }
        off += (size_t)w;
    }
    store_buckets_free(list, n);
    return rc < 0 ? -1 : (int)off;
}

/* Read one admin request: headers, then Content-Length body (≤ 16 KiB).
 * Sockets have short timeouts; this is a localhost control channel. */
static ssize_t admin_read_request(int fd, char *req, size_t cap) {
    size_t n = 0;
    for (;;) {
        if (n + 1 >= cap) return -1;
        ssize_t r = read(fd, req + n, cap - 1 - n);
        if (r <= 0) return n ? (ssize_t)n : -1;
        n += (size_t)r;
        req[n] = '\0';
        char *end = strstr(req, "\r\n\r\n");
        if (!end) continue;
        size_t clen = 0;
        for (char *h = req; h && h < end; h = strstr(h, "\r\n")) {
            if (*h == '\r') h += 2;
            if (strncasecmp(h, "content-length:", 15) == 0) {
                clen = strtoul(h + 15, NULL, 10);
                break;
            }
        }
        if (clen > 16 * 1024) return -1;
        if (n >= (size_t)(end + 4 - req) + clen) return (ssize_t)n;
    }
}

static void admin_serve_fd(server_t *s, int fd, int via_uds) {
    struct timeval tv = { .tv_usec = 200 * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    static char req[20 * 1024];
    ssize_t r = admin_read_request(fd, req, sizeof(req));
    if (r <= 0) return;

    if (strncmp(req, "GET /v1/", 8) == 0 || strncmp(req, "POST /v1/", 9) == 0
        || strncmp(req, "PUT /v1/", 8) == 0 || strncmp(req, "DELETE /v1/", 11) == 0) {
        size_t rn = 0;
        char *resp = s->admin ? admin_handle_v1(s->admin, req, (size_t)r, via_uds, &rn) : NULL;
        if (resp) {
            (void)!write(fd, resp, rn);
            free(resp);
        }
        return;
    }
    if (via_uds) {
        admin_respond(fd, "404 Not Found", "text/plain", "not found\n", 10);
        return;
    }
    if (strncmp(req, "GET /healthz", 12) == 0
        || strncmp(req, "HEAD /healthz", 13) == 0) {
        admin_respond(fd, "200 OK", "text/plain", "ok\n", 3);
    } else if (strncmp(req, "GET /buckets", 12) == 0) {
        static char body[64 * 1024];
        int blen = admin_render_buckets(s->store, body, sizeof(body));
        if (blen < 0) {
            admin_respond(fd, "500 Internal Server Error",
                          "text/plain", "render overflow\n", 16);
        } else {
            admin_respond(fd, "200 OK", "text/plain", body, (size_t)blen);
        }
    } else if (strncmp(req, "GET /metrics", 12) == 0) {
        static char body[64 * 1024];
        int blen = metrics_render(&s->metrics, s->store, body, sizeof(body));
        if (blen < 0) {
            admin_respond(fd, "500 Internal Server Error",
                          "text/plain", "render overflow\n", 16);
        } else {
            admin_respond(fd, "200 OK", "text/plain; version=0.0.4",
                          body, (size_t)blen);
        }
    } else {
        admin_respond(fd, "404 Not Found", "text/plain", "not found\n", 10);
    }
}

static void admin_handle(server_t *s, int lfd, int via_uds) {
    for (;;) {
        int fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EINTR) continue;
            return;  /* EAGAIN — drained */
        }
        if (via_uds) {
            /* S10: only our own uid (or root) may use the socket, on top
             * of its 0600 mode. */
            struct ucred cr;
            socklen_t cl = sizeof(cr);
            if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &cl) < 0
                || (cr.uid != geteuid() && cr.uid != 0)) {
                LOG_W("admin socket: refused peer uid");
                close(fd);
                continue;
            }
        }
        admin_serve_fd(s, fd, via_uds);
        close(fd);
    }
}

server_t *server_create(const server_cfg_t *cfg) {
    if (action_selfcheck() != 0) {
        LOG_E("action table incomplete: refusing to start (default deny)");
        return NULL;
    }
    server_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->cfg = *cfg;
    s->listen_fd = -1;
    s->web_fd = -1;
    s->admin_uds_fd = -1;
    s->admin_fd = -1;
    s->epoll_fd = -1;

    if (!cfg->data_root) {
        LOG_E("server_create: data_root not set");
        goto fail;
    }
    if (store_open(&s->store, cfg->data_root) != S3_OK) {
        LOG_E("store_open(%s) failed", cfg->data_root);
        goto fail;
    }
    if (cfg->min_free_bytes > 0) {
        store_set_min_free_bytes(s->store, cfg->min_free_bytes);
        LOG_I("disk quota: min %.1f MiB free required",
              (double)cfg->min_free_bytes / (1024.0 * 1024.0));
    }
    LOG_I("store opened at %s", cfg->data_root);

    if (cfg->legacy_owner) {
        int n = store_assign_legacy_owner(s->store, cfg->legacy_owner);
        if (n < 0) {
            LOG_E("--legacy-owner: cannot list buckets");
            goto fail;
        }
        if (n > 0) LOG_I("assigned %d ownerless bucket(s) to '%s'",
                         n, cfg->legacy_owner);
    } else if (cfg->auth) {
        /* Say so up front rather than let users discover 403s. */
        s3_bucket_info_t *list = NULL;
        size_t nb = 0, ownerless = 0;
        if (store_list_buckets(s->store, &list, &nb) == S3_OK) {
            for (size_t i = 0; i < nb; i++) ownerless += !list[i].owner[0];
            store_buckets_free(list, nb);
        }
        if (ownerless > 0)
            LOG_W("%zu bucket(s) have no owner and are visible to --admin "
                  "users only; assign them with --legacy-owner <user>",
                  ownerless);
    }

    if (cfg->io_threads > 0) {
        s->pool = iopool_create(cfg->io_threads);
        if (!s->pool) {
            LOG_E("iopool_create(%d) failed", cfg->io_threads);
            goto fail;
        }
        LOG_I("io pool: %d worker thread(s)", cfg->io_threads);
    }

    s->listen_fd = listen_socket(cfg->bind_addr, cfg->port, cfg->backlog);
    if (s->listen_fd < 0) goto fail;

    s->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (s->epoll_fd < 0) {
        LOG_E("epoll_create1: %s", strerror(errno));
        goto fail;
    }

    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.ptr = NULL,           /* NULL ptr = listen fd marker */
    };
    if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->listen_fd, &ev) < 0) {
        LOG_E("epoll_ctl ADD listen: %s", strerror(errno));
        goto fail;
    }

    LOG_I("listening on %s:%u", cfg->bind_addr, cfg->port);

    if (s->pool) {
        struct epoll_event pev = {
            .events = EPOLLIN,
            .data.ptr = s->pool,    /* pool ptr = job-completion marker */
        };
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, iopool_fd(s->pool),
                      &pev) < 0) {
            LOG_E("epoll_ctl ADD iopool: %s", strerror(errno));
            goto fail;
        }
    }

    /* Admin API (item 11). */
    {
        admin_cfg_t ac = {
            .store = s->store, .token = cfg->admin_token,
            .cred_file = cfg->admin_cred_file,
            .reload = cfg->admin_reload, .reload_user = cfg->admin_reload_user,
        };
        s->admin = admin_create(&ac);
        if (!s->admin) goto fail;
    }
    if (cfg->admin_socket) {
        struct sockaddr_un su = { .sun_family = AF_UNIX };
        if (strlen(cfg->admin_socket) >= sizeof(su.sun_path)) {
            LOG_E("--admin-socket path too long");
            goto fail;
        }
        snprintf(su.sun_path, sizeof(su.sun_path), "%s", cfg->admin_socket);
        struct stat lst;
        if (lstat(su.sun_path, &lst) == 0) {
            if (!S_ISSOCK(lst.st_mode)) {
                LOG_E("--admin-socket %s exists and is not a socket", su.sun_path);
                goto fail;
            }
            unlink(su.sun_path);
        }
        s->admin_uds_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        mode_t old = umask(0177);          /* socket file created 0600 */
        int br = s->admin_uds_fd < 0 ? -1
               : bind(s->admin_uds_fd, (struct sockaddr *)&su, sizeof(su));
        umask(old);
        if (br < 0 || chmod(su.sun_path, 0600) < 0 || listen(s->admin_uds_fd, 16) < 0) {
            LOG_E("admin socket %s: %s", su.sun_path, strerror(errno));
            goto fail;
        }
        struct epoll_event uev = { .events = EPOLLIN, .data.ptr = &s->admin_uds_fd };
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->admin_uds_fd, &uev) < 0) goto fail;
        LOG_I("admin API on unix:%s", su.sun_path);
    }

    /* Website listener (item 6). */
    if (cfg->web_port > 0) {
        s->web_fd = listen_socket(cfg->web_addr ? cfg->web_addr : "127.0.0.1",
                                  cfg->web_port, cfg->backlog);
        if (s->web_fd < 0) goto fail;
        struct epoll_event wev = { .events = EPOLLIN, .data.ptr = &s->web_fd };
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->web_fd, &wev) < 0) {
            LOG_E("epoll_ctl ADD web: %s", strerror(errno));
            goto fail;
        }
        LOG_I("website listener on %s:%u (root domain %s)",
              cfg->web_addr ? cfg->web_addr : "127.0.0.1", cfg->web_port,
              cfg->web_root_domain ? cfg->web_root_domain : "-");
    }

    /* Admin/metrics listener — localhost only, by design. */
    if (cfg->metrics_port > 0) {
        s->admin_fd = listen_socket("127.0.0.1", cfg->metrics_port, 16);
        if (s->admin_fd < 0) goto fail;
        struct epoll_event aev = {
            .events = EPOLLIN,
            .data.ptr = s,          /* server ptr = admin listener marker */
        };
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, s->admin_fd, &aev) < 0) {
            LOG_E("epoll_ctl ADD admin: %s", strerror(errno));
            goto fail;
        }
        LOG_I("metrics on 127.0.0.1:%u (/healthz, /metrics)",
              cfg->metrics_port);
    }

    /* GC defaults: sweep every 60s, reap uploads older than 24h.
     * Config may override either for testing or admin policy. */
    s->gc_interval_s = cfg->gc_interval_s > 0 ? cfg->gc_interval_s : 60;
    s->gc_max_age_ms = cfg->gc_max_age_ms > 0
                       ? cfg->gc_max_age_ms
                       : (24ULL * 3600 * 1000);
    s->gc_last_run = time(NULL);
    s->lc_last_yday = -1;
    s->lc_pending_now = cfg->lifecycle_now;
    /* Bucket lifecycle abort rules override the global MPU TTL. */
    store_set_mpu_gc_filter(s->store, lc_mpu_gc_filter, s->store);
    return s;

fail:
    server_destroy(s);
    return NULL;
}

void server_destroy(server_t *s) {
    if (!s) return;
    /* Drain any still-open connections. */
    while (s->conns_head) {
        conn_t *c = s->conns_head;
        list_remove(&s->conns_head, c);
        if (s->epoll_fd >= 0) {
            epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
        }
        close(c->fd);
        conn_destroy(c);            /* orphans any job still in flight */
    }
    /* Workers finish what they hold (a client's fully-received PUT still
     * gets committed) before the store they write into goes away. */
    iopool_destroy(s->pool);
    if (s->listen_fd >= 0) close(s->listen_fd);
    if (s->web_fd >= 0) close(s->web_fd);
    if (s->admin_uds_fd >= 0) {
        close(s->admin_uds_fd);
        if (s->cfg.admin_socket) unlink(s->cfg.admin_socket);
    }
    admin_destroy(s->admin);
    if (s->admin_fd  >= 0) close(s->admin_fd);
    if (s->epoll_fd  >= 0) close(s->epoll_fd);
    if (s->store) store_close(s->store);
    free(s);
}

void server_stop(server_t *s) { if (s) s->stop = 1; }

/* Update epoll registration to match what the connection currently wants. */
static int reset_conn_events(server_t *s, conn_t *c) {
    uint32_t ev = EPOLLRDHUP;
    /* Once peer has closed write-side, no point asking for more EPOLLIN
     * (level-triggered EOF would busy-loop). */
    if (!c->eof_seen) ev |= EPOLLIN;
    if (conn_wants_write(c)) ev |= EPOLLOUT;
    /* Parked on an iopool job: nothing to read or write until it's done,
     * and a level-triggered RDHUP would spin. Only ERR/HUP (always
     * reported) can wake us, meaning the peer is gone for good. */
    if (c->state == CST_WAIT_JOB) ev = 0;
    struct epoll_event e = { .events = ev, .data.ptr = c };
    if (epoll_ctl(s->epoll_fd, EPOLL_CTL_MOD, c->fd, &e) < 0) {
        LOG_W("epoll_ctl MOD fd=%d: %s", c->fd, strerror(errno));
        return -1;
    }
    return 0;
}

static void close_conn(server_t *s, conn_t *c);

/* iopool_reap callback: the job's done() has built c's response (or
 * marked it closing). Re-arm epoll so EPOLLOUT picks the response up. */
static void job_finished(struct conn *c, void *user) {
    server_t *s = user;
    c->last_activity = time(NULL);
    if (c->state == CST_CLOSING && !conn_wants_write(c)) {
        close_conn(s, c);
        return;
    }
    reset_conn_events(s, c);
}

static void close_conn(server_t *s, conn_t *c) {
    epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
    LOG_D("closing conn fd=%d peer=%s", c->fd, c->peer);
    list_remove(&s->conns_head, c);
    close(c->fd);
    conn_destroy(c);
    s->n_conns--;
}

static void accept_new(server_t *s, int lfd, int is_web) {
    for (;;) {
        struct sockaddr_in sa;
        socklen_t slen = sizeof(sa);
        int fd = accept4(lfd, (struct sockaddr *)&sa, &slen,
                         SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EINTR) continue;
            LOG_W("accept: %s", strerror(errno));
            return;
        }

        if (s->n_conns >= s->cfg.max_conns) {
            LOG_W("conn cap reached (%d), rejecting", s->cfg.max_conns);
            close(fd);
            continue;
        }

        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        char peer[64];
        inet_ntop(AF_INET, &sa.sin_addr, peer, sizeof(peer));
        size_t pl = strlen(peer);
        snprintf(peer + pl, sizeof(peer) - pl, ":%u", ntohs(sa.sin_port));

        conn_t *c = conn_create(fd, peer, s->store, s->pool,
                                s->cfg.auth, s->cfg.auth_required,
                                s->cfg.max_body_bytes, &s->metrics);
        if (!c) {
            LOG_E("conn_create OOM");
            close(fd);
            continue;
        }
        c->last_activity = time(NULL);
        c->is_web = is_web;
        c->web_root_domain = s->cfg.web_root_domain;
        c->allow_public = s->cfg.allow_public;
        c->allow_public_write = s->cfg.allow_public_write;
        c->trusted_proxies = s->cfg.trusted_proxies;

        struct epoll_event ev = {
            .events = EPOLLIN | EPOLLRDHUP,
            .data.ptr = c,
        };
        if (epoll_ctl(s->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            LOG_E("epoll_ctl ADD: %s", strerror(errno));
            close(fd);
            conn_destroy(c);
            continue;
        }

        list_push(&s->conns_head, c);
        s->n_conns++;
        LOG_D("accepted fd=%d peer=%s n_conns=%d", fd, peer, s->n_conns);
    }
}

/* ---- Lifecycle sweep job (item 5) ------------------------------------- */

typedef struct {
    iojob_t     base;
    server_t   *srv;
    lc_opts_t   opts;
    lc_stats_t  stats;
} lc_job_t;

static void lc_job_run(iojob_t *j) {
    lc_job_t *lj = (lc_job_t *)j;
    lc_sweep(lj->srv->store, &lj->opts, &lj->stats);
}

static void lc_job_done(iojob_t *j) {
    lc_job_t *lj = (lc_job_t *)j;
    lj->srv->lc_running = 0;
    __atomic_fetch_add(&lj->srv->metrics.lifecycle_runs_total, 1, __ATOMIC_RELAXED);
    LOG_I("lifecycle: %llu bucket(s) with rules, %llu object(s) scanned, "
          "%llu expired, %llu upload(s) aborted, %llu skipped (changed)%s",
          (unsigned long long)lj->stats.buckets,
          (unsigned long long)lj->stats.scanned,
          (unsigned long long)lj->stats.expired,
          (unsigned long long)lj->stats.aborted,
          (unsigned long long)lj->stats.skipped_changed,
          lj->opts.dry_run ? " [dry run]" : "");
    free(lj);
}

static void lc_maybe_start(server_t *s, time_t now) {
    if (s->lc_running) return;
    int due = s->lc_pending_now;
    if (!due && s->cfg.lifecycle_hour >= 0) {
        struct tm lt;
        localtime_r(&now, &lt);
        due = lt.tm_hour == s->cfg.lifecycle_hour && lt.tm_yday != s->lc_last_yday;
        if (due) s->lc_last_yday = lt.tm_yday;
    }
    if (!due) return;
    s->lc_pending_now = 0;
    lc_job_t *lj = calloc(1, sizeof(*lj));
    if (!lj) return;
    lj->base.run  = lc_job_run;
    lj->base.done = lc_job_done;
    lj->srv = s;
    lj->opts.now_ms = ((int64_t)now + s->cfg.lifecycle_time_offset_s) * 1000;
    lj->opts.rate_per_s = s->cfg.lifecycle_rate;
    lj->opts.dry_run = s->cfg.lifecycle_dry_run;
    lj->opts.expired_total = &s->metrics.lifecycle_expired_total;
    lj->opts.aborted_total = &s->metrics.lifecycle_aborted_mpu_total;
    s->lc_running = 1;
    /* Never walk buckets on the event loop: without a pool (io_threads 0)
     * the sweep is skipped. */
    if (!s->pool) {
        LOG_W("lifecycle: --io-threads 0, sweep skipped (would block the loop)");
        s->lc_running = 0;
        free(lj);
        return;
    }
    LOG_I("lifecycle: sweep started");
    iopool_submit(s->pool, &lj->base);
}

int server_run(server_t *s) {
    struct epoll_event events[MAX_EVENTS];

    while (!s->stop) {
        int n = epoll_wait(s->epoll_fd, events, MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            LOG_E("epoll_wait: %s", strerror(errno));
            return -1;
        }

        time_t now = time(NULL);

        /* Owner's once-per-second tick (e.g. SIGHUP credential reload).
         * Runs between batches, so never concurrently with a request. */
        if (s->cfg.tick_cb && now != s->tick_last) {
            s->tick_last = now;
            s->cfg.tick_cb(s->cfg.tick_user);
        }

        /* Periodic MPU GC. We piggyback on the 1s epoll timeout: every
         * gc_interval_s seconds (wall clock), sweep the staging area
         * and reap any abandoned upload older than gc_max_age_ms. */
        if (s->gc_interval_s > 0
            && now - s->gc_last_run >= s->gc_interval_s) {
            int reaped = store_mpu_gc(s->store,
                                      (uint64_t)now * 1000,
                                      s->gc_max_age_ms);
            if (reaped > 0) LOG_I("mpu_gc: reaped %d stale upload(s)", reaped);
            s->gc_last_run = now;
        }

        lc_maybe_start(s, now);

        int jobs_ready = 0;
        for (int i = 0; i < n; i++) {
            struct epoll_event *e = &events[i];

            /* Listening socket */
            if (e->data.ptr == NULL) {
                if (e->events & EPOLLIN) accept_new(s, s->listen_fd, 0);
                continue;
            }
            /* Website listener (marker: &s->web_fd). */
            if (e->data.ptr == (void *)&s->web_fd) {
                if (e->events & EPOLLIN) accept_new(s, s->web_fd, 1);
                continue;
            }

            /* Admin/metrics listener (marker: the server pointer). */
            if (e->data.ptr == (void *)s) {
                if (e->events & EPOLLIN) admin_handle(s, s->admin_fd, 0);
                continue;
            }
            if (e->data.ptr == (void *)&s->admin_uds_fd) {
                if (e->events & EPOLLIN) admin_handle(s, s->admin_uds_fd, 1);
                continue;
            }

            /* iopool job completions (marker: the pool pointer). Reaped
             * after the batch: job_finished may close a conn that a later
             * entry of this batch still points at. */
            if (s->pool && e->data.ptr == (void *)s->pool) {
                jobs_ready = 1;
                continue;
            }

            conn_t *c = e->data.ptr;
            c->last_activity = now;

            /* Parked on a job: only ERR/HUP get here, i.e. the peer is
             * gone. Close now; conn_destroy orphans the job. */
            if (c->state == CST_WAIT_JOB) {
                close_conn(s, c);
                continue;
            }

            if (e->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                /* Drain any final readable data first, but on hard error close. */
                if (e->events & EPOLLERR) { close_conn(s, c); continue; }
            }

            if (e->events & EPOLLIN) {
                if (conn_on_readable(c) < 0) { close_conn(s, c); continue; }
            }
            if (e->events & EPOLLOUT) {
                if (conn_on_writable(c) < 0) { close_conn(s, c); continue; }
            }

            /* Hangup with nothing more to write AND no buffered work → close. */
            if ((e->events & EPOLLRDHUP) && conn_hup_can_close(c)) {
                close_conn(s, c);
                continue;
            }

            if (c->state == CST_CLOSING && !conn_wants_write(c)) {
                close_conn(s, c);
                continue;
            }

            reset_conn_events(s, c);
        }

        /* Job completions, AFTER the event batch (see the marker above). */
        if (jobs_ready) iopool_reap(s->pool, job_finished, s);

        /* Idle-connection sweep, AFTER the event batch: closing during
         * the batch would leave dangling pointers in events[]. A slow
         * but progressing client keeps refreshing last_activity above,
         * so only truly stalled connections are reclaimed. */
        if (s->cfg.idle_timeout_s > 0 && now != s->idle_last_sweep) {
            s->idle_last_sweep = now;
            conn_t *c = s->conns_head;
            while (c) {
                conn_t *next = c->list_next;
                /* A conn waiting on its job isn't idle: a multi-GB copy
                 * can legitimately take longer than the timeout. */
                if (c->state != CST_WAIT_JOB
                    && now - c->last_activity >= s->cfg.idle_timeout_s) {
                    LOG_D("closing idle conn fd=%d peer=%s (%llds)",
                          c->fd, c->peer,
                          (long long)(now - c->last_activity));
                    close_conn(s, c);
                }
                c = next;
            }
        }
    }

    LOG_I("event loop exiting");
    return 0;
}
