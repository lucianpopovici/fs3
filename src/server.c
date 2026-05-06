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
#include "conn.h"
#include "log.h"
#include "store.h"

#include <time.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_EVENTS 64

struct server {
    server_cfg_t  cfg;
    int           listen_fd;
    int           epoll_fd;
    volatile int  stop;
    int           n_conns;
    conn_t       *conns_head;   /* intrusive doubly-linked list */
    s3_store_t   *store;        /* shared object store */
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

server_t *server_create(const server_cfg_t *cfg) {
    server_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->cfg = *cfg;
    s->listen_fd = -1;
    s->epoll_fd = -1;

    if (!cfg->data_root) {
        LOG_E("server_create: data_root not set");
        goto fail;
    }
    if (store_open(&s->store, cfg->data_root) != S3_OK) {
        LOG_E("store_open(%s) failed", cfg->data_root);
        goto fail;
    }
    LOG_I("store opened at %s", cfg->data_root);

    /* Initial GC sweep on startup to clean up leftovers from previous runs. */
    if (cfg->mpu_gc_age_secs > 0) {
        int n = store_mpu_gc(s->store, cfg->mpu_gc_age_secs);
        if (n > 0) LOG_I("mpu gc: removed %d stale upload(s) at startup", n);
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
        conn_destroy(c);
    }
    if (s->listen_fd >= 0) close(s->listen_fd);
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
    struct epoll_event e = { .events = ev, .data.ptr = c };
    if (epoll_ctl(s->epoll_fd, EPOLL_CTL_MOD, c->fd, &e) < 0) {
        LOG_W("epoll_ctl MOD fd=%d: %s", c->fd, strerror(errno));
        return -1;
    }
    return 0;
}

static void close_conn(server_t *s, conn_t *c) {
    epoll_ctl(s->epoll_fd, EPOLL_CTL_DEL, c->fd, NULL);
    LOG_D("closing conn fd=%d peer=%s", c->fd, c->peer);
    list_remove(&s->conns_head, c);
    close(c->fd);
    conn_destroy(c);
    s->n_conns--;
}

static void accept_new(server_t *s) {
    for (;;) {
        struct sockaddr_in sa;
        socklen_t slen = sizeof(sa);
        int fd = accept4(s->listen_fd, (struct sockaddr *)&sa, &slen,
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

        conn_t *c = conn_create(fd, peer, s->store,
                                s->cfg.auth, s->cfg.auth_required);
        if (!c) {
            LOG_E("conn_create OOM");
            close(fd);
            continue;
        }

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

#define GC_INTERVAL_SECS 60

int server_run(server_t *s) {
    struct epoll_event events[MAX_EVENTS];
    time_t last_gc = time(NULL);

    while (!s->stop) {
        int n = epoll_wait(s->epoll_fd, events, MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR) continue;
            LOG_E("epoll_wait: %s", strerror(errno));
            return -1;
        }

        /* Periodic GC sweep (runs at most once per GC_INTERVAL_SECS). */
        if (s->cfg.mpu_gc_age_secs > 0) {
            time_t now = time(NULL);
            if (now - last_gc >= GC_INTERVAL_SECS) {
                last_gc = now;
                int nr = store_mpu_gc(s->store, s->cfg.mpu_gc_age_secs);
                if (nr > 0)
                    LOG_I("mpu gc: removed %d stale upload(s)", nr);
            }
        }

        for (int i = 0; i < n; i++) {
            struct epoll_event *e = &events[i];

            /* Listening socket */
            if (e->data.ptr == NULL) {
                if (e->events & EPOLLIN) accept_new(s);
                continue;
            }

            conn_t *c = e->data.ptr;

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

            /* Hangup with nothing more to write AND no buffered work → close.
             * If we're CST_WRITE_RESPONSE we'll send what we have first; if
             * rbuf still has bytes the parser will consume them. */
            if ((e->events & EPOLLRDHUP) && !conn_wants_write(c)
                && c->rlen == 0
                && c->state != CST_WRITE_RESPONSE) {
                close_conn(s, c);
                continue;
            }

            if (c->state == CST_CLOSING && !conn_wants_write(c)) {
                close_conn(s, c);
                continue;
            }

            reset_conn_events(s, c);
        }
    }

    LOG_I("event loop exiting");
    return 0;
}
