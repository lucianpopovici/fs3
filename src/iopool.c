/* src/iopool.c — fixed-size worker pool for blocking store work
 *
 * One mutex guards both the pending queue and the completed list; jobs
 * are coarse (an fsync at least), so contention is irrelevant. Workers
 * block all signals so SIGINT/SIGTERM/SIGHUP always land on the loop
 * thread and interrupt its epoll_wait.
 */
#include "iopool.h"
#include "log.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

struct iopool {
    pthread_mutex_t mu;
    pthread_cond_t  cv;          /* signalled when q_head becomes non-empty */
    iojob_t        *q_head, *q_tail;   /* pending, FIFO */
    iojob_t        *done_head;         /* completed, any order */
    int             stop;
    int             efd;
    int             n_threads;
    pthread_t      *threads;
};

static void *worker_main(void *arg) {
    iopool_t *p = arg;
    for (;;) {
        pthread_mutex_lock(&p->mu);
        while (!p->q_head && !p->stop)
            pthread_cond_wait(&p->cv, &p->mu);
        iojob_t *j = p->q_head;
        if (!j) {                      /* stop requested and queue drained */
            pthread_mutex_unlock(&p->mu);
            return NULL;
        }
        p->q_head = j->next;
        if (!p->q_head) p->q_tail = NULL;
        pthread_mutex_unlock(&p->mu);

        j->run(j);

        pthread_mutex_lock(&p->mu);
        j->next = p->done_head;
        p->done_head = j;
        pthread_mutex_unlock(&p->mu);

        uint64_t one = 1;
        while (write(p->efd, &one, sizeof(one)) < 0 && errno == EINTR) {}
    }
}

iopool_t *iopool_create(int n_threads) {
    if (n_threads < 1) return NULL;
    iopool_t *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    p->threads = calloc((size_t)n_threads, sizeof(*p->threads));
    if (p->efd < 0 || !p->threads) {
        LOG_E("iopool_create: %s", strerror(errno));
        if (p->efd >= 0) close(p->efd);
        free(p->threads);
        free(p);
        return NULL;
    }
    pthread_mutex_init(&p->mu, NULL);
    pthread_cond_init(&p->cv, NULL);

    sigset_t all, old;
    sigfillset(&all);
    pthread_sigmask(SIG_BLOCK, &all, &old);
    for (int i = 0; i < n_threads; i++) {
        int e = pthread_create(&p->threads[i], NULL, worker_main, p);
        if (e != 0) {
            LOG_E("iopool_create: pthread_create: %s", strerror(e));
            break;
        }
        p->n_threads++;
    }
    pthread_sigmask(SIG_SETMASK, &old, NULL);

    if (p->n_threads < n_threads) {
        iopool_destroy(p);
        return NULL;
    }
    return p;
}

void iopool_destroy(iopool_t *p) {
    if (!p) return;
    pthread_mutex_lock(&p->mu);
    p->stop = 1;
    pthread_cond_broadcast(&p->cv);
    pthread_mutex_unlock(&p->mu);
    for (int i = 0; i < p->n_threads; i++) pthread_join(p->threads[i], NULL);

    /* Workers drained the queue before exiting; release what they left. */
    iopool_reap(p, NULL, NULL);

    pthread_cond_destroy(&p->cv);
    pthread_mutex_destroy(&p->mu);
    close(p->efd);
    free(p->threads);
    free(p);
}

void iopool_submit(iopool_t *p, iojob_t *j) {
    j->next = NULL;
    if (!p) {
        j->run(j);
        j->done(j);
        return;
    }
    pthread_mutex_lock(&p->mu);
    if (p->q_tail) p->q_tail->next = j;
    else           p->q_head = j;
    p->q_tail = j;
    pthread_cond_signal(&p->cv);
    pthread_mutex_unlock(&p->mu);
}

int iopool_fd(const iopool_t *p) { return p ? p->efd : -1; }

int iopool_reap(iopool_t *p,
                void (*after)(struct conn *c, void *user), void *user) {
    if (!p) return 0;
    uint64_t n;
    (void)!read(p->efd, &n, sizeof(n));   /* reset the counter; EAGAIN ok */

    pthread_mutex_lock(&p->mu);
    iojob_t *j = p->done_head;
    p->done_head = NULL;
    pthread_mutex_unlock(&p->mu);

    int reaped = 0;
    while (j) {
        iojob_t *next = j->next;
        struct conn *c = j->conn;
        j->done(j);                     /* frees j */
        if (c && after) after(c, user);
        reaped++;
        j = next;
    }
    return reaped;
}
