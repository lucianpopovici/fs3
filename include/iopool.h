/* include/iopool.h — worker threads for blocking store work
 *
 * The event loop is single-threaded; a request whose completion needs a
 * slow, blocking filesystem step (fsync, a multi-GB copy or MPU
 * concatenation) hands that step to this pool instead of running it on
 * the loop, so other connections keep being served meanwhile.
 *
 * A job has two halves:
 *   run()  — on a worker thread. Touches only the job's own fields
 *            (writers/readers it owns, copies of names). Never conn_t.
 *   done() — back on the loop thread, from iopool_reap(). Builds the
 *            response on job->conn, or, if the connection went away
 *            meanwhile (job->conn == NULL), just cleans up. Always
 *            frees the job.
 *
 * Workers signal completions through an eventfd (iopool_fd) that the
 * server registers with epoll.
 *
 * A NULL pool is valid everywhere: iopool_submit(NULL, j) runs run()
 * and done() inline, i.e. the old single-threaded behaviour.
 */
#ifndef FS3_IOPOOL_H
#define FS3_IOPOOL_H

struct conn;

typedef struct iojob iojob_t;
struct iojob {
    void         (*run)(iojob_t *j);
    void         (*done)(iojob_t *j);
    struct conn   *conn;     /* loop thread only; NULL once orphaned */
    iojob_t       *next;     /* pool-internal */
};

typedef struct iopool iopool_t;

/* n_threads >= 1. Returns NULL on failure. */
iopool_t *iopool_create(int n_threads);

/* Finish every queued and running job, run their done() callbacks, then
 * join the workers. Callers must orphan (job->conn = NULL) any job whose
 * conn they have already freed — conn_destroy does this. */
void      iopool_destroy(iopool_t *p);

/* Queue a job. With p == NULL, runs run() then done() before returning. */
void      iopool_submit(iopool_t *p, iojob_t *j);

/* eventfd that becomes readable when completed jobs are waiting. */
int       iopool_fd(const iopool_t *p);

/* Loop thread: run done() for every completed job. For each job whose
 * conn was still attached, after(conn, user) is called once done() has
 * returned (e.g. to re-arm epoll). Returns the number of jobs reaped. */
int       iopool_reap(iopool_t *p,
                      void (*after)(struct conn *c, void *user), void *user);

#endif
