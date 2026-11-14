/* include/conn.h — per-connection state machine
 *
 * Each accepted TCP connection owns one conn_t. An llhttp parser drives
 * request parsing; bytes read into rbuf are fed to llhttp_execute()
 * which fires callbacks defined in conn.c.
 *
 * Body bytes arrive via on_body callbacks while llhttp is executing.
 * Header field/value/URL tokens may be delivered across multiple
 * callback invocations when reads land mid-token, so we accumulate
 * them in hdr_scratch and snapshot the spans on the corresponding
 * `_complete` callbacks.
 */
#ifndef FS3_CONN_H
#define FS3_CONN_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "llhttp.h"
#include "s3.h"
#include "sigv4.h"
#include "checksum.h"
#include "store.h"

#define CONN_RBUF_SZ          (16 * 1024)
#define CONN_WBUF_SZ          (16 * 1024)
#define CONN_MAX_HEADERS      64
#define CONN_HDR_SCRATCH_SZ   (16 * 1024)   /* URL + all header bytes combined */
#define CONN_REQ_SCRATCH_SZ   (4 * 1024)    /* per-request decoded path/query */
/* Max socket bytes one conn_on_readable() call may read before yielding
 * back to the event loop. Epoll is level-triggered, so leftover bytes
 * re-fire EPOLLIN on the next wait; the cap just stops one fast uploader
 * from starving every other connection. */
#define CONN_READ_BUDGET      (256 * 1024)
#define CONN_XHDR_SZ          2048          /* extra response headers */

typedef enum {
    CST_READ_HEADERS,    /* feeding bytes to llhttp; headers not yet complete */
    CST_AUTH,            /* headers complete; auth check (Phase 0: no-op) */
    CST_READ_BODY,       /* body bytes streaming through on_body */
    CST_WAIT_JOB,        /* request complete; blocking store work (commit,
                          * copy) is running on the iopool. No socket
                          * interest until the job's done() builds the
                          * response and moves us to CST_WRITE_RESPONSE. */
    CST_WRITE_RESPONSE,  /* writing response from wbuf */
    CST_CLOSING,
} conn_state_t;

typedef struct {
    s3_str_t k, v;
} conn_header_t;

/* One decoded query parameter. `has_eq` distinguishes "?acl" from
 * "?acl=". Both spans point into conn_t.qbuf. */
typedef struct {
    s3_str_t k, v;
    int      has_eq;
} conn_qparam_t;

#define CONN_MAX_QPARAMS      48
#define CONN_QBUF_SZ          (8 * 1024)

typedef struct {
    s3_str_t       method;        /* "GET", "PUT", "POST", "DELETE", "HEAD" — static literal */
    s3_str_t       target;        /* raw request-target, points into hdr_scratch */
    s3_str_t       path;          /* path component of target (no decode yet) */
    s3_str_t       query;         /* query component of target */

    conn_header_t  headers[CONN_MAX_HEADERS];
    size_t         n_headers;

    int            chunked;       /* derived from llhttp flags after headers */
    int            keep_alive;    /* derived from version + Connection hdr */
    uint64_t       content_length_hint; /* parser->content_length at headers_complete */

    uint64_t       body_consumed; /* bytes seen via on_body so far */

    /* Query string, split on '&' and percent-decoded once at
     * headers-complete (conn_parse_query). */
    conn_qparam_t  qp[CONN_MAX_QPARAMS];
    size_t         n_qp;
    int            act;           /* s3_action_t, set by the router */
} conn_req_t;

/* Header-accumulation state machine. Tracks whether the most recent
 * data callback fed bytes for the URL, a header field name, a header
 * value, or none of the above. */
typedef enum {
    HACC_NONE,
    HACC_URL,
    HACC_FIELD,
    HACC_VALUE,
} hacc_state_t;

typedef struct conn {
    int                fd;
    conn_state_t       state;
    int                eof_seen;
    /* Last conn_on_readable() stopped at CONN_READ_BUDGET with the socket
     * possibly still holding data: not drained, so not yet at EOF. */
    int                read_yielded;

    /* Reference to the global object store (lifetime == server). */
    struct s3_store   *store;

    /* Worker pool for blocking store work (lifetime == server). NULL runs
     * that work inline on the event loop. */
    struct iopool     *pool;
    /* The job this conn is waiting on (state CST_WAIT_JOB). conn_destroy
     * orphans it (job->conn = NULL) so it completes without us. */
    struct iojob      *job;

    /* Reference to the global SigV4 verifier (lifetime == server).
     * NULL means auth is disabled — every request is accepted. */
    struct sigv4_verifier *auth;

    /* Set to 1 in server config to require a valid signature. When
     * verifier is NULL, this is moot (no auth at all). When verifier
     * is set, auth_required=0 means "verify if Authorization is
     * present, else allow" — useful for compatibility transitions. */
    int                auth_required;

    /* Who signed the current request (set on successful SigV4 verify,
     * cleared per request). id.user[0] == '\0' means anonymous. Used by
     * route.c to enforce bucket ownership whenever `auth` is set. */
    sigv4_id_t         id;

    /* Request body ceiling (0 = unlimited). Checked against the declared
     * Content-Length at headers-complete and against the running byte
     * count as the body streams, so a client that lies about (or omits)
     * its length is still bounded. body_limit_hit latches the 413 so the
     * remaining body drains silently without rebuilding the response. */
    uint64_t           max_body_bytes;
    int                body_limit_hit;

    /* Last socket activity (seconds). Maintained by server.c; used by
     * its idle-connection sweep. */
    time_t             last_activity;

    /* Request accounting (NULL metrics = disabled). req_start_ns is
     * stamped when llhttp begins a message; bytes_out_body counts
     * sendfile'd GET body bytes (wbuf/ext_body are counted from their
     * lengths); metrics_flushed guards against double-recording when
     * the write path is re-entered. */
    struct fs3_metrics *metrics;
    uint64_t           req_start_ns;
    uint64_t           bytes_out_body;
    int                metrics_flushed;

    /* Read buffer: bytes are fed to llhttp via llhttp_execute() */
    char               rbuf[CONN_RBUF_SZ];
    size_t             rlen;

    /* Write buffer (response head, plus inline body for small responses) */
    char               wbuf[CONN_WBUF_SZ];
    size_t             wlen;
    size_t             wpos;

    /* Optional extended body buffer for responses that don't fit in wbuf
     * (e.g. ListBucketResult with many entries). When non-NULL, the
     * write path drains wbuf first, then ext_body[ext_body_pos..ext_body_len].
     * Owned by conn_t; freed on request_reset / conn_destroy. */
    char              *ext_body;
    size_t             ext_body_len;
    size_t             ext_body_pos;

    /* Optional REQUEST body buffer. Used by handlers that need to parse
     * the entire request body (e.g. CompleteMultipartUpload XML) rather
     * than streaming it to a writer. Set by handlers in
     * route_dispatch_headers; populated by route_dispatch_body across
     * chunks; consumed by route_dispatch_complete. Capped at
     * req_body_cap; bytes beyond that cause a 400. */
    char              *req_body_buf;
    size_t             req_body_len;
    size_t             req_body_cap;

    /* HTTP parser */
    llhttp_t           parser;
    llhttp_settings_t  settings;

    /* Header accumulation. Data callbacks may slice tokens; we append
     * received bytes into hdr_scratch and track current token span. */
    char               hdr_scratch[CONN_HDR_SCRATCH_SZ];
    size_t             hdr_used;
    hacc_state_t       hacc;
    size_t             cur_off;          /* start offset of token in scratch */
    size_t             cur_len;          /* token length so far */
    size_t             pending_field_off; /* finalized field awaiting its value */
    size_t             pending_field_len;

    /* Per-request state */
    conn_req_t         req;
    int                request_dispatched;  /* response has been built */

    /* Decoded query bytes (req.qp spans point here). */
    char               qbuf[CONN_QBUF_SZ];

    /* Per-request bump arena, used by route.c for decoded path/query
     * spans. Reset at the start of each request. */
    char               req_scratch[CONN_REQ_SCRATCH_SZ];
    size_t             req_scratch_used;

    /* Handler-owned state. At most one of these is set per request. */
    struct s3_writer  *put_writer;          /* in-flight streaming PUT */
    struct s3_reader  *get_reader;          /* GET body still to send via sendfile */
    int                get_head_only;       /* HEAD: don't stream body */

    /* Body-hash verification state. Set up at cb_on_headers_complete
     * after a successful SigV4 verify, when the client declared a real
     * SHA-256 (not UNSIGNED-PAYLOAD). The on_body callback feeds bytes
     * into body_hash_ctx; on_message_complete finalizes and compares
     * with body_hash_expected. body_hash_ctx is a malloc'd EVP_MD_CTX*
     * (typed as void* here so this header doesn't pull in OpenSSL). */
    void              *body_hash_ctx;       /* EVP_MD_CTX* — NULL if not verifying */
    char               body_hash_expected[64];  /* hex, no NUL */

    /* Streaming chunked SigV4 decoder. Set up at cb_on_headers_complete
     * when x-amz-content-sha256 = STREAMING-AWS4-HMAC-SHA256-PAYLOAD.
     * Mutually exclusive with body_hash_ctx. The on_body callback
     * routes bytes through it; the decoder calls route_dispatch_body
     * with verified data. */
    struct sigv4_chunk_decoder *chunk_decoder;

    /* Accepted on the website listener (item 6): anonymous GET/HEAD only,
     * Authorization ignored, bucket from Host. */
    int                is_web;
    const char        *web_root_domain;   /* server-lifetime string */
    /* --allow-public: website configs / public policies may be stored.
     * --allow-public-write: public policies may also grant writes. */
    int                allow_public;
    int                allow_public_write;
    /* Trust signals (items 7.6 / 9): client address and whether the
     * request arrived over TLS. Behind a proxy listed in
     * trusted_proxies, X-Forwarded-For / X-Forwarded-Proto are honoured;
     * from anyone else they are ignored. */
    const char        *trusted_proxies;   /* comma-separated IPs, server-lifetime */
    int                conn_tls;          /* this connection is TLS (native) */
    /* Native TLS state (FS3_TLS builds; unused otherwise). */
    void              *ssl;               /* SSL* */
    int                tls_handshaking;
    int                tls_want_write;    /* last TLS op needs EPOLLOUT */
    char              *tls_buf;           /* body bounce buffer (no kTLS) */
    size_t             tls_buf_len, tls_buf_pos;
    /* --require-tls: SigV4 on a plain listener only from loopback. */
    int                require_tls;
    /* --require-signed-payload (S2): refuse unsigned payloads unless the
     * request is over TLS / from a trusted proxy that says https. */
    int                require_signed_payload;
    char               client_ip[64];
    int                secure;

    /* The request's signature was verified (header or presigned). */
    int                sig_verified;

    /* Additional-checksum verification (item 1). cksum runs over the
     * decoded body bytes delivered to the router; the expected value
     * comes from an x-amz-checksum-<algo> header or, for aws-chunked
     * trailers, from the decoder at end of body. md5 does the same for
     * Content-MD5. Inactive when .algo == 0. */
    cksum_ctx_t        cksum;
    int                cksum_algo;
    int                cksum_from_trailer;
    uint8_t            cksum_expect[CKSUM_MAX_DIGEST];
    cksum_ctx_t        md5;
    uint8_t            md5_expect[16];

    /* Extra response headers ("Name: value\r\n"...), spliced into
     * whatever response head is built for this request when it starts
     * going out (conn_on_writable). Used for checksum echoes, CORS,
     * version ids, ... so the many head builders need no new params. */
    char               xhdr[CONN_XHDR_SZ];
    size_t             xhdr_len;
    int                xhdr_done;

    /* Multipart upload context.
     *  mpu_is_part_upload — when true, c->put_writer was created via
     *      store_mpu_part_begin and route_dispatch_complete should call
     *      store_mpu_part_commit instead of store_put_commit.
     *  mpu_complete_pending — when true, route_dispatch_complete should
     *      parse req_body_buf and call store_mpu_complete with bucket,
     *      key, and upload_id below.
     *  mpu_bucket / mpu_key — saved from headers-complete time so we
     *      have them available at message-complete. They live in
     *      req_scratch (same lifetime as the request).
     *  mpu_upload_id — 32 hex chars + NUL. */
    int                mpu_is_part_upload;
    int                mpu_complete_pending;
    s3_str_t           mpu_bucket;
    s3_str_t           mpu_key;
    char               mpu_upload_id[33];

    /* Server-side copy (PUT with x-amz-copy-source): destination, saved
     * at headers time and run at message-complete. Points into req_scratch. */
    int                copy_pending;
    s3_str_t           copy_bucket;
    s3_str_t           copy_key;

    /* Bucket config PUT (?cors, ?lifecycle, ?website, ?policy, ...):
     * body buffered into req_body_buf, handled at message-complete.
     * cfg_act is the s3_action_t (0 = none). */
    int                cfg_act;
    s3_str_t           cfg_bucket;      /* points into req_scratch */
    s3_str_t           cfg_key;         /* object subresources (?retention) */

    /* Object Lock (item 10): lock headers on a PUT, applied to the new
     * version when the commit finishes. */
    int                lock_pending;
    s3_lock_t          lock_new;
    uint64_t           max_retention_ms;   /* server-lifetime setting */

    /* Bulk-delete context (POST /<bucket>?delete) */
    int                delete_pending;
    s3_str_t           delete_bucket;   /* points into req_scratch */

    /* Server-side bookkeeping (server.c uses these; opaque to other code). */
    struct conn       *list_prev;
    struct conn       *list_next;

    char               peer[64];
} conn_t;

/* Lifecycle */
conn_t *conn_create(int fd, const char *peer, struct s3_store *store,
                    struct iopool *pool,
                    struct sigv4_verifier *auth, int auth_required,
                    uint64_t max_body_bytes, struct fs3_metrics *metrics);
void    conn_destroy(conn_t *c);

/* I/O readiness callbacks. Return 0 to keep alive, -1 to close. */
int     conn_on_readable(conn_t *c);
int     conn_on_writable(conn_t *c);

int     conn_wants_write(const conn_t *c);

/* Peer hung up (EPOLLRDHUP): is it safe to close now? False while there is
 * a response to send or still to be built (CST_WAIT_JOB), buffered request
 * bytes, or unread socket data left behind by a read that yielded at
 * CONN_READ_BUDGET. */
int     conn_hup_can_close(const conn_t *c);

/* Split and percent-decode c->req.query into c->req.qp. '+' stays '+'.
 * Returns 0, or -1 if the query has too many parameters or is too long. */
int     conn_parse_query(conn_t *c);
/* First parameter named `name` (exact, case-sensitive), or NULL. */
const conn_qparam_t *conn_query_get(const conn_t *c, const char *name);
/* Number of parameters named `name`. */
int     conn_query_count(const conn_t *c, const char *name);

/* Body bytes to the socket: sendfile, or the TLS path. */
struct s3_reader;
ssize_t conn_io_send_body(conn_t *c, struct s3_reader *r, size_t max);

/* Fill c->client_ip / c->secure from the peer and, for a trusted proxy,
 * X-Forwarded-For (rightmost entry) / X-Forwarded-Proto. */
void    conn_resolve_client(conn_t *c);

/* Queue an extra response header for the current request. Returns 0, or
 * -1 if the extra-header buffer is full (the header is dropped). */
int     conn_add_header(conn_t *c, const char *name, const char *value);
/* Drop queued extra headers (e.g. when a success response turns into an
 * error after they were added). */
void    conn_clear_headers(conn_t *c);

#endif
