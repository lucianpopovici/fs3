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

#define CONN_RBUF_SZ          (16 * 1024)
#define CONN_WBUF_SZ          (16 * 1024)
#define CONN_MAX_HEADERS      64
#define CONN_HDR_SCRATCH_SZ   (16 * 1024)   /* URL + all header bytes combined */
#define CONN_REQ_SCRATCH_SZ   (4 * 1024)    /* per-request decoded path/query */

typedef enum {
    CST_READ_HEADERS,    /* feeding bytes to llhttp; headers not yet complete */
    CST_AUTH,            /* headers complete; auth check (Phase 0: no-op) */
    CST_READ_BODY,       /* body bytes streaming through on_body */
    CST_WRITE_RESPONSE,  /* writing response from wbuf */
    CST_CLOSING,
} conn_state_t;

typedef struct {
    s3_str_t k, v;
} conn_header_t;

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

    /* Reference to the global object store (lifetime == server). */
    struct s3_store   *store;

    /* Reference to the global SigV4 verifier (lifetime == server).
     * NULL means auth is disabled — every request is accepted. */
    struct sigv4_verifier *auth;

    /* Set to 1 in server config to require a valid signature. When
     * verifier is NULL, this is moot (no auth at all). When verifier
     * is set, auth_required=0 means "verify if Authorization is
     * present, else allow" — useful for compatibility transitions. */
    int                auth_required;

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
                    struct sigv4_verifier *auth, int auth_required);
void    conn_destroy(conn_t *c);

/* I/O readiness callbacks. Return 0 to keep alive, -1 to close. */
int     conn_on_readable(conn_t *c);
int     conn_on_writable(conn_t *c);

int     conn_wants_write(const conn_t *c);

#endif
