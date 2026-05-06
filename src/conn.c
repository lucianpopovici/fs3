/* src/conn.c — per-connection state machine driven by llhttp
 *
 * Wire-up summary:
 *   read() → c->rbuf → llhttp_execute() → callbacks fire → state advances
 *
 * The callbacks accumulate the URL and header field/value bytes into
 * c->hdr_scratch (because llhttp may slice a single token across multiple
 * data callbacks when the kernel returns partial reads). Tokens are
 * finalized in the corresponding `_complete` callbacks, where we know the
 * full span.
 *
 * on_headers_complete dispatches to the router, which decides what
 * handler to use and may build a response immediately or set up a
 * streaming PUT. on_body feeds body bytes into the streaming PUT
 * writer (if one was created). on_message_complete finalises the PUT
 * (commit, build response) or, for non-streaming requests, is a no-op
 * since the response was already built at headers-complete time.
 *
 * After the response head is fully written, the writable callback may
 * still need to stream the GET body via sendfile. That's signalled by
 * c->get_reader being non-NULL.
 *
 * Phase 2 hook for SigV4: insert a verification step at the head of
 * cb_on_headers_complete, before route_dispatch_headers().
 */

#include "conn.h"
#include "log.h"
#include "route.h"
#include "sigv4.h"
#include "store.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ------------------------------------------------------------------------- */
/* Forward declarations of llhttp callbacks                                  */
/* ------------------------------------------------------------------------- */

static int cb_on_message_begin   (llhttp_t *p);
static int cb_on_url             (llhttp_t *p, const char *at, size_t len);
static int cb_on_url_complete    (llhttp_t *p);
static int cb_on_header_field    (llhttp_t *p, const char *at, size_t len);
static int cb_on_header_value    (llhttp_t *p, const char *at, size_t len);
static int cb_on_headers_complete(llhttp_t *p);
static int cb_on_body            (llhttp_t *p, const char *at, size_t len);
static int cb_on_message_complete(llhttp_t *p);

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                 */
/* ------------------------------------------------------------------------- */

static void parser_init(conn_t *c) {
    llhttp_settings_init(&c->settings);
    c->settings.on_message_begin    = cb_on_message_begin;
    c->settings.on_url              = cb_on_url;
    c->settings.on_url_complete     = cb_on_url_complete;
    c->settings.on_header_field     = cb_on_header_field;
    c->settings.on_header_value     = cb_on_header_value;
    c->settings.on_headers_complete = cb_on_headers_complete;
    c->settings.on_body             = cb_on_body;
    c->settings.on_message_complete = cb_on_message_complete;

    llhttp_init(&c->parser, HTTP_REQUEST, &c->settings);
    c->parser.data = c;
}

conn_t *conn_create(int fd, const char *peer, struct s3_store *store,
                    struct sigv4_verifier *auth, int auth_required) {
    conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = fd;
    c->state = CST_READ_HEADERS;
    c->store = store;
    c->auth = auth;
    c->auth_required = auth_required;
    snprintf(c->peer, sizeof(c->peer), "%s", peer ? peer : "?");
    parser_init(c);
    return c;
}

void conn_destroy(conn_t *c) {
    if (!c) return;
    /* Release any handler-owned state (request was abandoned mid-flight). */
    if (c->put_writer) store_put_abort(c->put_writer);
    if (c->get_reader) store_get_close(c->get_reader);
    if (c->body_hash_ctx) sigv4_body_hash_free(c->body_hash_ctx);
    if (c->chunk_decoder) sigv4_chunk_free(c->chunk_decoder);
    free(c->ext_body);
    free(c->req_body_buf);
    free(c);
}

int conn_wants_write(const conn_t *c) {
    if (c->state == CST_WRITE_RESPONSE && c->wpos < c->wlen) return 1;
    if (c->state == CST_WRITE_RESPONSE
        && c->ext_body && c->ext_body_pos < c->ext_body_len) return 1;
    if (c->state == CST_WRITE_RESPONSE && c->get_reader) return 1;
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------- */

static s3_str_t scratch_span(const conn_t *c, size_t off, size_t len) {
    return (s3_str_t){ c->hdr_scratch + off, len };
}

/* Append `len` bytes to hdr_scratch, advancing cur_len. Returns 0 ok, -1 oom. */
static int hdr_append(conn_t *c, const char *p, size_t len, int lowercase) {
    if (c->hdr_used + len > sizeof(c->hdr_scratch)) {
        LOG_W("hdr_scratch exhausted (used=%zu add=%zu)", c->hdr_used, len);
        return -1;
    }
    char *dst = c->hdr_scratch + c->hdr_used;
    if (lowercase) {
        for (size_t i = 0; i < len; i++) {
            char ch = p[i];
            dst[i] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
        }
    } else {
        memcpy(dst, p, len);
    }
    c->hdr_used += len;
    c->cur_len  += len;
    return 0;
}

/* Begin a new accumulation span starting at the next free byte of scratch. */
static void hdr_begin(conn_t *c, hacc_state_t kind) {
    c->cur_off = c->hdr_used;
    c->cur_len = 0;
    c->hacc    = kind;
}

/* Reset request-scoped state for the next request on a keep-alive conn. */
static void request_reset(conn_t *c) {
    memset(&c->req, 0, sizeof(c->req));
    c->hdr_used = 0;
    c->hacc     = HACC_NONE;
    c->cur_off  = 0;
    c->cur_len  = 0;
    c->pending_field_off = 0;
    c->pending_field_len = 0;
    c->request_dispatched = 0;
    c->state = CST_READ_HEADERS;
    c->wlen  = 0;
    c->wpos  = 0;
    c->req_scratch_used = 0;
    free(c->ext_body);
    c->ext_body = NULL;
    c->ext_body_len = 0;
    c->ext_body_pos = 0;
    c->req_scratch_used = 0;
    free(c->req_body_buf);
    c->req_body_buf = NULL;
    c->req_body_len = 0;
    c->req_body_cap = 0;
    c->mpu_is_part_upload = 0;
    c->mpu_complete_pending = 0;
    c->mpu_bucket = (s3_str_t){0};
    c->mpu_key = (s3_str_t){0};
    c->mpu_upload_id[0] = '\0';

    /* Belt-and-suspenders: by the time we reset, route_dispatch_complete
     * (PUT path) or route_dispatch_send_body (GET path) should have
     * cleared these. If anything slipped through, release it now. */
    if (c->put_writer) { store_put_abort(c->put_writer); c->put_writer = NULL; }
    if (c->get_reader) { store_get_close(c->get_reader); c->get_reader = NULL; }
    if (c->body_hash_ctx) {
        sigv4_body_hash_free(c->body_hash_ctx);
        c->body_hash_ctx = NULL;
    }
    if (c->chunk_decoder) {
        sigv4_chunk_free(c->chunk_decoder);
        c->chunk_decoder = NULL;
    }
    c->get_head_only = 0;
}

/* ------------------------------------------------------------------------- */
/* llhttp callbacks                                                          */
/* ------------------------------------------------------------------------- */

static int cb_on_message_begin(llhttp_t *p) {
    conn_t *c = p->data;
    /* On a keep-alive connection, on_message_begin fires for each new
     * request. We've already reset state when the previous response was
     * fully written, so this is a no-op in normal flow. */
    (void)c;
    return 0;
}

/* Callback for the chunk decoder: forwards verified chunk-data bytes
 * to the route layer (which streams them into the PUT writer). */
static int chunk_data_to_route(void *user, const char *data, size_t len) {
    conn_t *c = user;
    return route_dispatch_body(c, data, len);
}

static int cb_on_url(llhttp_t *p, const char *at, size_t len) {
    conn_t *c = p->data;
    if (c->hacc != HACC_URL) hdr_begin(c, HACC_URL);
    return hdr_append(c, at, len, 0);
}

static int cb_on_url_complete(llhttp_t *p) {
    conn_t *c = p->data;
    /* Snapshot URL span. The path/query split is delayed until
     * cb_on_headers_complete so we can do it once with all info. */
    c->req.target = scratch_span(c, c->cur_off, c->cur_len);
    c->hacc = HACC_NONE;
    return 0;
}

static int cb_on_header_field(llhttp_t *p, const char *at, size_t len) {
    conn_t *c = p->data;

    /* Transition VALUE → FIELD means the previous header is complete:
     * push (pending_field, current_value) into headers[]. */
    if (c->hacc == HACC_VALUE) {
        if (c->req.n_headers >= CONN_MAX_HEADERS) {
            LOG_W("too many headers");
            return -1;
        }
        s3_str_t k = scratch_span(c, c->pending_field_off, c->pending_field_len);
        s3_str_t v = scratch_span(c, c->cur_off, c->cur_len);
        c->req.headers[c->req.n_headers++] = (conn_header_t){ k, v };
        c->hacc = HACC_NONE;
    }

    if (c->hacc != HACC_FIELD) hdr_begin(c, HACC_FIELD);
    /* Lowercase field names as we go; saves work in handler lookups. */
    return hdr_append(c, at, len, 1);
}

static int cb_on_header_value(llhttp_t *p, const char *at, size_t len) {
    conn_t *c = p->data;

    /* Transition FIELD → VALUE: stash the field span so we can pair it
     * with the value when value-bytes are complete. */
    if (c->hacc == HACC_FIELD) {
        c->pending_field_off = c->cur_off;
        c->pending_field_len = c->cur_len;
        c->hacc = HACC_NONE;
    }

    if (c->hacc != HACC_VALUE) hdr_begin(c, HACC_VALUE);
    return hdr_append(c, at, len, 0);
}

static const char *method_name_static(uint8_t m) {
    /* llhttp_method_name returns a pointer into a static table. */
    return llhttp_method_name((llhttp_method_t)m);
}

static int cb_on_headers_complete(llhttp_t *p) {
    conn_t *c = p->data;

    /* Flush the trailing header (last field+value pair). */
    if (c->hacc == HACC_VALUE) {
        if (c->req.n_headers >= CONN_MAX_HEADERS) return -1;
        s3_str_t k = scratch_span(c, c->pending_field_off, c->pending_field_len);
        s3_str_t v = scratch_span(c, c->cur_off, c->cur_len);
        c->req.headers[c->req.n_headers++] = (conn_header_t){ k, v };
    }
    c->hacc = HACC_NONE;

    /* Method name from llhttp's static table. */
    const char *m = method_name_static(p->method);
    c->req.method = (s3_str_t){ m, strlen(m) };

    /* Path / query split (no percent-decoding here; handlers do it). */
    s3_str_t t = c->req.target;
    const char *q = memchr(t.p, '?', t.n);
    if (q) {
        c->req.path  = (s3_str_t){ t.p, (size_t)(q - t.p) };
        c->req.query = (s3_str_t){ q + 1, t.n - (size_t)(q - t.p) - 1 };
    } else {
        c->req.path  = t;
        c->req.query = S3_STR_NULL;
    }

    /* llhttp tracks Content-Length and chunked flag for us. */
    c->req.content_length_hint = p->content_length;
    c->req.chunked = (p->flags & 0x08) ? 1 : 0;  /* F_CHUNKED = 0x08 */

    /* Keep-alive: llhttp's flag F_CONNECTION_CLOSE = 0x04 */
    int conn_close = (p->flags & 0x04) ? 1 : 0;
    int http11 = (p->http_major == 1 && p->http_minor == 1);
    c->req.keep_alive = http11 && !conn_close;

    /* Phase 2 hook: SigV4 verification.
     *
     * If a verifier is configured, check the signature now. On failure,
     * build the appropriate S3 error response and skip the route
     * dispatch — but return 0 (not -1) so llhttp continues to
     * on_body/on_message_complete, which lets us write the response
     * cleanly and either keep the connection alive or close it. */
    if (c->auth) {
        /* Look up authorization header. If missing and auth not strictly
         * required, fall through. */
        const s3_str_t *auth_h = NULL;
        for (size_t i = 0; i < c->req.n_headers; i++) {
            if (s3_str_eq_lit(c->req.headers[i].k, "authorization")) {
                auth_h = &c->req.headers[i].v;
                break;
            }
        }
        if (auth_h || c->auth_required) {
            s3_err_t e = sigv4_verify(c->auth, c);
            if (e != S3_OK) {
                LOG_D("sigv4 verify failed (err=%d) on %s",
                      (int)e, c->peer);
                if (route_build_error(c, e) < 0) return -1;
                return 0;
            }
            /* Verified. If the client declared a real body hash (not
             * UNSIGNED-PAYLOAD and not the streaming literal), set up
             * streaming verification so we catch the case where the
             * client lied about its body. */
            const s3_str_t *bh = NULL;
            for (size_t i = 0; i < c->req.n_headers; i++) {
                if (s3_str_eq_lit(c->req.headers[i].k, "x-amz-content-sha256")) {
                    bh = &c->req.headers[i].v;
                    break;
                }
            }
            if (bh && bh->n == 64
                && !s3_str_eq_lit(*bh, "UNSIGNED-PAYLOAD")) {
                c->body_hash_ctx = sigv4_body_hash_begin();
                if (c->body_hash_ctx) {
                    memcpy(c->body_hash_expected, bh->p, 64);
                }
                /* If begin failed (OOM), we'd silently skip body
                 * verification rather than fail the request. The
                 * signature itself is still verified. */
            }
        }
    }

    c->state = CST_READ_BODY;

    /* Dispatch to the router. For PUT this opens a writer (so on_body
     * can stream into it); for GET/HEAD/DELETE/list, this builds the
     * full response now and transitions to CST_WRITE_RESPONSE. */
    if (route_dispatch_headers(c) < 0) {
        return -1;
    }

    /* If this is a chunked-SigV4 request, set up the chunk decoder
     * AFTER route_dispatch_headers has set up a writer (if any).
     * The decoder's on_data callback forwards verified data bytes to
     * route_dispatch_body, which requires the writer to exist. */
    if (c->auth && sigv4_is_chunked(c)) {
        /* Find x-amz-decoded-content-length for end-of-stream check. */
        uint64_t expected = 0;
        for (size_t i = 0; i < c->req.n_headers; i++) {
            if (s3_str_eq_lit(c->req.headers[i].k, "x-amz-decoded-content-length")) {
                const s3_str_t *v = &c->req.headers[i].v;
                /* Bounded parse — value should be plain decimal. */
                for (size_t j = 0; j < v->n; j++) {
                    if (v->p[j] < '0' || v->p[j] > '9') { expected = 0; break; }
                    expected = expected * 10 + (uint64_t)(v->p[j] - '0');
                }
                break;
            }
        }
        c->chunk_decoder = sigv4_chunk_begin(c->auth, c, expected,
                                             chunk_data_to_route, c);
        if (!c->chunk_decoder) {
            /* OOM or some other failure setting up the decoder. */
            if (route_build_error(c, S3_ERR_INTERNAL) < 0) return -1;
            return 0;
        }
    }
    return 0;
}

static int cb_on_body(llhttp_t *p, const char *at, size_t len) {
    conn_t *c = p->data;
    c->req.body_consumed += len;

    /* Chunked SigV4: feed bytes to the decoder, which calls back via
     * chunk_data_to_route for each verified data segment. The decoder
     * also handles the framing and per-chunk signature verification. */
    if (c->chunk_decoder) {
        if (sigv4_chunk_feed(c->chunk_decoder, at, len) < 0) {
            LOG_D("chunk feed failed on %s", c->peer);
            /* Abort any in-flight PUT so nothing reaches the store. */
            if (c->put_writer) {
                store_put_abort(c->put_writer);
                c->put_writer = NULL;
            }
            sigv4_chunk_free(c->chunk_decoder);
            c->chunk_decoder = NULL;
            if (route_build_error(c, S3_ERR_SIGNATURE_DOES_NOT_MATCH) < 0) {
                return -1;
            }
            /* Drain remaining body bytes silently — but llhttp will keep
             * delivering them via on_body. We've already built the
             * response. Returning 0 keeps the parser running so we
             * still hit on_message_complete and can flush the response. */
            return 0;
        }
        return 0;
    }

    /* If body-hash verification is active, feed the bytes through. */
    if (c->body_hash_ctx) {
        sigv4_body_hash_update(c->body_hash_ctx, at, len);
    }
    /* Stream body bytes into a writer if route established one for PUT. */
    if (route_dispatch_body(c, at, len) < 0) return -1;
    return 0;
}

static int cb_on_message_complete(llhttp_t *p) {
    conn_t *c = p->data;

    /* If a chunk decoder was active and is still alive (no mid-stream
     * failure already produced a response), verify the terminator
     * chunk arrived and the total decoded length matched. */
    if (c->chunk_decoder) {
        int ok = (sigv4_chunk_finish(c->chunk_decoder) == 0);
        sigv4_chunk_free(c->chunk_decoder);
        c->chunk_decoder = NULL;
        if (!ok) {
            LOG_D("chunk finish failed on %s", c->peer);
            if (c->put_writer) {
                store_put_abort(c->put_writer);
                c->put_writer = NULL;
            }
            if (route_build_error(c, S3_ERR_SIGNATURE_DOES_NOT_MATCH) < 0) {
                return -1;
            }
            c->request_dispatched = 1;
            return HPE_PAUSED;
        }
    }

    /* If body-hash verification is active, finalize and compare BEFORE
     * the route layer commits. A mismatch means the client lied about
     * its body — we abort the PUT writer (no object on disk) and
     * return XAmzContentSHA256Mismatch. */
    if (c->body_hash_ctx) {
        int matched = sigv4_body_hash_verify(c->body_hash_ctx,
                                             c->body_hash_expected);
        sigv4_body_hash_free(c->body_hash_ctx);
        c->body_hash_ctx = NULL;
        if (!matched) {
            LOG_D("body sha256 mismatch on %s", c->peer);
            /* Abort any in-flight PUT so nothing reaches the store. */
            if (c->put_writer) {
                store_put_abort(c->put_writer);
                c->put_writer = NULL;
            }
            if (route_build_error(c, S3_ERR_BAD_DIGEST) < 0) return -1;
            c->request_dispatched = 1;
            return HPE_PAUSED;
        }
    }

    /* For streaming PUT, finalize: store_put_commit + build response.
     * For non-streaming requests the response was already built at
     * headers-complete time, and route_dispatch_complete is a no-op. */
    if (route_dispatch_complete(c) < 0) return -1;
    c->request_dispatched = 1;

    /* Pause so llhttp returns HPE_PAUSED to conn_on_readable, which can
     * then transition to writing the response without consuming any
     * pipelined bytes that may follow in rbuf — those wait until
     * llhttp_resume() after this response is fully written. */
    return HPE_PAUSED;
}

/* ------------------------------------------------------------------------- */
/* Read path                                                                 */
/* ------------------------------------------------------------------------- */

/* Build a 4xx/5xx error response into wbuf and force connection close. */
static void build_simple_error(conn_t *c, int status, const char *reason) {
    int blen = (int)strlen(reason);
    c->wlen = (size_t)snprintf(c->wbuf, CONN_WBUF_SZ,
        "HTTP/1.1 %d %s\r\n"
        "Server: fs3/0.1\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status, reason, blen, reason);
    c->wpos = 0;
    c->req.keep_alive = 0;
    c->state = CST_WRITE_RESPONSE;
    c->request_dispatched = 1;
}

/* Feed up to `n` bytes from rbuf to llhttp, starting at rbuf+0.
 * Returns the number of bytes consumed (always 0..n), or -1 on fatal error
 * (with response already built into wbuf). */
static ssize_t feed_parser(conn_t *c, size_t n) {
    llhttp_errno_t e = llhttp_execute(&c->parser, c->rbuf, n);

    if (e == HPE_OK) return (ssize_t)n;

    if (e == HPE_PAUSED) {
        /* We paused either at headers_complete (for auth) or
         * at message_complete (to suspend pipelining until response sent).
         * llhttp_get_error_pos() points to the byte AFTER the pause. */
        const char *stop = llhttp_get_error_pos(&c->parser);
        if (!stop || stop < c->rbuf || stop > c->rbuf + n) {
            LOG_E("invalid pause position");
            build_simple_error(c, 500, "Internal Server Error");
            return -1;
        }
        return stop - c->rbuf;
    }

    /* Any other error code is a parse failure → 400 (or 501 for some). */
    LOG_W("llhttp error %s: %s", llhttp_errno_name(e),
          llhttp_get_error_reason(&c->parser));
    if (e == HPE_INVALID_METHOD || e == HPE_INVALID_VERSION) {
        build_simple_error(c, 400, "Bad Request");
    } else if (e == HPE_INVALID_TRANSFER_ENCODING) {
        build_simple_error(c, 501, "Not Implemented");
    } else {
        build_simple_error(c, 400, "Bad Request");
    }
    return -1;
}

/* Compact rbuf by removing the first `n` bytes. */
static void rbuf_consume(conn_t *c, size_t n) {
    if (n == 0) return;
    if (n >= c->rlen) { c->rlen = 0; return; }
    memmove(c->rbuf, c->rbuf + n, c->rlen - n);
    c->rlen -= n;
}

int conn_on_readable(conn_t *c) {
    for (;;) {
        if (c->rlen >= sizeof(c->rbuf)) {
            /* Buffer full. If we're still parsing headers it means the
             * URL+headers are too large to fit. Otherwise body is being
             * delivered faster than we can drain — feed it now. */
            if (c->state == CST_READ_HEADERS) {
                build_simple_error(c, 431, "Request Header Fields Too Large");
                return 0;
            }
            ssize_t consumed = feed_parser(c, c->rlen);
            if (consumed < 0) return 0;       /* response built */
            rbuf_consume(c, (size_t)consumed);
            if (consumed == 0) return -1;     /* parser stuck; defensive */
            if (c->state == CST_WRITE_RESPONSE) return 0;
            continue;
        }

        ssize_t n = read(c->fd, c->rbuf + c->rlen, sizeof(c->rbuf) - c->rlen);
        if (n > 0) {
            c->rlen += (size_t)n;
            ssize_t consumed = feed_parser(c, c->rlen);
            if (consumed < 0) return 0;       /* response built */
            rbuf_consume(c, (size_t)consumed);
            if (c->state == CST_WRITE_RESPONSE) return 0;
            continue;
        }
        if (n == 0) {
            /* Peer closed write side. If we're mid-message, tell llhttp
             * so it can finalize using connection-close framing. If we're
             * idle between requests, calling llhttp_finish would just
             * yield a benign HPE_INVALID_EOF_STATE — skip it. */
            c->eof_seen = 1;
            if (c->state == CST_READ_HEADERS || c->state == CST_READ_BODY) {
                llhttp_errno_t e = llhttp_finish(&c->parser);
                if (e != HPE_OK && e != HPE_PAUSED) {
                    LOG_D("llhttp_finish: %s",
                          llhttp_get_error_reason(&c->parser));
                }
            }
            if (c->state == CST_WRITE_RESPONSE) return 0;
            /* Truncated mid-request → drop. */
            if (c->state == CST_READ_HEADERS || c->state == CST_READ_BODY) {
                return -1;
            }
            return 0;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        if (errno == EINTR) continue;
        LOG_W("read fd=%d: %s", c->fd, strerror(errno));
        return -1;
    }
}

/* ------------------------------------------------------------------------- */
/* Write path                                                                */
/* ------------------------------------------------------------------------- */

int conn_on_writable(conn_t *c) {
    /* Drain wbuf (the response head, plus inline body for small responses). */
    while (c->state == CST_WRITE_RESPONSE && c->wpos < c->wlen) {
        ssize_t n = write(c->fd, c->wbuf + c->wpos, c->wlen - c->wpos);
        if (n > 0) {
            c->wpos += (size_t)n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (n < 0 && errno == EINTR) continue;
        LOG_W("write fd=%d: %s", c->fd, strerror(errno));
        return -1;
    }

    /* Drain extended body buffer (for responses larger than wbuf, e.g.
     * a ListBucketResult with many entries). */
    while (c->state == CST_WRITE_RESPONSE
           && c->ext_body && c->ext_body_pos < c->ext_body_len) {
        ssize_t n = write(c->fd,
                          c->ext_body + c->ext_body_pos,
                          c->ext_body_len - c->ext_body_pos);
        if (n > 0) { c->ext_body_pos += (size_t)n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (n < 0 && errno == EINTR) continue;
        LOG_W("write ext_body fd=%d: %s", c->fd, strerror(errno));
        return -1;
    }

    /* If a GET set up a streaming reader, send body bytes via sendfile.
     * route_dispatch_send_body returns:
     *   1 = more bytes to send (would block / partial), keep wanting EPOLLOUT
     *   0 = done streaming, transition to keep-alive / close
     *  -1 = error, drop connection
     */
    if (c->state == CST_WRITE_RESPONSE && c->get_reader) {
        for (;;) {
            int r = route_dispatch_send_body(c);
            if (r < 0) return -1;
            if (r == 1) return 0;        /* more remaining; re-arm EPOLLOUT */
            if (r == 0) break;           /* done */
        }
    }

    if (!c->req.keep_alive) {
        c->state = CST_CLOSING;
        return 0;
    }

    /* Reset for next request. Preserve any pipelined bytes in rbuf
     * (request_reset does NOT touch rbuf). Then resume llhttp so it
     * begins parsing the next message, and drive the parser against
     * whatever is already buffered. */
    int had_pipelined = (c->rlen > 0);
    request_reset(c);
    llhttp_resume(&c->parser);

    if (had_pipelined) {
        ssize_t consumed = feed_parser(c, c->rlen);
        if (consumed < 0) return 0;
        rbuf_consume(c, (size_t)consumed);
    }

    /* If peer already closed write-side and there's nothing buffered
     * and no new request started, we're done. */
    if (c->eof_seen && c->state == CST_READ_HEADERS && c->rlen == 0) {
        c->state = CST_CLOSING;
    }
    return 0;
}
