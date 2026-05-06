/* include/route.h — request dispatcher
 *
 * dispatch() inspects the parsed request on conn_t and either
 * builds an immediate response (for errors, HEAD, DELETE, list,
 * etc.) or sets up streaming state (for PUT/GET) so that subsequent
 * on_body / on_writable calls can complete the operation.
 *
 * Returns 0 to keep the connection going, -1 to drop it.
 */
#ifndef FS3_ROUTE_H
#define FS3_ROUTE_H

#include "conn.h"

/* Called from on_headers_complete once headers are parsed.
 * Decides what handler to use and may build the response immediately
 * (for HEAD/DELETE/etc.) or set up streaming state (for PUT). */
int route_dispatch_headers(conn_t *c);

/* Called from on_body to feed body bytes into a streaming PUT writer. */
int route_dispatch_body(conn_t *c, const char *data, size_t len);

/* Called from on_message_complete to finalize a streaming PUT and
 * build the response. For non-streaming requests this is where
 * we build the response. */
int route_dispatch_complete(conn_t *c);

/* Called from on_writable AFTER the response headers have been fully
 * written, to stream the GET body via sendfile.
 * Returns: 1 if more bytes remain (re-arm EPOLLOUT),
 *          0 if done streaming,
 *         -1 on error. */
int route_dispatch_send_body(conn_t *c);

/* Build an S3 error response for the current request (used by the auth
 * hook to short-circuit dispatch). Returns 0 on success, -1 on error. */
int route_build_error(conn_t *c, s3_err_t err);

#endif
