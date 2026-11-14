/* include/admin.h — admin HTTP API (item 11)
 *
 * JSON endpoints under /v1 on the localhost admin listener
 * (--metrics-port) and, preferably, on a Unix domain socket
 * (--admin-socket, mode 0600, peer uid checked with SO_PEERCRED —
 * security review S10: every local user and container can reach
 * loopback).
 *
 *   GET    /v1/keys                      list access keys + users (never secrets)
 *   POST   /v1/keys        {"user":"u"}  create a key; secret returned once
 *   DELETE /v1/keys/<ak>                 delete a key (not the last one)
 *   GET    /v1/buckets                   buckets with owner + stats
 *   GET    /v1/buckets/<b>               details: stats, owner, grants, config
 *   PUT    /v1/buckets/<b>/owner {"owner":"u"}
 *   PUT    /v1/buckets/<b>/grants/<u> {"perms":"rw"}
 *   DELETE /v1/buckets/<b>/grants/<u>
 *
 * TCP requests need "Authorization: Bearer <token>" (--admin-token-file,
 * compared in constant time, failures back off exponentially), a
 * loopback Host header, and no Origin header (DNS rebinding / CSRF).
 * Unix-socket requests are authenticated by peer uid instead.
 *
 * Key changes rewrite the credentials file atomically and run the same
 * build-then-swap reload SIGHUP uses, so a new key works on the next
 * request and a deleted one is refused immediately.
 */
#ifndef FS3_ADMIN_H
#define FS3_ADMIN_H

#include <stddef.h>

struct s3_store;
struct scrub;
struct sigv4_verifier;

typedef struct {
    struct s3_store *store;
    const char      *token;        /* NULL = TCP /v1 disabled */
    const char      *cred_file;    /* NULL = key endpoints unavailable */
    int            (*reload)(void *user);   /* 0 = ok */
    void            *reload_user;
    struct scrub    *scrub;        /* POST/GET /v1/scrub (item 3) */
    const struct sigv4_verifier *auth;   /* live keys: last-used times (item 4) */
    int              key_max_age_days;   /* default expiry of new keys, 0 = none */
} admin_cfg_t;

typedef struct admin_ctx admin_ctx_t;

admin_ctx_t *admin_create(const admin_cfg_t *cfg);
void         admin_destroy(admin_ctx_t *a);

/* Handle one complete HTTP request (headers + body). via_uds: the peer
 * was authenticated by SO_PEERCRED. Returns a malloc'd HTTP response. */
char *admin_handle_v1(admin_ctx_t *a, const char *req, size_t n, int via_uds,
                      size_t *resp_n);

#endif
