/* include/audit.h — append-only audit log and auth-failure throttling
 * (security review: critical-to-have features 1 and 2).
 *
 * Audit: one JSON line per request — time, client, identity, access key,
 * S3 action, path (query string dropped, so presigned signatures and
 * credentials never reach the log), status, bytes, duration — plus admin
 * API changes. Opened O_APPEND; SIGHUP reopens it for log rotation.
 *
 * Throttling: per client address (after --trusted-proxy resolution),
 * `limit` signature/auth failures within 60 s block that address for an
 * exponentially growing period (2 s .. 5 min) with 503 SlowDown. Loopback
 * peers are exempt unless a trusted proxy resolved a real client address
 * — behind the DSM proxy without --trusted-proxy every client looks like
 * 127.0.0.1, and throttling it would lock everyone out.
 */
#ifndef FS3_AUDIT_H
#define FS3_AUDIT_H

#include <stdint.h>
#include <time.h>

struct conn;

int  audit_open(const char *path);     /* 0 ok */
void audit_reopen(void);
void audit_close(void);
void audit_request(const struct conn *c, int status, uint64_t bytes_in,
                   uint64_t bytes_out, double dur_s);
void audit_event(const char *who, const char *what);

void throttle_set_limit(int failures_per_minute);   /* 0 = off */
int  throttle_blocked(const char *ip, time_t now);  /* 1 = refuse */
void throttle_fail(const char *ip, time_t now);
void throttle_ok(const char *ip);

#endif
