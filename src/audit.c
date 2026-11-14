/* src/audit.c — audit log + auth-failure throttling. See include/audit.h. */

#include "audit.h"
#include "action.h"
#include "conn.h"
#include "json.h"
#include "log.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int   g_fd = -1;
static char *g_path;

int audit_open(const char *path) {
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    if (g_fd >= 0) close(g_fd);
    g_fd = fd;
    if (g_path != path) { free(g_path); g_path = strdup(path); }
    return 0;
}

void audit_reopen(void) {
    if (g_path && audit_open(g_path) < 0) LOG_W("audit log: cannot reopen %s", g_path);
}

void audit_close(void) {
    if (g_fd >= 0) close(g_fd);
    g_fd = -1;
    free(g_path);
    g_path = NULL;
}

static void emit(const char *line, size_t n) {
    if (g_fd >= 0) (void)!write(g_fd, line, n);     /* one write(): atomic append */
}

static void now_iso(char out[64]) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    snprintf(out, 64, "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ", tm.tm_year + 1900,
             tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
             ts.tv_nsec / 1000000);
}

void audit_request(const conn_t *c, int status, uint64_t bytes_in,
                   uint64_t bytes_out, double dur_s) {
    if (g_fd < 0) return;
    char line[3000], ts[64], path[1100], method[16];
    now_iso(ts);
    size_t pn = c->req.path.n < sizeof(path) - 1 ? c->req.path.n : sizeof(path) - 1;
    memcpy(path, c->req.path.p ? c->req.path.p : "", pn);
    path[pn] = '\0';
    size_t mn = c->req.method.n < sizeof(method) - 1 ? c->req.method.n : sizeof(method) - 1;
    memcpy(method, c->req.method.p ? c->req.method.p : "", mn);
    method[mn] = '\0';
    size_t o = 0;
    o += (size_t)snprintf(line, sizeof(line), "{\"ts\":\"%s\",\"client\":", ts);
    json_put_str(line, sizeof(line), &o, c->client_ip[0] ? c->client_ip : c->peer);
    o += (size_t)snprintf(line + o, sizeof(line) - o, ",\"user\":");
    json_put_str(line, sizeof(line), &o, c->id.user);
    o += (size_t)snprintf(line + o, sizeof(line) - o, ",\"access_key\":");
    json_put_str(line, sizeof(line), &o, c->id.access_key);
    o += (size_t)snprintf(line + o, sizeof(line) - o, ",\"method\":");
    json_put_str(line, sizeof(line), &o, method);
    o += (size_t)snprintf(line + o, sizeof(line) - o, ",\"action\":");
    json_put_str(line, sizeof(line), &o, action_name((s3_action_t)c->req.act));
    o += (size_t)snprintf(line + o, sizeof(line) - o, ",\"path\":");
    json_put_str(line, sizeof(line), &o, path);
    if (o + 200 < sizeof(line))
        o += (size_t)snprintf(line + o, sizeof(line) - o,
            ",\"status\":%d,\"bytes_in\":%llu,\"bytes_out\":%llu,\"ms\":%.1f,"
            "\"presigned\":%s,\"tls\":%s,\"web\":%s}\n",
            status, (unsigned long long)bytes_in, (unsigned long long)bytes_out,
            dur_s >= 0 ? dur_s * 1000 : -1.0, c->id.presigned ? "true" : "false",
            c->secure ? "true" : "false", c->is_web ? "true" : "false");
    emit(line, o);
}

void audit_event(const char *who, const char *what) {
    if (g_fd < 0) return;
    char line[1200], ts[64];
    now_iso(ts);
    size_t o = 0;
    o += (size_t)snprintf(line, sizeof(line), "{\"ts\":\"%s\",\"admin\":", ts);
    json_put_str(line, sizeof(line), &o, who);
    o += (size_t)snprintf(line + o, sizeof(line) - o, ",\"event\":");
    json_put_str(line, sizeof(line), &o, what);
    o += (size_t)snprintf(line + o, sizeof(line) - o, "}\n");
    emit(line, o);
}

/* ---- Throttling ------------------------------------------------------- */

#define SLOTS 1024
typedef struct { char ip[64]; int fails; time_t window; time_t blocked_until; int level; } slot_t;
static slot_t g_slots[SLOTS];
static int g_limit;

void throttle_set_limit(int n) { g_limit = n; }

static slot_t *slot_for(const char *ip, int create) {
    unsigned h = 2166136261u;
    for (const char *p = ip; *p; p++) h = (h ^ (unsigned char)*p) * 16777619u;
    slot_t *s = &g_slots[h % SLOTS];
    if (strcmp(s->ip, ip) == 0) return s;
    if (!create) return NULL;
    memset(s, 0, sizeof(*s));                    /* evict the colliding entry */
    snprintf(s->ip, sizeof(s->ip), "%s", ip);
    return s;
}

static int exempt(const char *ip) {
    return !ip || !*ip || !strcmp(ip, "127.0.0.1") || !strcmp(ip, "::1");
}

int throttle_blocked(const char *ip, time_t now) {
    if (!g_limit || exempt(ip)) return 0;
    slot_t *s = slot_for(ip, 0);
    return s && s->blocked_until > now;
}

void throttle_fail(const char *ip, time_t now) {
    if (!g_limit || exempt(ip)) return;
    slot_t *s = slot_for(ip, 1);
    if (now - s->window > 60) { s->window = now; s->fails = 0; }
    if (++s->fails >= g_limit) {
        if (s->level < 9) s->level++;
        long secs = 1L << s->level;
        if (secs > 300) secs = 300;
        s->blocked_until = now + secs;
        s->fails = 0;
        s->window = now;
        LOG_W("auth throttling: blocking %s for %ld s after repeated failures", ip, secs);
    }
}

void throttle_ok(const char *ip) {
    slot_t *s = ip ? slot_for(ip, 0) : NULL;
    if (s && s->blocked_until == 0) s->fails = 0;
}
