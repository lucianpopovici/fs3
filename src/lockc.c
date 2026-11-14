/* src/lockc.c — client for fs3-lockd (round 2, item 9). Blocking, one
 * short request per connection; the helper answers in microseconds. */
#include "lockc.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

int lockc_call(const char *sock, const char *req, char *reply, size_t cap) {
    if (cap) reply[0] = '\0';
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    struct timeval tv = { 3, 0 };
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    if (strlen(sock) >= sizeof(a.sun_path)) { close(s); return -1; }
    strcpy(a.sun_path, sock);
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) < 0) { close(s); return -1; }
    size_t n = strlen(req);
    if (write(s, req, n) != (ssize_t)n || write(s, "\n", 1) != 1) { close(s); return -1; }
    char buf[300];
    ssize_t got = 0;
    while (got < (ssize_t)sizeof(buf) - 1) {
        ssize_t r = read(s, buf + got, sizeof(buf) - 1 - (size_t)got);
        if (r <= 0) break;
        got += r;
        if (memchr(buf, '\n', (size_t)got)) break;
    }
    close(s);
    if (got <= 0) return -1;
    buf[got] = '\0';
    buf[strcspn(buf, "\r\n")] = '\0';
    if (cap) snprintf(reply, cap, "%s", buf);
    return strcmp(buf, "OK") == 0 ? 0 : 1;
}

static int call_fmt(const char *sock, const char *fmt, const char *path, uint64_t a, int b) {
    char req[4400], rep[300];
    snprintf(req, sizeof(req), fmt, path, (unsigned long long)a, b);
    return lockc_call(sock, req, rep, sizeof(rep));
}

int lockc_set(const char *sock, const char *path, uint64_t until_ms, int hold) {
    return call_fmt(sock, "SET %s %llu %d", path, until_ms, hold ? 1 : 0);
}
int lockc_hold_off(const char *sock, const char *path) {
    char req[4400], rep[300];
    snprintf(req, sizeof(req), "HOLD_OFF %s", path);
    return lockc_call(sock, req, rep, sizeof(rep));
}
int lockc_clear(const char *sock, const char *path) {
    char req[4400], rep[300];
    snprintf(req, sizeof(req), "CLEAR %s", path);
    return lockc_call(sock, req, rep, sizeof(rep));
}

int lockc_is_immutable(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    int fl = 0, r = ioctl(fd, FS_IOC_GETFLAGS, &fl) == 0 && (fl & FS_IMMUTABLE_FL);
    close(fd);
    return r;
}

int lockc_probe(const char *sock, const char *dir, char *why, size_t cap) {
    char p[4200];
    snprintf(p, sizeof(p), "%s/lockd-probe.XXXXXX", dir);
    int fd = mkstemp(p);
    if (fd < 0) { snprintf(why, cap, "cannot create a probe file in %s", dir); return -1; }
    close(fd);
    char rp[4200];
    if (!realpath(p, rp)) snprintf(rp, sizeof(rp), "%s", p);
    char rep[300];
    char req[4400];
    snprintf(req, sizeof(req), "SET %s 0 0", rp);
    int r = lockc_call(sock, req, rep, sizeof(rep));
    int ok = r == 0 && lockc_is_immutable(rp);
    if (!ok) snprintf(why, cap, "%s", r < 0 ? "fs3-lockd unreachable" : r > 0 ? rep
                      : "the filesystem refused FS_IMMUTABLE_FL");
    if (ok) {
        snprintf(req, sizeof(req), "CLEAR %s", rp);
        r = lockc_call(sock, req, rep, sizeof(rep));
        ok = r == 0 && !lockc_is_immutable(rp);
        if (!ok) snprintf(why, cap, "CLEAR failed: %s", r < 0 ? "unreachable" : rep);
    }
    if (unlink(rp) < 0 && ok) { snprintf(why, cap, "probe file stayed immutable"); ok = 0; }
    return ok ? 0 : -1;
}
