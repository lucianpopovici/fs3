/* src/lockd.c — fs3-lockd: the only holder of CAP_LINUX_IMMUTABLE
 * (round 2, item 9). A small root-run helper, no network, one Unix
 * socket (0600, owned by the fs3 service user, peer checked with
 * SO_PEERCRED). fs3 asks it to make COMPLIANCE / legal-hold versions
 * immutable and to clear the flag later; the helper keeps its own
 * root-only, append-only journal of (inode → retain-until, legal hold)
 * and refuses to clear early, whatever fs3 says. A compromised fs3 can
 * neither unlink an immutable version nor talk the helper out of it.
 *
 *   fs3-lockd --root <store root> --socket <path> --journal <path> [--peer-uid N]
 *
 * Requests (one per connection, one line): "PING", "SET <path> <until_ms>
 * <hold 0|1>", "HOLD_OFF <path>", "CLEAR <path>". Replies "OK" or
 * "ERR <reason>". Retention can only be extended; a legal hold is only
 * released by an explicit, journaled HOLD_OFF.
 */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

typedef struct { uint64_t dev, ino, until_ms; int hold; } rec_t;
static rec_t *g_recs;
static size_t g_n, g_cap;
static int g_journal = -1;
static int g_root = -1;
static char g_root_path[4096];

static rec_t *rec_find(uint64_t dev, uint64_t ino, int create) {
    for (size_t i = 0; i < g_n; i++)
        if (g_recs[i].dev == dev && g_recs[i].ino == ino) return &g_recs[i];
    if (!create) return NULL;
    if (g_n == g_cap) {
        size_t nc = g_cap ? g_cap * 2 : 64;
        rec_t *n = realloc(g_recs, nc * sizeof(*n));
        if (!n) return NULL;
        g_recs = n; g_cap = nc;
    }
    g_recs[g_n] = (rec_t){ dev, ino, 0, 0 };
    return &g_recs[g_n++];
}

static void rec_drop(rec_t *r) { *r = g_recs[--g_n]; }

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void apply(const char *op, uint64_t dev, uint64_t ino, uint64_t until, int hold) {
    rec_t *r = rec_find(dev, ino, !strcmp(op, "SET"));
    if (!r) return;
    if (!strcmp(op, "SET")) {
        if (until > r->until_ms) r->until_ms = until;       /* only ever extended */
        if (hold) r->hold = 1;
    } else if (!strcmp(op, "HOLD_OFF")) {
        r->hold = 0;
    } else if (!strcmp(op, "CLEAR")) {
        rec_drop(r);
    }
}

static int journal(const char *op, uint64_t dev, uint64_t ino, uint64_t until, int hold) {
    char line[160];
    int n = snprintf(line, sizeof(line), "%s %" PRIu64 " %" PRIu64 " %" PRIu64 " %d %" PRIu64 "\n",
                     op, dev, ino, until, hold, now_ms());
    if (write(g_journal, line, (size_t)n) != n || fsync(g_journal) < 0) return -1;
    apply(op, dev, ino, until, hold);
    return 0;
}

static void replay(const char *path) {
    FILE *f = fopen(path, "re");
    if (!f) return;
    char op[16];
    uint64_t dev, ino, until, ts;
    int hold;
    while (fscanf(f, "%15s %" SCNu64 " %" SCNu64 " %" SCNu64 " %d %" SCNu64, op, &dev, &ino, &until,
                  &hold, &ts) == 6)
        apply(op, dev, ino, until, hold);
    fclose(f);
}

/* Open a regular file strictly inside the store root: every component
 * by openat with O_NOFOLLOW, no "." / ".." / empty components. */
static int open_in_root(const char *path) {
    size_t rl = strlen(g_root_path);
    if (strncmp(path, g_root_path, rl) || path[rl] != '/') return -1;
    char buf[4096];
    if (snprintf(buf, sizeof(buf), "%s", path + rl + 1) >= (int)sizeof(buf)) return -1;
    int dir = dup(g_root);
    char *save = NULL, *comp = strtok_r(buf, "/", &save);
    while (comp) {
        char *next = strtok_r(NULL, "/", &save);
        if (!strcmp(comp, ".") || !strcmp(comp, "..")) { close(dir); return -1; }
        int fd = openat(dir, comp, (next ? O_DIRECTORY : 0) | O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        close(dir);
        if (fd < 0) return -1;
        dir = fd;
        comp = next;
    }
    struct stat st;
    if (fstat(dir, &st) < 0 || !S_ISREG(st.st_mode)) { close(dir); return -1; }
    return dir;
}

static int set_immutable(int fd, int on) {
    int fl = 0;
    if (ioctl(fd, FS_IOC_GETFLAGS, &fl) < 0) return -1;
    fl = on ? (fl | FS_IMMUTABLE_FL) : (fl & ~FS_IMMUTABLE_FL);
    return ioctl(fd, FS_IOC_SETFLAGS, &fl);
}

static int is_immutable(int fd) {
    int fl = 0;
    return ioctl(fd, FS_IOC_GETFLAGS, &fl) == 0 && (fl & FS_IMMUTABLE_FL);
}

static void handle(int c) {
    char req[4400];
    ssize_t n = 0;
    while (n < (ssize_t)sizeof(req) - 1) {
        ssize_t r = read(c, req + n, sizeof(req) - 1 - (size_t)n);
        if (r <= 0) break;
        n += r;
        if (memchr(req, '\n', (size_t)n)) break;
    }
    if (n <= 0) return;
    req[n] = '\0';
    req[strcspn(req, "\r\n")] = '\0';
    char op[16] = "", path[4200] = "";
    unsigned long long until = 0;
    int hold = 0;
    const char *reply = "ERR bad request";
    char rb[256];
    int k = sscanf(req, "%15s %4199s %llu %d", op, path, &until, &hold);
    if (k >= 1 && !strcmp(op, "PING")) {
        reply = "OK";
    } else if (k >= 2) {
        int fd = open_in_root(path);
        struct stat st;
        if (fd < 0 || fstat(fd, &st) < 0) {
            reply = "ERR not a regular file inside the store root";
        } else if (!strcmp(op, "SET") && k == 4 && (hold == 0 || hold == 1)) {
            if (journal("SET", (uint64_t)st.st_dev, (uint64_t)st.st_ino, until, hold) < 0)
                reply = "ERR journal";
            else if (set_immutable(fd, 1) < 0)
                reply = "ERR cannot set FS_IMMUTABLE_FL";
            else reply = "OK";
        } else if (!strcmp(op, "HOLD_OFF") && k == 2) {
            reply = journal("HOLD_OFF", (uint64_t)st.st_dev, (uint64_t)st.st_ino, 0, 0) < 0
                    ? "ERR journal" : "OK";
        } else if (!strcmp(op, "CLEAR") && k == 2) {
            rec_t *r = rec_find((uint64_t)st.st_dev, (uint64_t)st.st_ino, 0);
            if (!r) {
                reply = is_immutable(fd) ? "ERR no record for this immutable file" : "OK";
            } else if (r->hold) {
                reply = "ERR legal hold";
            } else if (r->until_ms > now_ms()) {
                snprintf(rb, sizeof(rb), "ERR retained until %" PRIu64, r->until_ms);
                reply = rb;
            } else if (set_immutable(fd, 0) < 0) {
                reply = "ERR cannot clear FS_IMMUTABLE_FL";
            } else {
                reply = journal("CLEAR", (uint64_t)st.st_dev, (uint64_t)st.st_ino, 0, 0) < 0
                        ? "ERR journal" : "OK";
            }
        }
        if (fd >= 0) close(fd);
        fprintf(stderr, "fs3-lockd: %s %s -> %s\n", op, path, reply);
    }
    char out[300];
    int on = snprintf(out, sizeof(out), "%s\n", reply);
    (void)!write(c, out, (size_t)on);
}

int main(int argc, char **argv) {
    const char *root = NULL, *sock = NULL, *jpath = NULL;
    long peer = -1;
    static struct option opts[] = {
        { "root", required_argument, NULL, 'r' }, { "socket", required_argument, NULL, 's' },
        { "journal", required_argument, NULL, 'j' }, { "peer-uid", required_argument, NULL, 'u' },
        { NULL, 0, NULL, 0 } };
    int ch;
    while ((ch = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        if (ch == 'r') root = optarg;
        else if (ch == 's') sock = optarg;
        else if (ch == 'j') jpath = optarg;
        else if (ch == 'u') peer = strtol(optarg, NULL, 10);
        else { fprintf(stderr, "usage: fs3-lockd --root DIR --socket PATH --journal FILE [--peer-uid N]\n"); return 2; }
    }
    if (!root || !sock || !jpath) {
        fprintf(stderr, "usage: fs3-lockd --root DIR --socket PATH --journal FILE [--peer-uid N]\n");
        return 2;
    }
    if (!realpath(root, g_root_path) || (g_root = open(g_root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) {
        perror("fs3-lockd: --root");
        return 1;
    }
    struct stat rst;
    fstat(g_root, &rst);
    if (peer < 0) peer = (long)rst.st_uid;            /* the store's owner = the fs3 user */
    replay(jpath);
    g_journal = open(jpath, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (g_journal < 0) { perror("fs3-lockd: --journal"); return 1; }
    signal(SIGPIPE, SIG_IGN);
    int l = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un a = { .sun_family = AF_UNIX };
    if (strlen(sock) >= sizeof(a.sun_path)) { fprintf(stderr, "fs3-lockd: socket path too long\n"); return 1; }
    strcpy(a.sun_path, sock);
    unlink(sock);
    mode_t old = umask(0177);
    if (bind(l, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(l, 16) < 0) {
        perror("fs3-lockd: bind"); return 1;
    }
    umask(old);
    if (chown(sock, (uid_t)peer, (gid_t)-1) < 0) perror("fs3-lockd: chown socket");
    fprintf(stderr, "fs3-lockd: serving %s for uid %ld on %s (%zu record(s))\n", g_root_path, peer, sock, g_n);
    for (;;) {
        int c = accept4(l, NULL, NULL, SOCK_CLOEXEC);
        if (c < 0) { if (errno == EINTR) continue; break; }
        struct ucred cr;
        socklen_t cl = sizeof(cr);
        struct timeval tv = { 2, 0 };
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cr, &cl) < 0
            || (cr.uid != (uid_t)peer && cr.uid != 0)) {
            (void)!write(c, "ERR peer not allowed\n", 21);
        } else {
            handle(c);
        }
        close(c);
    }
    return 0;
}
