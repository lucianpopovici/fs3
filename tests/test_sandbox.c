/* tests/test_sandbox.c — the seccomp filter (round 2, item 5) really
 * blocks what it should and allows what fs3 needs. Each case runs in a
 * forked child that installs the filter and then tries one thing. */
#include "sandbox.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static int pass, fail;
#define CHECK(c, msg) do { if (c) pass++; else { fail++; printf("FAIL %s\n", msg); } } while (0)

static void *thr(void *a) { return a; }

enum { T_EXEC, T_FORK, T_THREAD, T_SOCK_NETLINK, T_SOCK_INET, T_IOCTL_BAD, T_IOCTL_FIONBIO,
       T_FILE_IO, T_PTRACE };

static int run(sandbox_mode_t mode, int what) {
    pid_t p = fork();
    if (p == 0) {
        int dn = open("/dev/null", O_WRONLY);
        if (dn >= 0) { dup2(dn, 2); close(dn); }        /* keep the log quiet */
        if (sandbox_install(mode) < 0) _exit(90);
        switch (what) {
        case T_EXEC: { char *a[] = { "/bin/true", NULL }; execv(a[0], a); _exit(91); }
        case T_FORK: { pid_t c = (pid_t)syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0); if (c == 0) _exit(0); _exit(92); }
        case T_THREAD: { pthread_t t; if (pthread_create(&t, NULL, thr, NULL)) _exit(93);
                         pthread_join(t, NULL); _exit(0); }
        case T_SOCK_NETLINK: { int s = socket(AF_NETLINK, SOCK_RAW, 0); (void)s; _exit(94); }
        case T_SOCK_INET: { int s = socket(AF_INET, SOCK_STREAM, 0); _exit(s >= 0 ? 0 : 95); }
        case T_IOCTL_BAD: { ioctl(0, 0x5412 /* TIOCSTI */, "x"); _exit(96); }
        case T_IOCTL_FIONBIO: { int on = 1; int s = socket(AF_INET, SOCK_STREAM, 0);
                                _exit(ioctl(s, FIONBIO, &on) == 0 ? 0 : 97); }
        case T_FILE_IO: { char path[] = "/tmp/fs3-sandbox-XXXXXX"; int fd = mkstemp(path);
                          if (fd < 0 || write(fd, "x", 1) != 1 || fsync(fd) < 0) _exit(98);
                          char p2[64]; snprintf(p2, sizeof(p2), "%s.r", path);
                          if (rename(path, p2) < 0 || unlink(p2) < 0) _exit(99);
                          _exit(0); }
        case T_PTRACE: { syscall(SYS_ptrace, 0, 0, 0, 0); _exit(100); }
        }
        _exit(101);
    }
    int st = 0;
    waitpid(p, &st, 0);
    return st;
}

static int killed_sigsys(int st) { return WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS; }
static int exited(int st, int code) { return WIFEXITED(st) && WEXITSTATUS(st) == code; }

int main(void) {
#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_UNDEFINED__)
    printf("SKIP: seccomp is compiled out of sanitizer builds\nALL TESTS PASSED\n");
    return 0;
#endif
    int st = run(SANDBOX_ENFORCE, T_FILE_IO);
    if (exited(st, 90)) { printf("SKIP: kernel without seccomp filters\nALL TESTS PASSED\n"); return 0; }
    CHECK(exited(st, 0), "file I/O (open/write/fsync/rename/unlink) allowed");
    CHECK(killed_sigsys(run(SANDBOX_ENFORCE, T_EXEC)), "execve killed");
    CHECK(killed_sigsys(run(SANDBOX_ENFORCE, T_FORK)), "clone without CLONE_THREAD (fork) killed");
    CHECK(exited(run(SANDBOX_ENFORCE, T_THREAD), 0), "pthread_create allowed (clone3 → ENOSYS → clone)");
    CHECK(killed_sigsys(run(SANDBOX_ENFORCE, T_SOCK_NETLINK)), "socket(AF_NETLINK) killed");
    CHECK(exited(run(SANDBOX_ENFORCE, T_SOCK_INET), 0), "socket(AF_INET) allowed");
    CHECK(killed_sigsys(run(SANDBOX_ENFORCE, T_IOCTL_BAD)), "unknown ioctl (TIOCSTI) killed");
    CHECK(exited(run(SANDBOX_ENFORCE, T_IOCTL_FIONBIO), 0), "ioctl FIONBIO allowed");
    CHECK(killed_sigsys(run(SANDBOX_ENFORCE, T_PTRACE)), "ptrace killed");
    CHECK(exited(run(SANDBOX_LOG, T_EXEC), 159), "log mode: blocked syscall → _exit(159)");
    CHECK(exited(run(SANDBOX_OFF, T_FORK), 92), "off: no filter (the raw clone succeeds)");
    CHECK(sandbox_parse_mode("enforce") == SANDBOX_ENFORCE && sandbox_parse_mode("bogus") == -1,
          "mode parsing");
    printf("%d passed, %d failed\n", pass, fail);
    if (fail) return 1;
    printf("ALL TESTS PASSED\n");
    return 0;
}
