/* src/sandbox.c — hand-written seccomp-BPF filter (round 2, item 5).
 *
 * Allowlist built from `make seccomp-profile` (strace over the e2e
 * suites), not from memory. Argument filters: clone only with
 * CLONE_VM|CLONE_THREAD (threads, never processes), socket only for
 * AF_UNIX/AF_INET/AF_INET6, ioctl only for the request numbers in use.
 * clone3 answers ENOSYS (its flags sit behind a pointer BPF can't read);
 * glibc then falls back to clone. fork/vfork/execve are simply absent.
 */
#include "sandbox.h"
#include "log.h"

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U   /* = RET_KILL on kernels < 4.14 */
#endif
#ifndef FICLONE
#define FICLONE      0x40049409
#endif
#ifndef FICLONERANGE
#define FICLONERANGE 0x4020940d
#endif
#ifndef FS_IOC_GETFLAGS
#define FS_IOC_GETFLAGS 0x80086601
#endif
#ifndef FS_IOC_SETFLAGS
#define FS_IOC_SETFLAGS 0x40086602
#endif

#if defined(__x86_64__)
#define SB_ARCH AUDIT_ARCH_X86_64
/* Old kernel headers (3.10 in DSM 7 toolchains, 4.9 in debian:stretch)
 * lack post-3.10 syscall numbers, while the runtime glibc (on DSM or on a
 * newer build host in Part B4) still probes them and expects ENOSYS from
 * the kernel rather than SIGSYS from seccomp. */
#ifndef __NR_renameat2
#define __NR_renameat2       316
#endif
#ifndef __NR_getrandom
#define __NR_getrandom       318
#endif
#ifndef __NR_membarrier
#define __NR_membarrier      324
#endif
#ifndef __NR_copy_file_range
#define __NR_copy_file_range 326
#endif
#ifndef __NR_statx
#define __NR_statx           332
#endif
#ifndef __NR_rseq
#define __NR_rseq            334
#endif
#ifndef __NR_clone3
#define __NR_clone3          435
#endif
#ifndef __NR_faccessat2
#define __NR_faccessat2      439
#endif
#ifndef __NR_epoll_pwait2
#define __NR_epoll_pwait2    441
#endif
#elif defined(__aarch64__)
#define SB_ARCH AUDIT_ARCH_AARCH64
#endif

#if defined(__SANITIZE_ADDRESS__) || defined(__SANITIZE_UNDEFINED__)
#define SB_SANITIZER 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define SB_SANITIZER 1
#endif
#endif

typedef struct { int nr; const char *name; } sb_call_t;
#define C(n) { __NR_##n, #n }

/* Plain allowlist (any arguments). Names missing on an architecture are
 * #ifdef'd so the table compiles on x86_64 and aarch64. */
static const sb_call_t ALLOW[] = {
    /* I/O */
    C(read), C(write), C(pread64), C(pwrite64), C(readv), C(writev), C(sendfile),
    C(lseek), C(close), C(fsync), C(fdatasync), C(fadvise64), C(ftruncate), C(fallocate),
    C(dup), C(dup3), C(fcntl),
#ifdef __NR_copy_file_range          /* kernel 4.5; absent from 3.10 headers */
    C(copy_file_range),
#endif
#ifdef __NR_dup2
    C(dup2),
#endif
    /* files and directories */
    C(openat), C(newfstatat), C(fstat), C(statfs), C(fstatfs), C(getdents64),
    C(renameat), C(linkat), C(unlinkat), C(mkdirat), C(faccessat), C(readlinkat),
    C(utimensat), C(fchmod), C(umask), C(getcwd), C(symlinkat),   /* layout-2 links */
#ifdef __NR_renameat2
    C(renameat2),
#endif
#ifdef __NR_faccessat2
    C(faccessat2),
#endif
#ifdef __NR_statx
    C(statx),
#endif
#ifdef __NR_open
    C(open), C(stat), C(lstat), C(rename), C(link), C(unlink), C(mkdir), C(rmdir),
    C(access), C(readlink), C(getdents), C(symlink),
#endif
    /* network (listeners already bound) */
    C(accept4), C(recvfrom), C(sendto), C(recvmsg), C(sendmsg), C(shutdown),
    C(setsockopt), C(getsockopt), C(getpeername), C(getsockname),
    C(connect),                         /* fs3-lockd's Unix socket (item 9) */
#ifdef __NR_accept
    C(accept),
#endif
    /* event loop */
    C(epoll_ctl), C(epoll_pwait), C(eventfd2), C(ppoll), C(pselect6),
#ifdef __NR_epoll_wait
    C(epoll_wait), C(poll), C(select),
#endif
#ifdef __NR_epoll_pwait2
    C(epoll_pwait2),
#endif
    /* memory */
    C(mmap), C(munmap), C(mprotect), C(mremap), C(brk), C(madvise),
    /* threads and time */
    C(futex), C(set_robust_list), C(get_robust_list), C(sched_yield), C(sched_getaffinity),
    C(gettid), C(getpid), C(getppid), C(getuid), C(geteuid), C(getgid), C(getegid),
    C(clock_gettime), C(clock_getres), C(clock_nanosleep), C(nanosleep), C(gettimeofday),
    C(prctl), C(ioprio_get), C(ioprio_set), C(getrlimit), C(prlimit64), C(sysinfo),
    C(uname),
#ifdef __NR_getrandom               /* kernel 3.17; OpenSSL falls back to /dev/urandom */
    C(getrandom),
#endif
#ifdef __NR_time
    C(time),
#endif
#ifdef __NR_rseq
    C(rseq),
#endif
#ifdef __NR_membarrier
    C(membarrier),
#endif
    /* signals and exit */
    C(rt_sigaction), C(rt_sigprocmask), C(rt_sigreturn), C(rt_sigtimedwait), C(sigaltstack),
    C(tgkill), C(exit), C(exit_group), C(restart_syscall),
};
#undef C

static const unsigned long IOCTLS[] = {
    FIONBIO, FIONREAD, FICLONE, FICLONERANGE, FS_IOC_GETFLAGS, FS_IOC_SETFLAGS, TCGETS,
};

int sandbox_parse_mode(const char *s) {
    if (!strcmp(s, "off"))     return SANDBOX_OFF;
    if (!strcmp(s, "log"))     return SANDBOX_LOG;
    if (!strcmp(s, "enforce")) return SANDBOX_ENFORCE;
    if (!strcmp(s, "require")) return SANDBOX_REQUIRE;
    return -1;
}

void sandbox_print_allowlist(void) {
    for (size_t i = 0; i < sizeof(ALLOW) / sizeof(ALLOW[0]); i++) printf("%s\n", ALLOW[i].name);
    printf("clone\nclone3\nsocket\nioctl\n");      /* argument-filtered */
}

#ifdef SB_ARCH
static void on_sigsys(int sig, siginfo_t *si, void *uc) {
    (void)sig; (void)uc;
    char msg[96];
    int nr = si->si_syscall;
    int n = snprintf(msg, sizeof(msg), "seccomp: blocked syscall %d; exiting (--seccomp=log)\n", nr);
    if (n > 0) (void)!write(2, msg, (size_t)n);
    _exit(159);
}

static struct sock_filter STMT(uint16_t code, uint32_t val) {
    struct sock_filter x = { code, 0, 0, val };
    return x;
}
static struct sock_filter JUMP(uint16_t code, uint32_t val, uint8_t jt, uint8_t jf) {
    struct sock_filter x = { code, jt, jf, val };
    return x;
}
#define LD_NR    STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr))
#define LD_ARG(i) STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[i]))
#define RET(v)   STMT(BPF_RET | BPF_K, (v))
#endif

int sandbox_install(sandbox_mode_t mode) {
    if (mode == SANDBOX_OFF) { LOG_W("seccomp: off (--seccomp=off)"); return 0; }
#if defined(SB_SANITIZER) || !defined(SB_ARCH)
    /* The sanitizer runtimes need far more syscalls than fs3 does. */
    if (mode == SANDBOX_REQUIRE) {
        LOG_E("seccomp: not available in this build; --seccomp=require refuses to start");
        return -1;
    }
    LOG_W("seccomp: not available in this build (sanitizers or unsupported arch); running unfiltered");
    return 0;
#else
    const uint32_t deny = mode == SANDBOX_LOG ? SECCOMP_RET_TRAP : SECCOMP_RET_KILL_PROCESS;
    size_t n_allow = sizeof(ALLOW) / sizeof(ALLOW[0]);
    size_t n_ioctl = sizeof(IOCTLS) / sizeof(IOCTLS[0]);
    size_t cap = 16 + 2 * n_allow + 32 + 2 * n_ioctl;
    struct sock_filter *f = calloc(cap, sizeof(*f));
    if (!f) return mode == SANDBOX_REQUIRE ? -1 : 0;
    size_t k = 0;
    /* Architecture, then the x32 ABI bit. */
    f[k++] = STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    f[k++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, SB_ARCH, 1, 0);
    f[k++] = RET(SECCOMP_RET_KILL_PROCESS);
    f[k++] = LD_NR;
#ifdef __x86_64__
    f[k++] = JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000U, 0, 1);   /* __X32_SYSCALL_BIT */
    f[k++] = RET(SECCOMP_RET_KILL_PROCESS);
#endif
    /* clone: threads only. */
    f[k++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 5);
    f[k++] = LD_ARG(0);
    f[k++] = STMT(BPF_ALU | BPF_AND | BPF_K, CLONE_VM | CLONE_THREAD);
    f[k++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, CLONE_VM | CLONE_THREAD, 0, 1);
    f[k++] = RET(SECCOMP_RET_ALLOW);
    f[k++] = RET(deny);
#ifdef __NR_clone3
    f[k++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1);
    f[k++] = RET(SECCOMP_RET_ERRNO | ENOSYS);
#endif
    /* socket: AF_UNIX / AF_INET / AF_INET6. */
    f[k++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 6);
    f[k++] = LD_ARG(0);
    f[k++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_UNIX, 3, 0);
    f[k++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 2, 0);
    f[k++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 1, 0);
    f[k++] = RET(deny);
    f[k++] = RET(SECCOMP_RET_ALLOW);
    /* ioctl: known request numbers (low 32 bits). */
    f[k++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_ioctl, 0, (uint8_t)(n_ioctl + 3));
    f[k++] = LD_ARG(1);
    for (size_t i = 0; i < n_ioctl; i++)
        f[k++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)IOCTLS[i], (uint8_t)(n_ioctl - i), 0);
    f[k++] = RET(deny);
    f[k++] = RET(SECCOMP_RET_ALLOW);
    /* Everything else: the plain allowlist. */
    for (size_t i = 0; i < n_allow; i++) {
        f[k++] = JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)ALLOW[i].nr, 0, 1);
        f[k++] = RET(SECCOMP_RET_ALLOW);
    }
    f[k++] = RET(deny);

    if (mode == SANDBOX_LOG) {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = on_sigsys;
        sa.sa_flags = SA_SIGINFO;
        sigaction(SIGSYS, &sa, NULL);
    }
    struct sock_fprog prog = { .len = (unsigned short)k, .filter = f };
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    int rc = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    int err = errno;
    free(f);
    if (rc < 0) {
        if (mode == SANDBOX_REQUIRE) {
            LOG_E("seccomp: cannot install the filter (%s); --seccomp=require refuses to start",
                  strerror(err));
            return -1;
        }
        LOG_W("seccomp: kernel refused the filter (%s); running unfiltered", strerror(err));
        return 0;
    }
    LOG_I("seccomp: filter installed (%zu instructions, mode %s)", k,
          mode == SANDBOX_LOG ? "log" : "enforce");
    return 0;
#endif
}
