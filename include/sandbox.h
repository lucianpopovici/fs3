/* include/sandbox.h — seccomp-BPF syscall filter (round 2, item 5).
 *
 * Installed once, after everything privileged or unusual is done
 * (listeners bound, TLS and credentials loaded, store opened and
 * recovered, logs open) and before the I/O worker threads are created,
 * so every thread inherits it (kernel 3.10 has no TSYNC). No libseccomp:
 * the BPF program is built by hand.
 */
#ifndef FS3_SANDBOX_H
#define FS3_SANDBOX_H

typedef enum {
    SANDBOX_OFF = 0,
    SANDBOX_LOG,       /* SIGSYS handler logs the syscall, then _exit(159) */
    SANDBOX_ENFORCE,   /* kill the process; warn and run unfiltered if the kernel can't */
    SANDBOX_REQUIRE,   /* like enforce, but refuse to start without seccomp */
} sandbox_mode_t;

/* "off" / "log" / "enforce" / "require" → mode; -1 if unknown. */
int sandbox_parse_mode(const char *s);

/* 0 installed (or off), -1 failed and the mode demands it (require). */
int sandbox_install(sandbox_mode_t mode);

/* Print the allowlist (one syscall name per line) for the profile diff. */
void sandbox_print_allowlist(void);

#endif
