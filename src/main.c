/* src/main.c — argv parsing, signal handling, server bootstrap */

#include "log.h"
#include "server.h"
#include "sigv4.h"

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* g_server/on_signal pull in server.h symbols (server_stop), which would
 * drag src/server.o and its whole dependency chain into a unit test
 * binary that only wants the credentials-file parser below. Excluded
 * when FS3_MAIN_TESTING is defined — see the test-hook section at the
 * bottom of this file. */
#ifndef FS3_MAIN_TESTING
static server_t *g_server;
#endif
static volatile sig_atomic_t g_reload;

#ifndef FS3_MAIN_TESTING
static void on_signal(int sig) {
    (void)sig;
    if (g_server) server_stop(g_server);
}
#endif

static void on_sighup(int sig) {
    (void)sig;
    g_reload = 1;
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s [options]\n"
        "  -a, --addr <ip>            bind address (default 127.0.0.1)\n"
        "  -p, --port <num>           port (default 9000)\n"
        "  -d, --data <dir>           object store root (default /tmp/fs3-data)\n"
        "      --auth <ak:sk[:user]>  add a SigV4 credential (repeatable); buckets are\n"
        "                             owned by <user>, or by the access key if omitted\n"
        "      --credentials-file <f> load credentials from file (one ak:sk[:user] per line);\n"
        "                             SIGHUP re-reads the file for downtime-free rotation\n"
        "      --require-auth         reject requests without an Authorization header\n"
        "      --admin <user>         user who can see and manage every bucket (repeatable)\n"
        "      --legacy-owner <user>  at startup, give ownerless buckets (made before\n"
        "                             per-user isolation, or in no-auth mode) to <user>\n"
        "      --min-free-bytes <N>   reject uploads when disk free < N (K/M/G suffix ok)\n"
        "      --max-body-size <N>    reject request bodies > N with 413 (default 5G; 0 = off)\n"
        "      --max-conns <num>      concurrent connection cap (default 512)\n"
        "      --idle-timeout <sec>   close idle connections after this long (default 60; 0 = off)\n"
        "      --metrics-port <num>   serve /healthz + /metrics on 127.0.0.1:<num> (0 = off)\n"
        "      --io-threads <num>     worker threads for fsync/copy/MPU completion\n"
        "                             (default 4; 0 = run them on the event loop)\n"
        "      --mpu-gc-interval N    seconds between MPU GC sweeps (default 60)\n"
        "      --mpu-gc-max-age N     seconds before a stale MPU is reaped (default 86400)\n"
        "      --presign-max-expires N  longest accepted presigned-URL lifetime in\n"
        "                             seconds (default 86400; at most 604800)\n"
        "      --no-presign-admin     refuse presigned URLs signed by an --admin user\n"
        "      --lifecycle-hour H     run the lifecycle sweeper daily at local hour H\n"
        "                             (default 3; -1 = never)\n"
        "      --lifecycle-now        also run a sweep right after startup\n"
        "      --lifecycle-rate N     max lifecycle deletions per second (default 100; 0 = no cap)\n"
        "      --lifecycle-dry-run    log what the sweeper would delete, delete nothing\n"
        "      --lifecycle-time-offset S  shift the sweeper's clock by S seconds (testing)\n"
        "      --web-port <num>       serve static websites (anonymous GET/HEAD) here\n"
        "      --web-addr <ip>        website listener address (default 127.0.0.1)\n"
        "      --web-root-domain <d>  websites at <bucket>.<d> (else Host = bucket name)\n"
        "      --allow-public         allow website configs / public bucket policies\n"
        "      --allow-public-write   also allow public policies that grant writes\n"
        "      --trusted-proxy <ip>   honour X-Forwarded-For/-Proto from this proxy\n"
        "                             (repeatable; e.g. 127.0.0.1 behind DSM)\n"
        "      --admin-token-file <f> bearer token for the /v1 admin API on the metrics\n"
        "                             port; file must be mode 0600 and owned by us\n"
        "      --admin-socket <path>  serve the /v1 admin API on a unix socket (0600)\n"
        "                             (block-public-access is on by default)\n"
        "  -v, --verbose              debug logging\n"
        "  -h, --help                 this help\n",
        argv0);
}

/* Parse a size string with optional K/M/G suffix. Returns 0 on error. */
static uint64_t parse_size(const char *s) {
    char *end;
    unsigned long long v = strtoull(s, &end, 10);
    if (end == s) return 0;
    if (*end == 'K' || *end == 'k') v *= 1024ULL;
    else if (*end == 'M' || *end == 'm') v *= 1024ULL * 1024;
    else if (*end == 'G' || *end == 'g') v *= 1024ULL * 1024 * 1024;
    else if (*end != '\0') return 0;
    return (uint64_t)v;
}

/* An identity that owns buckets: a user name, or an access key standing
 * in for one. Stored as a line in each bucket's meta file, so: 1..128
 * printable ASCII characters, no whitespace, no ':'. */
static int valid_identity(const char *u) {
    size_t n = strlen(u);
    if (n == 0 || n > SIGV4_USER_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)u[i];
        if (ch <= ' ' || ch >= 0x7f || ch == ':') return 0;
    }
    return 1;
}

/* Parse "access:secret[:user]" and add it to the verifier. Without a
 * user, the access key is the identity that owns buckets. Returns 0 on
 * success. The input string is not modified. */
static int parse_and_add_cred(sigv4_verifier_t *v, const char *spec) {
    const char *c1 = strchr(spec, ':');
    const char *c2 = c1 ? strchr(c1 + 1, ':') : NULL;
    if (!c1 || c1 == spec || c1[1] == 0 || c1[1] == ':'
        || (c2 && c2[1] == 0)) {
        fprintf(stderr, "invalid credential: expected "
                        "<access_key>:<secret_key>[:<user>]\n");
        return -1;
    }
    char *ak = strndup(spec, (size_t)(c1 - spec));
    char *sk = c2 ? strndup(c1 + 1, (size_t)(c2 - c1 - 1)) : strdup(c1 + 1);
    const char *user = c2 ? c2 + 1 : NULL;
    int rc = -1;
    if (!ak || !sk) goto out;
    if (!valid_identity(user ? user : ak)) {
        fprintf(stderr, "invalid credential: user (or access key used as "
                        "user) must be 1-%d printable characters without "
                        "spaces or ':'\n", SIGV4_USER_MAX);
        goto out;
    }
    if (sigv4_add_cred_user(v, ak, sk, user) != 0) {
        fprintf(stderr, "failed to add credential (duplicate or OOM)\n");
        goto out;
    }
    rc = 0;
out:
    free(ak);
    free(sk);
    return rc;
}

/* Load credentials from a file. Format: one "access_key:secret_key[:user]"
 * per line.
 * Lines starting with '#' and blank lines are ignored. Returns 0 on success. */
static int load_credentials_file(sigv4_verifier_t *v, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "cannot open credentials file %s: ", path);
        perror(NULL);
        return -1;
    }
    char line[512];
    int lineno = 0, loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        size_t n = strlen(line);
        while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r'
                         || line[n-1] == ' '  || line[n-1] == '\t'))
            line[--n] = '\0';
        if (n == 0 || line[0] == '#') continue;
        if (parse_and_add_cred(v, line) < 0) {
            fprintf(stderr, "%s:%d: invalid credential line\n", path, lineno);
            fclose(f);
            return -1;
        }
        loaded++;
    }
    fclose(f);
    if (loaded == 0) {
        fprintf(stderr, "%s: no credentials found\n", path);
        return -1;
    }
    fprintf(stderr, "loaded %d credential(s) from %s\n", loaded, path);
    return 0;
}

/* SIGHUP credential reload. Rebuilds the complete credential set — the
 * CLI --auth specs plus the credentials file — in a scratch verifier,
 * then swaps it into the live one (sigv4_swap_creds). Build-then-swap:
 * a malformed or missing file leaves the live credentials untouched, so
 * a botched rotation can't lock everyone out. Invoked from the server's
 * once-per-second tick, never concurrently with a request. */
typedef struct {
    sigv4_verifier_t *live;            /* NULL if auth disabled */
    const char       *cred_file;       /* NULL if not configured */
    const char       *auth_specs[32];  /* argv pointers, stable for the
                                          process lifetime */
    int               n_auth_specs;
} reload_ctx_t;

static int do_reload(void *user);

static void reload_tick(void *user) {
    if (!g_reload) return;
    g_reload = 0;
    (void)do_reload(user);
}

/* Build-then-swap credential reload; also called by the admin API after
 * it rewrites the credentials file. 0 on success. */
static int do_reload(void *user) {
    reload_ctx_t *r = user;
    if (!r->live || !r->cred_file) {
        LOG_W("SIGHUP: credential reload needs --credentials-file; ignored");
        return -1;
    }
    sigv4_verifier_t *scratch = sigv4_create();
    if (!scratch) {
        LOG_E("SIGHUP reload: out of memory; keeping old credentials");
        return -1;
    }
    for (int i = 0; i < r->n_auth_specs; i++) {
        if (parse_and_add_cred(scratch, r->auth_specs[i]) < 0) {
            LOG_E("SIGHUP reload: bad --auth spec; keeping old credentials");
            sigv4_destroy(scratch);
            return -1;
        }
    }
    if (load_credentials_file(scratch, r->cred_file) < 0) {
        LOG_E("SIGHUP reload: cannot load %s; keeping old credentials",
              r->cred_file);
        sigv4_destroy(scratch);
        return -1;
    }
    sigv4_swap_creds(r->live, scratch);
    sigv4_destroy(scratch);  /* now holds (and zeroes) the old list */
    LOG_I("SIGHUP: credentials reloaded from %s", r->cred_file);
    return 0;
}

enum {
    OPT_AUTH = 256,
    OPT_CREDENTIALS_FILE,
    OPT_REQUIRE_AUTH,
    OPT_MIN_FREE_BYTES,
    OPT_MPU_GC_INTERVAL,
    OPT_MPU_GC_MAX_AGE,
    OPT_MAX_BODY_SIZE,
    OPT_MAX_CONNS,
    OPT_IDLE_TIMEOUT,
    OPT_METRICS_PORT,
    OPT_IO_THREADS,
    OPT_ADMIN,
    OPT_LEGACY_OWNER,
    OPT_PRESIGN_MAX_EXPIRES,
    OPT_NO_PRESIGN_ADMIN,
    OPT_LIFECYCLE_HOUR,
    OPT_LIFECYCLE_NOW,
    OPT_LIFECYCLE_RATE,
    OPT_LIFECYCLE_DRY_RUN,
    OPT_LIFECYCLE_TIME_OFFSET,
    OPT_WEB_ADDR,
    OPT_WEB_PORT,
    OPT_WEB_ROOT_DOMAIN,
    OPT_ALLOW_PUBLIC,
    OPT_ADMIN_TOKEN_FILE,
    OPT_ADMIN_SOCKET,
    OPT_ALLOW_PUBLIC_WRITE,
    OPT_TRUSTED_PROXY,
};

#ifndef FS3_MAIN_TESTING
/* Read a secret (first line, trimmed) from a file that must be a
 * regular file, mode 0600 (no group/other bits), owned by our euid —
 * else refuse to start (S8/S10). */
static int read_secret_file(const char *path, char *out, size_t cap) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) < 0) {
        fprintf(stderr, "%s: cannot open: %s\n", path, strerror(errno));
        if (fd >= 0) close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode) || (st.st_mode & 077) || st.st_uid != geteuid()) {
        fprintf(stderr, "%s: must be a regular file, mode 0600, owned by the "
                        "service user\n", path);
        close(fd);
        return -1;
    }
    ssize_t n = read(fd, out, cap - 1);
    close(fd);
    if (n <= 0) { fprintf(stderr, "%s: empty\n", path); return -1; }
    out[n] = '\0';
    out[strcspn(out, "\r\n")] = '\0';
    size_t len = strlen(out);
    while (len && (out[len-1] == ' ' || out[len-1] == '\t')) out[--len] = '\0';
    if (len < 16) { fprintf(stderr, "%s: secret must be at least 16 characters\n", path); return -1; }
    return 0;
}

int main(int argc, char **argv) {
    const char *addr = "127.0.0.1";
    const char *data_root = "/tmp/fs3-data";
    int port = 9000;
    int verbose = 0;
    int require_auth = 0;
    int gc_interval_s = 0;        /* 0 → server defaults to 60 */
    uint64_t gc_max_age_ms = 0;   /* 0 → server defaults to 24h */
    uint64_t min_free_bytes = 0;  /* 0 → no quota */
    /* Defaults sized for small hardware (the SPK targets a 2 GB-RAM
     * NAS): bodies capped at the S3 single-PUT limit, a connection cap
     * whose fixed buffers stay well under 100 MB, and an idle sweep so
     * stuck clients can't pin slots. Each is flag-overridable; 0
     * disables the body cap / idle sweep. */
    uint64_t max_body_bytes = 5ULL * 1024 * 1024 * 1024;  /* 5 GiB */
    int max_conns = 512;
    int idle_timeout_s = 60;
    int metrics_port = 0;         /* 0 = no admin/metrics listener */
    /* Blocking store work (commit fsync, copy, MPU completion) runs on
     * this many threads so the event loop stays responsive. A handful is
     * plenty: the work is disk-bound, not CPU-bound. */
    int io_threads = 4;
    const char *admins[32];
    int n_admins = 0;
    const char *legacy_owner = NULL;
    long presign_max_expires = 86400;   /* 24 h; AWS allows 7 days */
    int no_presign_admin = 0;
    int lifecycle_hour = 3, lifecycle_now = 0, lifecycle_rate = 100;
    int lifecycle_dry_run = 0;
    long lifecycle_time_offset = 0;
    const char *web_addr = "127.0.0.1", *web_root_domain = NULL;
    int web_port = 0, allow_public = 0;
    char admin_token[256] = "";
    const char *admin_socket = NULL;
    int allow_public_write = 0;
    char trusted_proxies[1024] = "";
    sigv4_verifier_t *auth = NULL;
    reload_ctx_t reload_ctx = {0};

    static struct option opts[] = {
        { "addr",             required_argument, NULL, 'a' },
        { "port",             required_argument, NULL, 'p' },
        { "data",             required_argument, NULL, 'd' },
        { "auth",             required_argument, NULL, OPT_AUTH },
        { "credentials-file", required_argument, NULL, OPT_CREDENTIALS_FILE },
        { "require-auth",     no_argument,       NULL, OPT_REQUIRE_AUTH },
        { "min-free-bytes",   required_argument, NULL, OPT_MIN_FREE_BYTES },
        { "max-body-size",    required_argument, NULL, OPT_MAX_BODY_SIZE },
        { "max-conns",        required_argument, NULL, OPT_MAX_CONNS },
        { "idle-timeout",     required_argument, NULL, OPT_IDLE_TIMEOUT },
        { "metrics-port",     required_argument, NULL, OPT_METRICS_PORT },
        { "io-threads",       required_argument, NULL, OPT_IO_THREADS },
        { "admin",            required_argument, NULL, OPT_ADMIN },
        { "legacy-owner",     required_argument, NULL, OPT_LEGACY_OWNER },
        { "mpu-gc-interval",  required_argument, NULL, OPT_MPU_GC_INTERVAL },
        { "mpu-gc-max-age",   required_argument, NULL, OPT_MPU_GC_MAX_AGE },
        { "presign-max-expires", required_argument, NULL, OPT_PRESIGN_MAX_EXPIRES },
        { "no-presign-admin", no_argument,       NULL, OPT_NO_PRESIGN_ADMIN },
        { "lifecycle-hour",   required_argument, NULL, OPT_LIFECYCLE_HOUR },
        { "lifecycle-now",    no_argument,       NULL, OPT_LIFECYCLE_NOW },
        { "lifecycle-rate",   required_argument, NULL, OPT_LIFECYCLE_RATE },
        { "lifecycle-dry-run", no_argument,      NULL, OPT_LIFECYCLE_DRY_RUN },
        { "lifecycle-time-offset", required_argument, NULL, OPT_LIFECYCLE_TIME_OFFSET },
        { "web-addr",         required_argument, NULL, OPT_WEB_ADDR },
        { "web-port",         required_argument, NULL, OPT_WEB_PORT },
        { "web-root-domain",  required_argument, NULL, OPT_WEB_ROOT_DOMAIN },
        { "allow-public",     no_argument,       NULL, OPT_ALLOW_PUBLIC },
        { "admin-token-file", required_argument, NULL, OPT_ADMIN_TOKEN_FILE },
        { "admin-socket",     required_argument, NULL, OPT_ADMIN_SOCKET },
        { "allow-public-write", no_argument,     NULL, OPT_ALLOW_PUBLIC_WRITE },
        { "trusted-proxy",    required_argument, NULL, OPT_TRUSTED_PROXY },
        { "verbose",          no_argument,       NULL, 'v' },
        { "help",             no_argument,       NULL, 'h' },
        { 0 },
    };

    int c;
    while ((c = getopt_long(argc, argv, "a:p:d:vh", opts, NULL)) != -1) {
        switch (c) {
            case 'a': addr = optarg; break;
            case 'p': port = atoi(optarg); break;
            case 'd': data_root = optarg; break;
            case 'v': verbose = 1; break;
            case 'h': usage(argv[0]); return 0;
            case OPT_AUTH:
                if (!auth) {
                    auth = sigv4_create();
                    if (!auth) {
                        fprintf(stderr, "sigv4_create OOM\n");
                        return 1;
                    }
                }
                if (parse_and_add_cred(auth, optarg) < 0) {
                    sigv4_destroy(auth);
                    return 2;
                }
                if (reload_ctx.n_auth_specs
                    < (int)(sizeof(reload_ctx.auth_specs)
                            / sizeof(reload_ctx.auth_specs[0]))) {
                    reload_ctx.auth_specs[reload_ctx.n_auth_specs++] = optarg;
                }
                break;
            case OPT_CREDENTIALS_FILE:
                if (!auth) {
                    auth = sigv4_create();
                    if (!auth) {
                        fprintf(stderr, "sigv4_create OOM\n");
                        return 1;
                    }
                }
                if (load_credentials_file(auth, optarg) < 0) {
                    sigv4_destroy(auth);
                    return 2;
                }
                reload_ctx.cred_file = optarg;
                break;
            case OPT_REQUIRE_AUTH:
                require_auth = 1;
                break;
            case OPT_MIN_FREE_BYTES:
                min_free_bytes = parse_size(optarg);
                if (min_free_bytes == 0) {
                    fprintf(stderr, "--min-free-bytes: invalid size '%s'\n",
                            optarg);
                    return 2;
                }
                break;
            case OPT_MAX_BODY_SIZE:
                /* "0" disables; parse_size returns 0 for both "0" and
                 * garbage, so check the spelling explicitly. */
                if (strcmp(optarg, "0") == 0) {
                    max_body_bytes = 0;
                } else {
                    max_body_bytes = parse_size(optarg);
                    if (max_body_bytes == 0) {
                        fprintf(stderr, "--max-body-size: invalid size '%s'\n",
                                optarg);
                        return 2;
                    }
                }
                break;
            case OPT_MAX_CONNS:
                max_conns = atoi(optarg);
                if (max_conns < 1) {
                    fprintf(stderr, "--max-conns must be >= 1\n");
                    return 2;
                }
                break;
            case OPT_IDLE_TIMEOUT:
                idle_timeout_s = atoi(optarg);
                if (idle_timeout_s < 0) {
                    fprintf(stderr, "--idle-timeout must be >= 0 (0 disables)\n");
                    return 2;
                }
                break;
            case OPT_METRICS_PORT:
                metrics_port = atoi(optarg);
                if (metrics_port < 1 || metrics_port > 65535) {
                    fprintf(stderr, "--metrics-port must be 1..65535\n");
                    return 2;
                }
                break;
            case OPT_ADMIN:
                if (!valid_identity(optarg)) {
                    fprintf(stderr, "--admin: invalid user name '%s'\n", optarg);
                    return 2;
                }
                if (n_admins == (int)(sizeof(admins) / sizeof(admins[0]))) {
                    fprintf(stderr, "--admin: at most %d admins\n", n_admins);
                    return 2;
                }
                admins[n_admins++] = optarg;
                break;
            case OPT_LEGACY_OWNER:
                if (!valid_identity(optarg)) {
                    fprintf(stderr, "--legacy-owner: invalid user name '%s'\n",
                            optarg);
                    return 2;
                }
                legacy_owner = optarg;
                break;
            case OPT_IO_THREADS:
                io_threads = atoi(optarg);
                if (io_threads < 0 || io_threads > 64) {
                    fprintf(stderr, "--io-threads must be 0..64\n");
                    return 2;
                }
                break;
            case OPT_MPU_GC_INTERVAL:
                gc_interval_s = atoi(optarg);
                if (gc_interval_s < 1) {
                    fprintf(stderr, "--mpu-gc-interval must be >= 1\n");
                    return 2;
                }
                break;
            case OPT_MPU_GC_MAX_AGE:
                gc_max_age_ms = (uint64_t)atoll(optarg) * 1000;
                if (gc_max_age_ms == 0) {
                    fprintf(stderr, "--mpu-gc-max-age must be >= 1\n");
                    return 2;
                }
                break;
            case OPT_PRESIGN_MAX_EXPIRES:
                presign_max_expires = atol(optarg);
                if (presign_max_expires < 1 || presign_max_expires > 604800) {
                    fprintf(stderr, "--presign-max-expires must be 1..604800\n");
                    return 2;
                }
                break;
            case OPT_NO_PRESIGN_ADMIN:
                no_presign_admin = 1;
                break;
            case OPT_LIFECYCLE_HOUR:
                lifecycle_hour = atoi(optarg);
                if (lifecycle_hour < -1 || lifecycle_hour > 23) {
                    fprintf(stderr, "--lifecycle-hour must be 0..23 (-1 = off)\n");
                    return 2;
                }
                break;
            case OPT_LIFECYCLE_NOW:     lifecycle_now = 1; break;
            case OPT_LIFECYCLE_DRY_RUN: lifecycle_dry_run = 1; break;
            case OPT_LIFECYCLE_RATE:
                lifecycle_rate = atoi(optarg);
                if (lifecycle_rate < 0) {
                    fprintf(stderr, "--lifecycle-rate must be >= 0\n");
                    return 2;
                }
                break;
            case OPT_LIFECYCLE_TIME_OFFSET:
                lifecycle_time_offset = atol(optarg);
                break;
            case OPT_WEB_ADDR: web_addr = optarg; break;
            case OPT_WEB_PORT:
                web_port = atoi(optarg);
                if (web_port < 1 || web_port > 65535) {
                    fprintf(stderr, "--web-port must be 1..65535\n");
                    return 2;
                }
                break;
            case OPT_WEB_ROOT_DOMAIN: {
                /* Lowercase hostname chars only. */
                for (const char *q = optarg; *q; q++) {
                    if (!((*q >= 'a' && *q <= 'z') || (*q >= '0' && *q <= '9')
                          || *q == '.' || *q == '-')) {
                        fprintf(stderr, "--web-root-domain: invalid host name\n");
                        return 2;
                    }
                }
                web_root_domain = optarg;
                break;
            }
            case OPT_ALLOW_PUBLIC: allow_public = 1; break;
            case OPT_ADMIN_SOCKET: admin_socket = optarg; break;
            case OPT_ALLOW_PUBLIC_WRITE: allow_public_write = 1; allow_public = 1; break;
            case OPT_TRUSTED_PROXY: {
                size_t cur = strlen(trusted_proxies);
                if (strlen(optarg) > 60 || strchr(optarg, ',')
                    || cur + strlen(optarg) + 2 >= sizeof(trusted_proxies)) {
                    fprintf(stderr, "--trusted-proxy: one IP per flag\n");
                    return 2;
                }
                snprintf(trusted_proxies + cur, sizeof(trusted_proxies) - cur, "%s%s",
                         cur ? "," : "", optarg);
                break;
            }
            case OPT_ADMIN_TOKEN_FILE:
                if (read_secret_file(optarg, admin_token, sizeof(admin_token)) < 0)
                    return 2;
                break;
            default:  usage(argv[0]); return 2;
        }
    }
    if (auth) sigv4_set_presign_policy(auth, presign_max_expires, no_presign_admin);

    if (require_auth && !auth) {
        fprintf(stderr, "--require-auth requires at least one --auth credential\n");
        return 2;
    }
    if (n_admins > 0 && !auth) {
        fprintf(stderr, "--admin requires --auth or --credentials-file\n");
        return 2;
    }
    for (int i = 0; i < n_admins; i++) {
        if (sigv4_add_admin(auth, admins[i]) != 0) {
            fprintf(stderr, "--admin: out of memory\n");
            sigv4_destroy(auth);
            return 1;
        }
    }

    log_init(verbose ? LOG_DEBUG : LOG_INFO);

    /* Ignore SIGPIPE; we handle EPIPE on write() instead. */
    signal(SIGPIPE, SIG_IGN);

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* SIGHUP = reload credentials (handled on the event-loop tick). */
    struct sigaction sa_hup = { .sa_handler = on_sighup, .sa_flags = SA_RESTART };
    sigemptyset(&sa_hup.sa_mask);
    sigaction(SIGHUP, &sa_hup, NULL);
    reload_ctx.live = auth;

    server_cfg_t cfg = {
        .bind_addr     = addr,
        .port          = (uint16_t)port,
        .backlog       = 1024,
        .max_conns     = max_conns,
        .data_root     = data_root,
        .auth          = auth,
        .auth_required = require_auth,
        .gc_interval_s = gc_interval_s,
        .gc_max_age_ms = gc_max_age_ms,
        .min_free_bytes = min_free_bytes,
        .max_body_bytes = max_body_bytes,
        .idle_timeout_s = idle_timeout_s,
        .metrics_port   = (uint16_t)metrics_port,
        .io_threads     = io_threads,
        .legacy_owner   = legacy_owner,
        .lifecycle_hour = lifecycle_hour,
        .lifecycle_now  = lifecycle_now,
        .lifecycle_rate = lifecycle_rate,
        .lifecycle_dry_run = lifecycle_dry_run,
        .lifecycle_time_offset_s = lifecycle_time_offset,
        .web_addr        = web_addr,
        .web_port        = (uint16_t)web_port,
        .web_root_domain = web_root_domain,
        .allow_public    = allow_public,
        .allow_public_write = allow_public_write,
        .trusted_proxies = trusted_proxies[0] ? trusted_proxies : NULL,
        .admin_token     = admin_token[0] ? admin_token : NULL,
        .admin_socket    = admin_socket,
        .admin_cred_file = reload_ctx.cred_file,
        .admin_reload    = do_reload,
        .admin_reload_user = &reload_ctx,
        .tick_cb        = reload_tick,
        .tick_user      = &reload_ctx,
    };

    g_server = server_create(&cfg);
    if (!g_server) {
        LOG_E("server_create failed");
        sigv4_destroy(auth);
        return 1;
    }

    int rc = server_run(g_server);
    server_destroy(g_server);
    g_server = NULL;
    sigv4_destroy(auth);
    return rc < 0 ? 1 : 0;
}
#endif /* FS3_MAIN_TESTING */

/* ===================================================================== */
/* Test hooks (only enabled when FS3_MAIN_TESTING is defined)             */
/* ===================================================================== */
#ifdef FS3_MAIN_TESTING

/* Thin non-static wrappers around the static credentials-file parser,
 * mirroring sigv4.c's SIGV4_TESTING seam. This is the security boundary
 * for per-user bucket isolation, so it gets a dedicated unit harness
 * (tests/test_credfile.c) rather than only end-to-end coverage. */

int main_test_parse_and_add_cred(sigv4_verifier_t *v, const char *spec);
int main_test_load_credentials_file(sigv4_verifier_t *v, const char *path);
int main_test_valid_identity(const char *u);

int main_test_parse_and_add_cred(sigv4_verifier_t *v, const char *spec) {
    return parse_and_add_cred(v, spec);
}

int main_test_load_credentials_file(sigv4_verifier_t *v, const char *path) {
    return load_credentials_file(v, path);
}

int main_test_valid_identity(const char *u) {
    return valid_identity(u);
}

#endif /* FS3_MAIN_TESTING */
