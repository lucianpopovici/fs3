/* src/main.c — argv parsing, signal handling, server bootstrap */

#include "log.h"
#include "server.h"
#include "sigv4.h"

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static server_t *g_server;

static void on_signal(int sig) {
    (void)sig;
    if (g_server) server_stop(g_server);
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s [options]\n"
        "  -a, --addr <ip>            bind address (default 127.0.0.1)\n"
        "  -p, --port <num>           port (default 9000)\n"
        "  -d, --data <dir>           object store root (default /tmp/fs3-data)\n"
        "      --auth <ak:sk>         add a SigV4 credential (repeatable)\n"
        "      --credentials-file <f> load credentials from file (one ak:sk per line)\n"
        "      --require-auth         reject requests without an Authorization header\n"
        "      --min-free-bytes <N>   reject uploads when disk free < N (K/M/G suffix ok)\n"
        "      --mpu-gc-interval N    seconds between MPU GC sweeps (default 60)\n"
        "      --mpu-gc-max-age N     seconds before a stale MPU is reaped (default 86400)\n"
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

/* Parse "access:secret" into ak/sk and add to verifier. Returns 0 on
 * success. The input string is not modified. */
static int parse_and_add_cred(sigv4_verifier_t *v, const char *spec) {
    const char *colon = strchr(spec, ':');
    if (!colon || colon == spec || colon[1] == 0) {
        fprintf(stderr, "invalid --auth: expected <access_key>:<secret_key>\n");
        return -1;
    }
    size_t ak_n = (size_t)(colon - spec);
    char *ak = strndup(spec, ak_n);
    const char *sk = colon + 1;
    if (!ak) return -1;
    int rc = sigv4_add_cred(v, ak, sk);
    free(ak);
    if (rc != 0) {
        fprintf(stderr, "failed to add credential (duplicate or OOM)\n");
        return -1;
    }
    return 0;
}

/* Load credentials from a file. Format: one "access_key:secret_key" per line.
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

enum {
    OPT_AUTH = 256,
    OPT_CREDENTIALS_FILE,
    OPT_REQUIRE_AUTH,
    OPT_MIN_FREE_BYTES,
    OPT_MPU_GC_INTERVAL,
    OPT_MPU_GC_MAX_AGE,
};

int main(int argc, char **argv) {
    const char *addr = "127.0.0.1";
    const char *data_root = "/tmp/fs3-data";
    int port = 9000;
    int verbose = 0;
    int require_auth = 0;
    int gc_interval_s = 0;        /* 0 → server defaults to 60 */
    uint64_t gc_max_age_ms = 0;   /* 0 → server defaults to 24h */
    uint64_t min_free_bytes = 0;  /* 0 → no quota */
    sigv4_verifier_t *auth = NULL;

    static struct option opts[] = {
        { "addr",             required_argument, NULL, 'a' },
        { "port",             required_argument, NULL, 'p' },
        { "data",             required_argument, NULL, 'd' },
        { "auth",             required_argument, NULL, OPT_AUTH },
        { "credentials-file", required_argument, NULL, OPT_CREDENTIALS_FILE },
        { "require-auth",     no_argument,       NULL, OPT_REQUIRE_AUTH },
        { "min-free-bytes",   required_argument, NULL, OPT_MIN_FREE_BYTES },
        { "mpu-gc-interval",  required_argument, NULL, OPT_MPU_GC_INTERVAL },
        { "mpu-gc-max-age",   required_argument, NULL, OPT_MPU_GC_MAX_AGE },
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
            default:  usage(argv[0]); return 2;
        }
    }

    if (require_auth && !auth) {
        fprintf(stderr, "--require-auth requires at least one --auth credential\n");
        return 2;
    }

    log_init(verbose ? LOG_DEBUG : LOG_INFO);

    /* Ignore SIGPIPE; we handle EPIPE on write() instead. */
    signal(SIGPIPE, SIG_IGN);

    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    server_cfg_t cfg = {
        .bind_addr     = addr,
        .port          = (uint16_t)port,
        .backlog       = 1024,
        .max_conns     = 4096,
        .data_root     = data_root,
        .auth          = auth,
        .auth_required = require_auth,
        .gc_interval_s = gc_interval_s,
        .gc_max_age_ms = gc_max_age_ms,
        .min_free_bytes = min_free_bytes,
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
