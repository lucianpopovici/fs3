/* src/main.c — argv parsing, signal handling, server bootstrap */

#include "log.h"
#include "server.h"
#include "sigv4.h"

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static server_t *g_server;

static void on_signal(int sig) {
    (void)sig;
    if (g_server) server_stop(g_server);
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "usage: %s [options]\n"
        "  -a, --addr <ip>          bind address (default 127.0.0.1)\n"
        "  -p, --port <num>         port (default 9000)\n"
        "  -d, --data <dir>         object store root (default /tmp/fs3-data)\n"
        "      --auth <ak:sk>       add a SigV4 credential (repeatable)\n"
        "      --require-auth       reject requests without an Authorization header\n"
        "  -v, --verbose            debug logging\n"
        "  -h, --help               this help\n",
        argv0);
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

enum {
    OPT_AUTH = 256,
    OPT_REQUIRE_AUTH,
};

int main(int argc, char **argv) {
    const char *addr = "127.0.0.1";
    const char *data_root = "/tmp/fs3-data";
    int port = 9000;
    int verbose = 0;
    int require_auth = 0;
    sigv4_verifier_t *auth = NULL;

    static struct option opts[] = {
        { "addr",         required_argument, NULL, 'a' },
        { "port",         required_argument, NULL, 'p' },
        { "data",         required_argument, NULL, 'd' },
        { "auth",         required_argument, NULL, OPT_AUTH },
        { "require-auth", no_argument,       NULL, OPT_REQUIRE_AUTH },
        { "verbose",      no_argument,       NULL, 'v' },
        { "help",         no_argument,       NULL, 'h' },
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
            case OPT_REQUIRE_AUTH:
                require_auth = 1;
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
        .bind_addr = addr,
        .port      = (uint16_t)port,
        .backlog   = 1024,
        .max_conns = 4096,
        .data_root = data_root,
        .auth      = auth,
        .auth_required = require_auth,
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
