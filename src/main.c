/* src/main.c — argv parsing, signal handling, server bootstrap */

#include "log.h"
#include "server.h"

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
        "  -a, --addr <ip>     bind address (default 127.0.0.1)\n"
        "  -p, --port <num>    port (default 9000)\n"
        "  -d, --data <dir>    object store root (default /tmp/fs3-data)\n"
        "  -v, --verbose       debug logging\n"
        "  -h, --help          this help\n",
        argv0);
}

int main(int argc, char **argv) {
    const char *addr = "127.0.0.1";
    const char *data_root = "/tmp/fs3-data";
    int port = 9000;
    int verbose = 0;

    static struct option opts[] = {
        { "addr",    required_argument, NULL, 'a' },
        { "port",    required_argument, NULL, 'p' },
        { "data",    required_argument, NULL, 'd' },
        { "verbose", no_argument,       NULL, 'v' },
        { "help",    no_argument,       NULL, 'h' },
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
            default:  usage(argv[0]); return 2;
        }
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
    };

    g_server = server_create(&cfg);
    if (!g_server) {
        LOG_E("server_create failed");
        return 1;
    }

    int rc = server_run(g_server);
    server_destroy(g_server);
    g_server = NULL;
    return rc < 0 ? 1 : 0;
}
