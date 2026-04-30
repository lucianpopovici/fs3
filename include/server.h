/* include/server.h — epoll-driven TCP server */
#ifndef FS3_SERVER_H
#define FS3_SERVER_H

#include <stdint.h>

typedef struct server server_t;

typedef struct {
    const char *bind_addr;   /* e.g. "0.0.0.0" */
    uint16_t    port;        /* e.g. 9000 */
    int         backlog;     /* listen() backlog */
    int         max_conns;   /* hard cap on concurrent connections */
    const char *data_root;   /* path for the object store; required */
} server_cfg_t;

server_t *server_create(const server_cfg_t *cfg);
void      server_destroy(server_t *s);

/* Run the event loop until server_stop() is called or a fatal error occurs.
 * Returns 0 on graceful shutdown, -1 on fatal error. */
int       server_run(server_t *s);
void      server_stop(server_t *s);

#endif
