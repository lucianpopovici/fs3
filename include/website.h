/* include/website.h — static website configuration (item 6). */
#ifndef FS3_WEBSITE_H
#define FS3_WEBSITE_H

#include <stddef.h>
#include "s3.h"

#define WEB_MAX_BYTES (16 * 1024)

typedef struct {
    char *index_suffix;      /* IndexDocument/Suffix, e.g. "index.html" */
    char *error_key;         /* ErrorDocument/Key, or NULL */
    char *redirect_host;     /* RedirectAllRequestsTo/HostName, or NULL */
    char *redirect_proto;    /* "http"/"https", or NULL (same as request) */
} web_config_t;

/* NULL on error with *err set (MalformedXML / InvalidArgument /
 * NotImplemented for RoutingRules). */
web_config_t *web_parse(const char *xml, size_t n, s3_err_t *err);
void          web_free(web_config_t *w);
void         *web_parse_cb(const char *xml, size_t n);
void          web_free_cb(void *o);

#endif
