/* src/website.c — WebsiteConfiguration parsing (item 6). */

#include "website.h"
#include "xml_parser.h"

#include <stdlib.h>
#include <string.h>

void web_free(web_config_t *w) {
    if (!w) return;
    free(w->index_suffix);
    free(w->error_key);
    free(w->redirect_host);
    free(w->redirect_proto);
    free(w);
}
void web_free_cb(void *o) { web_free(o); }
void *web_parse_cb(const char *xml, size_t n) {
    s3_err_t e;
    return web_parse(xml, n, &e);
}

/* Trimmed text; NULL if empty, too long, or containing control chars,
 * '"', '<', '>' (values reach HTTP headers and HTML). */
static char *text_of(const XMLNode *n, size_t max) {
    const char *t = n && n->content ? n->content : "";
    while (*t == ' ' || *t == '\n' || *t == '\r' || *t == '\t') t++;
    size_t l = strlen(t);
    while (l && (t[l-1] == ' ' || t[l-1] == '\n' || t[l-1] == '\r' || t[l-1] == '\t')) l--;
    if (l == 0 || l > max) return NULL;
    for (size_t i = 0; i < l; i++) {
        unsigned char ch = (unsigned char)t[i];
        if (ch < 0x20 || ch == 0x7f || ch == '"' || ch == '<' || ch == '>') return NULL;
    }
    char *s = malloc(l + 1);
    if (!s) return NULL;
    memcpy(s, t, l);
    s[l] = '\0';
    return s;
}

web_config_t *web_parse(const char *xml, size_t n, s3_err_t *err) {
    *err = S3_ERR_MALFORMED_XML;
    if (n > WEB_MAX_BYTES) return NULL;
    xml_parse_opts_t po = { .max_depth = 6, .max_nodes = 256 };
    XMLNode *root = parse_xml(xml, n, &po, NULL);
    if (!root) return NULL;
    web_config_t *w = calloc(1, sizeof(*w));
    if (!w || strcmp(root->local_name, "WebsiteConfiguration") != 0) goto bad;
    for (int i = 0; i < root->child_count; i++) {
        XMLNode *c = root->children[i];
        if (!strcmp(c->local_name, "IndexDocument")) {
            if (w->index_suffix) goto bad;
            w->index_suffix = text_of(find_child(c, "Suffix"), 1024);
            if (!w->index_suffix || strchr(w->index_suffix, '/')) {
                *err = S3_ERR_INVALID_ARGUMENT; goto bad;
            }
        } else if (!strcmp(c->local_name, "ErrorDocument")) {
            if (w->error_key) goto bad;
            w->error_key = text_of(find_child(c, "Key"), 1024);
            if (!w->error_key) { *err = S3_ERR_INVALID_ARGUMENT; goto bad; }
        } else if (!strcmp(c->local_name, "RedirectAllRequestsTo")) {
            if (w->redirect_host) goto bad;
            w->redirect_host = text_of(find_child(c, "HostName"), 253);
            if (!w->redirect_host || strpbrk(w->redirect_host, "/\\?#@ ")) {
                *err = S3_ERR_INVALID_ARGUMENT; goto bad;
            }
            XMLNode *pr = find_child(c, "Protocol");
            if (pr) {
                w->redirect_proto = text_of(pr, 5);
                if (!w->redirect_proto || (strcmp(w->redirect_proto, "http")
                                           && strcmp(w->redirect_proto, "https"))) {
                    *err = S3_ERR_INVALID_ARGUMENT; goto bad;
                }
            }
        } else if (!strcmp(c->local_name, "RoutingRules")) {
            *err = S3_ERR_NOT_IMPLEMENTED; goto bad;
        } else {
            goto bad;
        }
    }
    /* Either a redirect-everything config or an index document. */
    if (w->redirect_host ? (w->index_suffix || w->error_key) : !w->index_suffix) {
        *err = S3_ERR_INVALID_ARGUMENT; goto bad;
    }
    free_tree(root);
    *err = S3_OK;
    return w;
bad:
    free_tree(root);
    web_free(w);
    return NULL;
}
