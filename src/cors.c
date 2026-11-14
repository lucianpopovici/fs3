/* src/cors.c — CORSConfiguration parsing, validation and matching. */

#include "cors.h"
#include "xml_parser.h"

#include <stdlib.h>
#include <string.h>

static void free_strs(char **v, size_t n) {
    for (size_t i = 0; i < n; i++) free(v[i]);
    free(v);
}

void cors_free(cors_config_t *c) {
    if (!c) return;
    for (size_t i = 0; i < c->n_rules; i++) {
        cors_rule_t *r = &c->rules[i];
        free_strs(r->origins, r->n_origins);
        free_strs(r->headers, r->n_headers);
        free_strs(r->expose, r->n_expose);
    }
    free(c->rules);
    free(c);
}

void cors_free_cb(void *o) { cors_free(o); }

void *cors_parse_cb(const char *xml, size_t n) {
    s3_err_t e;
    return cors_parse(xml, n, &e);
}

int cors_method_bit(s3_str_t m) {
    if (s3_str_eq_lit(m, "GET"))    return CORS_GET;
    if (s3_str_eq_lit(m, "PUT"))    return CORS_PUT;
    if (s3_str_eq_lit(m, "POST"))   return CORS_POST;
    if (s3_str_eq_lit(m, "DELETE")) return CORS_DELETE;
    if (s3_str_eq_lit(m, "HEAD"))   return CORS_HEAD;
    return 0;
}

/* Trimmed copy of a node's text, or NULL. Rejects control characters:
 * these values end up in response headers. */
static char *text_of(const XMLNode *n) {
    const char *t = n->content ? n->content : "";
    while (*t == ' ' || *t == '\t' || *t == '\n' || *t == '\r') t++;
    size_t len = strlen(t);
    while (len && (t[len-1] == ' ' || t[len-1] == '\t'
                   || t[len-1] == '\n' || t[len-1] == '\r')) len--;
    if (len == 0 || len > 1024) return NULL;
    for (size_t i = 0; i < len; i++)
        if ((unsigned char)t[i] < 0x20 || t[i] == 0x7f) return NULL;
    char *s = malloc(len + 1);
    if (!s) return NULL;
    memcpy(s, t, len);
    s[len] = '\0';
    return s;
}

static int push(char ***v, size_t *n, char *s) {
    char **nv = realloc(*v, (*n + 1) * sizeof(**v));
    if (!nv) { free(s); return -1; }
    *v = nv;
    nv[(*n)++] = s;
    return 0;
}

cors_config_t *cors_parse(const char *xml, size_t n, s3_err_t *err) {
    *err = S3_ERR_MALFORMED_XML;
    if (n > CORS_MAX_BYTES) return NULL;
    xml_parse_opts_t po = { .max_depth = 8, .max_nodes = 8192 };
    XMLNode *root = parse_xml(xml, n, &po, NULL);
    if (!root) return NULL;
    cors_config_t *c = calloc(1, sizeof(*c));
    if (!c || strcmp(root->local_name, "CORSConfiguration") != 0) goto bad;

    for (int i = 0; i < root->child_count; i++) {
        XMLNode *rn = root->children[i];
        if (strcmp(rn->local_name, "CORSRule") != 0) goto bad;
        if (c->n_rules >= CORS_MAX_RULES) { *err = S3_ERR_INVALID_REQUEST; goto bad; }
        cors_rule_t *nr = realloc(c->rules, (c->n_rules + 1) * sizeof(*nr));
        if (!nr) goto bad;
        c->rules = nr;
        cors_rule_t *r = &c->rules[c->n_rules++];
        memset(r, 0, sizeof(*r));
        r->max_age = -1;
        for (int j = 0; j < rn->child_count; j++) {
            XMLNode *f = rn->children[j];
            const char *nm = f->local_name;
            if (strcmp(nm, "ID") == 0) continue;
            char *t = text_of(f);
            if (!t) goto bad;
            if (strcmp(nm, "AllowedOrigin") == 0) {
                const char *star = strchr(t, '*');
                if (star && strchr(star + 1, '*')) {
                    free(t); *err = S3_ERR_INVALID_REQUEST; goto bad;
                }
                if (push(&r->origins, &r->n_origins, t) < 0) goto bad;
            } else if (strcmp(nm, "AllowedMethod") == 0) {
                int b = cors_method_bit((s3_str_t){ t, strlen(t) });
                free(t);
                if (!b) { *err = S3_ERR_INVALID_REQUEST; goto bad; }
                r->methods |= b;
            } else if (strcmp(nm, "AllowedHeader") == 0) {
                if (push(&r->headers, &r->n_headers, t) < 0) goto bad;
            } else if (strcmp(nm, "ExposeHeader") == 0) {
                if (strchr(t, '*') || strchr(t, ',')) {
                    free(t); *err = S3_ERR_INVALID_REQUEST; goto bad;
                }
                if (push(&r->expose, &r->n_expose, t) < 0) goto bad;
            } else if (strcmp(nm, "MaxAgeSeconds") == 0) {
                char *end;
                long v = strtol(t, &end, 10);
                int ok = *end == '\0' && v >= 0 && v <= 86400 * 365;
                free(t);
                if (!ok) { *err = S3_ERR_INVALID_REQUEST; goto bad; }
                r->max_age = v;
            } else {
                free(t);
                goto bad;
            }
        }
        if (!r->n_origins || !r->methods) { *err = S3_ERR_INVALID_REQUEST; goto bad; }
    }
    if (c->n_rules == 0) goto bad;
    free_tree(root);
    *err = S3_OK;
    return c;
bad:
    free_tree(root);
    cors_free(c);
    return NULL;
}

static char lc(char ch) { return (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch; }

static int eqc(char a, char b, int icase) {
    return icase ? lc(a) == lc(b) : a == b;
}

int cors_glob(const char *pat, s3_str_t s, int icase) {
    const char *star = strchr(pat, '*');
    size_t pn = strlen(pat);
    if (!star) {
        if (pn != s.n) return 0;
        for (size_t i = 0; i < pn; i++) if (!eqc(pat[i], s.p[i], icase)) return 0;
        return 1;
    }
    size_t pre = (size_t)(star - pat), suf = pn - pre - 1;
    if (s.n < pre + suf) return 0;
    for (size_t i = 0; i < pre; i++) if (!eqc(pat[i], s.p[i], icase)) return 0;
    for (size_t i = 0; i < suf; i++)
        if (!eqc(star[1 + i], s.p[s.n - suf + i], icase)) return 0;
    return 1;
}

static int header_allowed(const cors_rule_t *r, s3_str_t h) {
    for (size_t i = 0; i < r->n_headers; i++)
        if (cors_glob(r->headers[i], h, 1)) return 1;
    return 0;
}

const cors_rule_t *cors_match(const cors_config_t *c, s3_str_t origin,
                              int method_bit, s3_str_t req_headers) {
    if (!c || origin.n == 0 || !method_bit) return NULL;
    for (size_t i = 0; i < c->n_rules; i++) {
        const cors_rule_t *r = &c->rules[i];
        if (!(r->methods & method_bit)) continue;
        int om = 0;
        for (size_t j = 0; j < r->n_origins && !om; j++)
            om = cors_glob(r->origins[j], origin, 0);
        if (!om) continue;
        int ok = 1;
        size_t k = 0;
        while (ok && k < req_headers.n) {
            while (k < req_headers.n && (req_headers.p[k] == ' ' || req_headers.p[k] == ','))
                k++;
            size_t st = k;
            while (k < req_headers.n && req_headers.p[k] != ',') k++;
            size_t e = k;
            while (e > st && req_headers.p[e-1] == ' ') e--;
            if (e > st && !header_allowed(r, (s3_str_t){ req_headers.p + st, e - st }))
                ok = 0;
        }
        if (ok) return r;
    }
    return NULL;
}
