/* src/json.c — strict recursive-descent JSON reader + escaped writer. */

#include "json.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *p, *end;
    int depth, max_depth;
    int nodes, max_nodes;
} jp_t;

static void ws(jp_t *j) {
    while (j->p < j->end && (*j->p == ' ' || *j->p == '\t'
                             || *j->p == '\n' || *j->p == '\r')) j->p++;
}

void json_free(json_t *v) {
    while (v) {
        json_t *n = v->next;
        json_free(v->child);
        free(v->key);
        free(v->str);
        free(v);
        v = n;
    }
}

static json_t *node(jp_t *j, json_type_t t) {
    if (++j->nodes > j->max_nodes) return NULL;
    json_t *v = calloc(1, sizeof(*v));
    if (v) v->type = t;
    return v;
}

static int hex4(const char *p, unsigned *out) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = p[i];
        v <<= 4;
        if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
        else return -1;
    }
    *out = v;
    return 0;
}

static size_t put_utf8(char *o, unsigned cp) {
    if (cp < 0x80) { o[0] = (char)cp; return 1; }
    if (cp < 0x800) { o[0] = (char)(0xC0 | (cp >> 6)); o[1] = (char)(0x80 | (cp & 63)); return 2; }
    if (cp < 0x10000) {
        o[0] = (char)(0xE0 | (cp >> 12)); o[1] = (char)(0x80 | ((cp >> 6) & 63));
        o[2] = (char)(0x80 | (cp & 63)); return 3;
    }
    o[0] = (char)(0xF0 | (cp >> 18)); o[1] = (char)(0x80 | ((cp >> 12) & 63));
    o[2] = (char)(0x80 | ((cp >> 6) & 63)); o[3] = (char)(0x80 | (cp & 63));
    return 4;
}

/* Validate one UTF-8 sequence at p; returns its length or 0. */
static size_t utf8_len(const unsigned char *p, const unsigned char *end) {
    unsigned c = p[0];
    size_t n;
    unsigned min;
    if (c < 0x80) return 1;
    if ((c & 0xE0) == 0xC0) { n = 2; min = 0x80; c &= 0x1F; }
    else if ((c & 0xF0) == 0xE0) { n = 3; min = 0x800; c &= 0x0F; }
    else if ((c & 0xF8) == 0xF0) { n = 4; min = 0x10000; c &= 0x07; }
    else return 0;
    if ((size_t)(end - p) < n) return 0;
    for (size_t i = 1; i < n; i++) {
        if ((p[i] & 0xC0) != 0x80) return 0;
        c = (c << 6) | (p[i] & 0x3F);
    }
    if (c < min || c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF)) return 0;
    return n;
}

static char *parse_string(jp_t *j, size_t *len_out) {
    if (j->p >= j->end || *j->p != '"') return NULL;
    j->p++;
    /* Decoded length never exceeds the encoded length. */
    const char *s = j->p;
    while (s < j->end && *s != '"') { if (*s == '\\') s++; s++; }
    if (s >= j->end) return NULL;
    char *out = malloc((size_t)(s - j->p) + 1);
    if (!out) return NULL;
    size_t o = 0;
    while (j->p < j->end && *j->p != '"') {
        unsigned char c = (unsigned char)*j->p;
        if (c < 0x20) goto bad;
        if (c == '\\') {
            if (++j->p >= j->end) goto bad;
            char e = *j->p++;
            switch (e) {
            case '"': out[o++] = '"'; break;
            case '\\': out[o++] = '\\'; break;
            case '/': out[o++] = '/'; break;
            case 'b': out[o++] = '\b'; break;
            case 'f': out[o++] = '\f'; break;
            case 'n': out[o++] = '\n'; break;
            case 'r': out[o++] = '\r'; break;
            case 't': out[o++] = '\t'; break;
            case 'u': {
                unsigned cp;
                if (j->end - j->p < 4 || hex4(j->p, &cp) < 0) goto bad;
                j->p += 4;
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    unsigned lo;
                    if (j->end - j->p < 6 || j->p[0] != '\\' || j->p[1] != 'u'
                        || hex4(j->p + 2, &lo) < 0 || lo < 0xDC00 || lo > 0xDFFF)
                        goto bad;
                    j->p += 6;
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    goto bad;
                }
                if (cp == 0) goto bad;          /* no embedded NULs */
                o += put_utf8(out + o, cp);
                break;
            }
            default: goto bad;
            }
        } else {
            size_t n = utf8_len((const unsigned char *)j->p, (const unsigned char *)j->end);
            if (!n) goto bad;
            memcpy(out + o, j->p, n);
            o += n;
            j->p += n;
        }
    }
    if (j->p >= j->end) goto bad;
    j->p++;                                     /* closing quote */
    out[o] = '\0';
    *len_out = o;
    return out;
bad:
    free(out);
    return NULL;
}

static json_t *parse_value(jp_t *j);

static json_t *parse_container(jp_t *j, int obj) {
    if (++j->depth > j->max_depth) return NULL;
    json_t *v = node(j, obj ? JSON_OBJ : JSON_ARR);
    if (!v) return NULL;
    j->p++;
    ws(j);
    json_t **tail = &v->child;
    if (j->p < j->end && *j->p == (obj ? '}' : ']')) { j->p++; j->depth--; return v; }
    for (;;) {
        char *key = NULL;
        if (obj) {
            size_t kn;
            ws(j);
            key = parse_string(j, &kn);
            if (!key) goto bad;
            for (json_t *m = v->child; m; m = m->next)
                if (strcmp(m->key, key) == 0) { free(key); goto bad; }  /* duplicate */
            ws(j);
            if (j->p >= j->end || *j->p != ':') { free(key); goto bad; }
            j->p++;
        }
        json_t *c = parse_value(j);
        if (!c) { free(key); goto bad; }
        c->key = key;
        *tail = c;
        tail = &c->next;
        v->n_children++;
        ws(j);
        if (j->p >= j->end) goto bad;
        if (*j->p == ',') { j->p++; ws(j); continue; }
        if (*j->p == (obj ? '}' : ']')) { j->p++; break; }
        goto bad;
    }
    j->depth--;
    return v;
bad:
    json_free(v);
    return NULL;
}

static json_t *parse_value(jp_t *j) {
    ws(j);
    if (j->p >= j->end) return NULL;
    char c = *j->p;
    if (c == '{') return parse_container(j, 1);
    if (c == '[') return parse_container(j, 0);
    if (c == '"') {
        json_t *v = node(j, JSON_STR);
        if (!v) return NULL;
        if (!(v->str = parse_string(j, &v->str_n))) { free(v); return NULL; }
        return v;
    }
    static const struct { const char *w; json_type_t t; int b; } LIT[] = {
        { "true", JSON_BOOL, 1 }, { "false", JSON_BOOL, 0 }, { "null", JSON_NULL, 0 },
    };
    for (size_t i = 0; i < 3; i++) {
        size_t n = strlen(LIT[i].w);
        if ((size_t)(j->end - j->p) >= n && memcmp(j->p, LIT[i].w, n) == 0) {
            json_t *v = node(j, LIT[i].t);
            if (!v) return NULL;
            v->b = LIT[i].b;
            j->p += n;
            return v;
        }
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        const char *s = j->p;
        if (*j->p == '-') j->p++;
        if (j->p >= j->end) return NULL;
        if (*j->p == '0') j->p++;
        else if (*j->p >= '1' && *j->p <= '9') while (j->p < j->end && *j->p >= '0' && *j->p <= '9') j->p++;
        else return NULL;
        if (j->p < j->end && *j->p == '.') {
            j->p++;
            if (j->p >= j->end || *j->p < '0' || *j->p > '9') return NULL;
            while (j->p < j->end && *j->p >= '0' && *j->p <= '9') j->p++;
        }
        if (j->p < j->end && (*j->p == 'e' || *j->p == 'E')) {
            j->p++;
            if (j->p < j->end && (*j->p == '+' || *j->p == '-')) j->p++;
            if (j->p >= j->end || *j->p < '0' || *j->p > '9') return NULL;
            while (j->p < j->end && *j->p >= '0' && *j->p <= '9') j->p++;
        }
        size_t n = (size_t)(j->p - s);
        if (n > 64) return NULL;
        json_t *v = node(j, JSON_NUM);
        if (!v || !(v->str = malloc(n + 1))) { free(v); return NULL; }
        memcpy(v->str, s, n);
        v->str[n] = '\0';
        v->str_n = n;
        return v;
    }
    return NULL;
}

json_t *json_parse(const char *s, size_t n, int max_depth, int max_nodes) {
    jp_t j = { s, s + n, 0, max_depth > 0 ? max_depth : 8, 0,
               max_nodes > 0 ? max_nodes : 4096 };
    json_t *v = parse_value(&j);
    if (!v) return NULL;
    ws(&j);
    if (j.p != j.end) { json_free(v); return NULL; }
    return v;
}

const json_t *json_get(const json_t *obj, const char *key) {
    if (!obj || obj->type != JSON_OBJ) return NULL;
    for (const json_t *m = obj->child; m; m = m->next)
        if (strcmp(m->key, key) == 0) return m;
    return NULL;
}

const char *json_str(const json_t *j) {
    return j && j->type == JSON_STR ? j->str : NULL;
}

int json_put_str(char *out, size_t cap, size_t *o, const char *s) {
    static const char H[] = "0123456789abcdef";
#define PUT(ch) do { if (*o + 1 >= cap) goto full; out[(*o)++] = (ch); } while (0)
    PUT('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        if (c == '"' || c == '\\') { PUT('\\'); PUT((char)c); }
        else if (c < 0x20) {
            PUT('\\'); PUT('u'); PUT('0'); PUT('0'); PUT(H[c >> 4]); PUT(H[c & 15]);
        } else if (c == '<' || c == '>' || c == '&') {
            /* Safe to embed in HTML too. */
            PUT('\\'); PUT('u'); PUT('0'); PUT('0'); PUT(H[c >> 4]); PUT(H[c & 15]);
        } else PUT((char)c);
    }
    PUT('"');
    out[*o] = '\0';
    return 0;
full:
    if (cap) out[*o < cap ? *o : cap - 1] = '\0';
    return -1;
#undef PUT
}
