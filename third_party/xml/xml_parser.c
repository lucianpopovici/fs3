/* xml_parser.c — DOM building, serialization, and parsing.
 *
 * Layout:
 *   1. Internal helpers (string growth, UTF-8 emit)
 *   2. DOM builders (create_node, add_child, add_attr, find_node, free_tree)
 *      - capacity-doubling growth, OOM-safe
 *   3. Helpers (xml_set_content*, find_child, get_attr)
 *   4. Serialization
 *      - escaping is the central correctness fix
 *      - serialize_node(FILE*) wraps the callback variant
 *   5. Parser
 *      - recursive descent, bounded depth, no DTD/external entity processing
 */

#include "xml_parser.h"

#include <assert.h>
#include <stdarg.h>
#include <stdint.h>

/* ===================================================================== */
/* 1. Internal helpers                                                   */
/* ===================================================================== */

/* Grow a pointer array in capacity-doubling fashion. *cap is updated.
 * Returns 0 on success, -1 on OOM (in which case *arr and *cap are
 * unchanged). */
static int grow_array(void ***arr, int *cap, int min_cap) {
    if (*cap >= min_cap) return 0;
    int new_cap = (*cap > 0) ? *cap * 2 : 4;
    while (new_cap < min_cap) new_cap *= 2;
    void **n = realloc(*arr, sizeof(void *) * (size_t)new_cap);
    if (!n) return -1;
    *arr = n;
    *cap = new_cap;
    return 0;
}

/* Duplicate `n` bytes plus a NUL terminator. */
static char *strndup_safe(const char *p, size_t n) {
    char *d = malloc(n + 1);
    if (!d) return NULL;
    if (n) memcpy(d, p, n);
    d[n] = '\0';
    return d;
}

/* Encode a Unicode code point as UTF-8 into out (which must have at least
 * 4 bytes of room). Returns the number of bytes written, or 0 if cp is
 * not a valid scalar value. */
static int utf8_encode(uint32_t cp, char *out) {
    if (cp <= 0x7F) {
        out[0] = (char)cp;
        return 1;
    }
    if (cp <= 0x7FF) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    /* Surrogate pair range is invalid as a scalar value */
    if (cp >= 0xD800 && cp <= 0xDFFF) return 0;
    if (cp <= 0xFFFF) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    if (cp <= 0x10FFFF) {
        out[0] = (char)(0xF0 | (cp >> 18));
        out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[3] = (char)(0x80 | (cp & 0x3F));
        return 4;
    }
    return 0;
}

/* ===================================================================== */
/* 2. DOM builders                                                       */
/* ===================================================================== */

XMLNode *create_node(const char *name) {
    if (!name) return NULL;
    XMLNode *node = calloc(1, sizeof(XMLNode));
    if (!node) return NULL;
    node->local_name = strdup(name);
    if (!node->local_name) { free(node); return NULL; }
    return node;
}

int add_child(XMLNode *parent, XMLNode *child) {
    if (!parent || !child) return -1;
    if (grow_array((void ***)&parent->children, &parent->child_cap,
                   parent->child_count + 1) < 0) {
        return -1;
    }
    parent->children[parent->child_count++] = child;
    child->parent = parent;
    return 0;
}

int add_attr(XMLNode *node, const char *key, const char *val) {
    if (!node || !key || !val) return -1;

    /* We grow attr_keys and attr_values together; they always share count. */
    if (grow_array((void ***)&node->attr_keys, &node->attr_cap,
                   node->attr_count + 1) < 0) {
        return -1;
    }
    /* attr_values may have been NULL or a smaller capacity than the array
     * we just grew. Sync it. */
    if (node->attr_count + 1 > node->attr_cap) {
        /* Cannot happen given we just grew above, but defend. */
        return -1;
    }
    /* Ensure attr_values is sized to match attr_cap. */
    char **nv = realloc(node->attr_values, sizeof(char *) * (size_t)node->attr_cap);
    if (!nv) return -1;
    node->attr_values = nv;

    char *kdup = strdup(key);
    char *vdup = strdup(val);
    if (!kdup || !vdup) { free(kdup); free(vdup); return -1; }

    node->attr_keys[node->attr_count]   = kdup;
    node->attr_values[node->attr_count] = vdup;
    node->attr_count++;
    return 0;
}

XMLNode *find_node(XMLNode *root, const char *name) {
    if (!root || !name) return NULL;
    if (root->local_name && strcmp(root->local_name, name) == 0) return root;
    for (int i = 0; i < root->child_count; i++) {
        XMLNode *found = find_node(root->children[i], name);
        if (found) return found;
    }
    return NULL;
}

void free_tree(XMLNode *node) {
    if (!node) return;
    free(node->local_name);
    free(node->content);
    for (int i = 0; i < node->attr_count; i++) {
        free(node->attr_keys[i]);
        free(node->attr_values[i]);
    }
    free(node->attr_keys);
    free(node->attr_values);
    for (int i = 0; i < node->child_count; i++) {
        free_tree(node->children[i]);
    }
    free(node->children);
    free(node);
}

/* ===================================================================== */
/* 3. Helpers                                                            */
/* ===================================================================== */

int xml_set_content(XMLNode *node, const char *content) {
    return xml_set_content_n(node, content, content ? strlen(content) : 0);
}

int xml_set_content_n(XMLNode *node, const char *content, size_t n) {
    if (!node) return -1;
    if (!content) {
        free(node->content);
        node->content = NULL;
        return 0;
    }
    char *d = strndup_safe(content, n);
    if (!d) return -1;
    free(node->content);
    node->content = d;
    return 0;
}

XMLNode *find_child(XMLNode *parent, const char *name) {
    if (!parent || !name) return NULL;
    for (int i = 0; i < parent->child_count; i++) {
        XMLNode *c = parent->children[i];
        if (c && c->local_name && strcmp(c->local_name, name) == 0) return c;
    }
    return NULL;
}

const char *get_attr(const XMLNode *node, const char *key) {
    if (!node || !key) return NULL;
    for (int i = 0; i < node->attr_count; i++) {
        if (strcmp(node->attr_keys[i], key) == 0) return node->attr_values[i];
    }
    return NULL;
}

/* ===================================================================== */
/* 4. Serialization                                                      */
/* ===================================================================== */

/* Write a single span via the callback. Returns 0 ok, or non-zero from cb. */
static int w(xml_write_fn cb, void *ctx, const char *p, size_t n) {
    return n ? cb(ctx, p, n) : 0;
}

/* Write an indent of `n` spaces. */
static int w_indent(xml_write_fn cb, void *ctx, int n) {
    static const char spaces[64] =
        "                                                                ";
    while (n > 0) {
        int chunk = n > 64 ? 64 : n;
        int rc = w(cb, ctx, spaces, (size_t)chunk);
        if (rc) return rc;
        n -= chunk;
    }
    return 0;
}

/* Escape `s` of length `n` and write it via cb. The escape set depends on
 * `in_attr`:
 *   - element content: '&' '<' '>' (the latter is technically only required
 *     when it follows "]]", but escaping it always is safe and what every
 *     other XML library does)
 *   - attribute value: also escape '"' and the various whitespace forms
 *     that the XML spec says must be normalised on parse (TAB, LF, CR).
 *
 * Bytes that aren't special characters are batched into runs and emitted
 * as a single callback invocation, which keeps the per-byte cost low. */
static int w_escaped(xml_write_fn cb, void *ctx,
                     const char *s, size_t n, int in_attr) {
    size_t run_start = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)s[i];
        const char *rep = NULL;
        size_t rep_len = 0;

        switch (ch) {
            case '&':  rep = "&amp;";  rep_len = 5; break;
            case '<':  rep = "&lt;";   rep_len = 4; break;
            case '>':  rep = "&gt;";   rep_len = 4; break;
            case '"':  if (in_attr) { rep = "&quot;"; rep_len = 6; } break;
            case '\t': if (in_attr) { rep = "&#9;";   rep_len = 4; } break;
            case '\n': if (in_attr) { rep = "&#10;";  rep_len = 5; } break;
            case '\r': /* Always escape — XML normalises it on parse. */
                       rep = "&#13;"; rep_len = 5; break;
            default: break;
        }

        if (!rep) continue;

        /* Flush the run of unescaped bytes before writing the entity. */
        if (i > run_start) {
            int rc = w(cb, ctx, s + run_start, i - run_start);
            if (rc) return rc;
        }
        int rc = w(cb, ctx, rep, rep_len);
        if (rc) return rc;
        run_start = i + 1;
    }
    if (run_start < n) {
        int rc = w(cb, ctx, s + run_start, n - run_start);
        if (rc) return rc;
    }
    return 0;
}

/* Recursively serialize one node. Returns 0 ok, or the cb's error. */
static int serialize_one(const XMLNode *node, xml_write_fn cb, void *ctx,
                         int indent) {
    int rc;
    if (!node || !node->local_name) return 0;

    if ((rc = w_indent(cb, ctx, indent))) return rc;
    if ((rc = w(cb, ctx, "<", 1))) return rc;
    if ((rc = w(cb, ctx, node->local_name, strlen(node->local_name)))) return rc;

    for (int i = 0; i < node->attr_count; i++) {
        if ((rc = w(cb, ctx, " ", 1))) return rc;
        if ((rc = w(cb, ctx, node->attr_keys[i],
                    strlen(node->attr_keys[i])))) return rc;
        if ((rc = w(cb, ctx, "=\"", 2))) return rc;
        if ((rc = w_escaped(cb, ctx, node->attr_values[i],
                            strlen(node->attr_values[i]), 1))) return rc;
        if ((rc = w(cb, ctx, "\"", 1))) return rc;
    }

    int has_content = node->content && node->content[0] != '\0';
    int has_children = node->child_count > 0;

    if (!has_content && !has_children) {
        return w(cb, ctx, "/>\n", 3);
    }

    if ((rc = w(cb, ctx, ">", 1))) return rc;

    if (has_content) {
        if ((rc = w_escaped(cb, ctx, node->content,
                            strlen(node->content), 0))) return rc;
    }

    if (has_children) {
        if ((rc = w(cb, ctx, "\n", 1))) return rc;
        for (int i = 0; i < node->child_count; i++) {
            if ((rc = serialize_one(node->children[i], cb, ctx,
                                    indent + 2))) return rc;
        }
        if ((rc = w_indent(cb, ctx, indent))) return rc;
    }

    if ((rc = w(cb, ctx, "</", 2))) return rc;
    if ((rc = w(cb, ctx, node->local_name, strlen(node->local_name)))) return rc;
    return w(cb, ctx, ">\n", 2);
}

int xml_serialize(const XMLNode *root, xml_write_fn write_fn, void *ctx,
                  int indent) {
    if (!root || !write_fn) return -1;
    return serialize_one(root, write_fn, ctx, indent);
}

/* ---- Buffer-backed callback for xml_serialize_to_buf -------------- */

typedef struct {
    char  *buf;
    size_t cap;
    size_t used;
    int    overflowed;
} buf_ctx_t;

static int buf_write(void *vctx, const char *data, size_t len) {
    buf_ctx_t *b = vctx;
    if (b->overflowed) return -1;
    if (b->used + len > b->cap) {
        b->overflowed = 1;
        return -1;
    }
    memcpy(b->buf + b->used, data, len);
    b->used += len;
    return 0;
}

int xml_serialize_to_buf(const XMLNode *root, char *buf, size_t cap,
                         size_t *out_len) {
    if (!root || !buf) return -1;
    buf_ctx_t b = { buf, cap, 0, 0 };
    int rc = xml_serialize(root, buf_write, &b, 0);
    if (rc != 0 || b.overflowed) return -1;
    if (out_len) *out_len = b.used;
    return 0;
}

/* ---- FILE* wrapper for the original serialize_node API ------------ */

static int file_write(void *ctx, const char *data, size_t len) {
    FILE *f = ctx;
    return (fwrite(data, 1, len, f) == len) ? 0 : -1;
}

void serialize_node(FILE *out, XMLNode *node, int indent) {
    if (!out || !node) return;
    (void)xml_serialize(node, file_write, out, indent);
}

/* ===================================================================== */
/* 5. Parser                                                             */
/* ===================================================================== */

#define DEFAULT_MAX_DEPTH 64
#define DEFAULT_MAX_NODES 65536

typedef struct {
    const char *src;        /* original buffer start */
    const char *p;          /* current position */
    const char *end;
    int         depth;
    int         max_depth;
    int         nodes;
    int         max_nodes;
    int         allow_doctype;
    const char *err;        /* first error encountered (static string) */
    const char *err_pos;    /* position when err was set */
} pstate_t;

#define PERR(s, msg) do {                       \
    if (!(s)->err) {                            \
        (s)->err = (msg);                       \
        (s)->err_pos = (s)->p;                  \
    }                                           \
} while (0)

/* ---- Low-level cursor primitives ---------------------------------- */

static int s_eof(const pstate_t *s) { return s->p >= s->end; }

static int s_peek(const pstate_t *s, size_t off) {
    return (s->p + off < s->end) ? (unsigned char)s->p[off] : -1;
}

static int s_starts_with(const pstate_t *s, const char *lit) {
    size_t n = strlen(lit);
    if ((size_t)(s->end - s->p) < n) return 0;
    return memcmp(s->p, lit, n) == 0;
}

static void s_skip_ws(pstate_t *s) {
    while (s->p < s->end) {
        char c = *s->p;
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') s->p++;
        else break;
    }
}

/* ---- Name validation --------------------------------------------- */

static int is_name_start(int c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
        || c == '_' || c == ':'
        /* Permissive UTF-8: any byte >= 0x80 may begin a multibyte char.
         * We trust the rest of the parser to stop at ASCII delimiters,
         * which UTF-8 encoding guarantees won't appear mid-character. */
        || (c >= 0x80);
}

static int is_name_char(int c) {
    return is_name_start(c) || (c >= '0' && c <= '9')
        || c == '-' || c == '.';
}

/* Parse an XML Name. Returns 1 on success with *name_start and *name_len
 * set, 0 on no-name, -1 on bad name (sets err). */
static int parse_name(pstate_t *s, const char **name_start, size_t *name_len) {
    if (s_eof(s)) return 0;
    if (!is_name_start((unsigned char)*s->p)) return 0;
    const char *start = s->p;
    s->p++;
    while (!s_eof(s) && is_name_char((unsigned char)*s->p)) s->p++;
    *name_start = start;
    *name_len = (size_t)(s->p - start);
    return 1;
}

/* ---- Entity / CDATA decoding ------------------------------------- */

/* Decode a single &entity; reference at s->p (which must point at '&').
 * Writes 1..4 bytes into out and returns the byte count. Returns -1 on
 * malformed reference. Advances s->p past the trailing ';'. */
static int decode_entity_ref(pstate_t *s, char out[4]) {
    if (*s->p != '&') return -1;
    const char *q = s->p + 1;
    /* Numeric */
    if (q < s->end && *q == '#') {
        q++;
        uint32_t cp = 0;
        int hex = 0;
        if (q < s->end && (*q == 'x' || *q == 'X')) { hex = 1; q++; }
        const char *digits_start = q;
        while (q < s->end && *q != ';') {
            int d;
            if (hex) {
                if (*q >= '0' && *q <= '9') d = *q - '0';
                else if (*q >= 'a' && *q <= 'f') d = 10 + *q - 'a';
                else if (*q >= 'A' && *q <= 'F') d = 10 + *q - 'A';
                else return -1;
                cp = cp * 16 + (uint32_t)d;
            } else {
                if (*q < '0' || *q > '9') return -1;
                cp = cp * 10 + (uint32_t)(*q - '0');
            }
            if (cp > 0x10FFFF) return -1;  /* overflow / out of range */
            q++;
        }
        if (q == digits_start || q >= s->end || *q != ';') return -1;
        int n = utf8_encode(cp, out);
        if (n == 0) return -1;
        s->p = q + 1;
        return n;
    }
    /* Named: lt, gt, amp, apos, quot. We do NOT resolve user-defined
     * entities; that's an explicit security choice. */
    static const struct { const char *name; size_t nlen; char out; } names[] = {
        { "lt",   2, '<' },
        { "gt",   2, '>' },
        { "amp",  3, '&' },
        { "apos", 4, '\'' },
        { "quot", 4, '"' },
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        if ((size_t)(s->end - q) >= names[i].nlen + 1
            && memcmp(q, names[i].name, names[i].nlen) == 0
            && q[names[i].nlen] == ';') {
            out[0] = names[i].out;
            s->p = q + names[i].nlen + 1;
            return 1;
        }
    }
    return -1;
}

/* Append `n` bytes to a growing malloc'd buffer. Returns 0 ok, -1 OOM. */
static int strbuf_append(char **buf, size_t *len, size_t *cap,
                         const char *src, size_t n) {
    if (*len + n + 1 > *cap) {
        size_t nc = *cap ? *cap * 2 : 64;
        while (nc < *len + n + 1) nc *= 2;
        char *nb = realloc(*buf, nc);
        if (!nb) return -1;
        *buf = nb;
        *cap = nc;
    }
    memcpy(*buf + *len, src, n);
    *len += n;
    (*buf)[*len] = '\0';
    return 0;
}

/* ---- Skip helpers for prolog/whitespace structures ---------------- */

/* Consume "<?...?>" (XML decl or PI). Caller has verified "<?". */
static int skip_pi(pstate_t *s) {
    s->p += 2;
    while (s->p + 1 < s->end) {
        if (s->p[0] == '?' && s->p[1] == '>') { s->p += 2; return 0; }
        s->p++;
    }
    PERR(s, "unterminated processing instruction");
    return -1;
}

/* Consume "<!--...-->". Caller has verified "<!--". */
static int skip_comment(pstate_t *s) {
    s->p += 4;
    while (s->p + 2 < s->end) {
        if (s->p[0] == '-' && s->p[1] == '-' && s->p[2] == '>') {
            s->p += 3;
            return 0;
        }
        s->p++;
    }
    PERR(s, "unterminated comment");
    return -1;
}

/* Consume "<!DOCTYPE ...>". Caller has verified "<!DOCTYPE".
 * Tracks bracket depth for internal subsets like <!DOCTYPE x [ ... ]> */
static int skip_doctype(pstate_t *s) {
    if (!s->allow_doctype) {
        PERR(s, "DOCTYPE not allowed");
        return -1;
    }
    int bracket = 0;
    while (!s_eof(s)) {
        char c = *s->p++;
        if (c == '[') bracket++;
        else if (c == ']') { if (bracket > 0) bracket--; }
        else if (c == '>' && bracket == 0) return 0;
    }
    PERR(s, "unterminated DOCTYPE");
    return -1;
}

/* Skip everything in the prolog before the root element. */
static int skip_prolog(pstate_t *s) {
    /* Optional UTF-8 BOM */
    if ((size_t)(s->end - s->p) >= 3
        && (unsigned char)s->p[0] == 0xEF
        && (unsigned char)s->p[1] == 0xBB
        && (unsigned char)s->p[2] == 0xBF) {
        s->p += 3;
    }

    for (;;) {
        s_skip_ws(s);
        if (s_eof(s)) return 0;
        if (s_starts_with(s, "<?")) {
            if (skip_pi(s) < 0) return -1;
            continue;
        }
        if (s_starts_with(s, "<!--")) {
            if (skip_comment(s) < 0) return -1;
            continue;
        }
        if (s_starts_with(s, "<!DOCTYPE")) {
            if (skip_doctype(s) < 0) return -1;
            continue;
        }
        return 0;
    }
}

/* ---- Attribute value & content parsing --------------------------- */

/* Parse `"..."` or `'...'`. Returns malloc'd NUL-terminated value, or
 * NULL on error (sets err). */
static char *parse_attr_value(pstate_t *s) {
    if (s_eof(s) || (*s->p != '"' && *s->p != '\'')) {
        PERR(s, "expected attribute value");
        return NULL;
    }
    char quote = *s->p++;

    char  *buf = NULL;
    size_t len = 0, cap = 0;

    while (!s_eof(s)) {
        char c = *s->p;
        if (c == quote) { s->p++; if (!buf) return strdup(""); return buf; }
        if (c == '<') { PERR(s, "'<' in attribute value"); break; }
        if (c == '&') {
            char ent[4];
            int n = decode_entity_ref(s, ent);
            if (n < 0) { PERR(s, "invalid entity reference"); break; }
            if (strbuf_append(&buf, &len, &cap, ent, (size_t)n) < 0) {
                PERR(s, "OOM"); break;
            }
            continue;
        }
        /* XML normalises CR, CR+LF, and TAB to a space in attribute values.
         * We do the simple case (CR or LF or TAB → 0x20) and handle CRLF
         * by skipping the LF that follows a CR. */
        if (c == '\r') {
            if (strbuf_append(&buf, &len, &cap, " ", 1) < 0) {
                PERR(s, "OOM"); break;
            }
            s->p++;
            if (!s_eof(s) && *s->p == '\n') s->p++;
            continue;
        }
        if (c == '\n' || c == '\t') {
            if (strbuf_append(&buf, &len, &cap, " ", 1) < 0) {
                PERR(s, "OOM"); break;
            }
            s->p++;
            continue;
        }
        if (strbuf_append(&buf, &len, &cap, s->p, 1) < 0) {
            PERR(s, "OOM"); break;
        }
        s->p++;
    }
    if (!s->err) PERR(s, "unterminated attribute value");
    free(buf);
    return NULL;
}

/* ---- Element parser ---------------------------------------------- */

static XMLNode *parse_element(pstate_t *s);

/* Parse content between `<elem>` and `</elem>`: a mix of text,
 * &entity refs, CDATA sections, comments, and child elements. Appends
 * accumulated text into `node->content` and child elements into the
 * node's child list. */
static int parse_content(pstate_t *s, XMLNode *node) {
    char  *text = NULL;
    size_t tlen = 0, tcap = 0;

    while (!s_eof(s)) {
        if (*s->p == '<') {
            /* Could be: closing tag, child element, comment, or CDATA. */
            if (s_starts_with(s, "</")) break;            /* close — parent handles */
            if (s_starts_with(s, "<!--")) {
                if (skip_comment(s) < 0) goto fail;
                continue;
            }
            if (s_starts_with(s, "<![CDATA[")) {
                s->p += 9;
                const char *cdata_start = s->p;
                while (s->p + 2 < s->end
                       && !(s->p[0] == ']' && s->p[1] == ']' && s->p[2] == '>')) {
                    s->p++;
                }
                if (s->p + 2 >= s->end) {
                    PERR(s, "unterminated CDATA"); goto fail;
                }
                size_t n = (size_t)(s->p - cdata_start);
                if (strbuf_append(&text, &tlen, &tcap, cdata_start, n) < 0) {
                    PERR(s, "OOM"); goto fail;
                }
                s->p += 3;
                continue;
            }
            if (s_starts_with(s, "<?")) {
                if (skip_pi(s) < 0) goto fail;
                continue;
            }
            /* Child element */
            XMLNode *child = parse_element(s);
            if (!child) goto fail;
            if (add_child(node, child) < 0) {
                free_tree(child);
                PERR(s, "OOM");
                goto fail;
            }
            continue;
        }
        if (*s->p == '&') {
            char ent[4];
            int n = decode_entity_ref(s, ent);
            if (n < 0) { PERR(s, "invalid entity reference"); goto fail; }
            if (strbuf_append(&text, &tlen, &tcap, ent, (size_t)n) < 0) {
                PERR(s, "OOM"); goto fail;
            }
            continue;
        }
        /* Plain character data (UTF-8 passes through). */
        if (strbuf_append(&text, &tlen, &tcap, s->p, 1) < 0) {
            PERR(s, "OOM"); goto fail;
        }
        s->p++;
    }

    if (text) {
        /* Only assign content if non-whitespace, OR if the element has no
         * children (for leaf text elements like <Size>123</Size> we always
         * keep the text; for container elements with whitespace between
         * children, we drop the whitespace). */
        int all_ws = 1;
        for (size_t i = 0; i < tlen; i++) {
            char c = text[i];
            if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
                all_ws = 0;
                break;
            }
        }
        if (all_ws && node->child_count > 0) {
            free(text);
        } else {
            free(node->content);
            node->content = text;
        }
    }
    return 0;

fail:
    free(text);
    return -1;
}

static XMLNode *parse_element(pstate_t *s) {
    if (s->depth >= s->max_depth) { PERR(s, "max nesting depth exceeded"); return NULL; }
    if (s->nodes >= s->max_nodes) { PERR(s, "max node count exceeded"); return NULL; }

    if (s_eof(s) || *s->p != '<') {
        PERR(s, "expected '<'");
        return NULL;
    }
    s->p++; /* consume '<' */

    const char *name_p; size_t name_n;
    if (parse_name(s, &name_p, &name_n) != 1 || name_n == 0) {
        PERR(s, "expected element name");
        return NULL;
    }
    /* Strip namespace prefix: <ns:Foo> → local_name "Foo". */
    const char *colon = memchr(name_p, ':', name_n);
    const char *local_p = colon ? colon + 1 : name_p;
    size_t      local_n = colon ? name_n - (size_t)(colon - name_p) - 1 : name_n;
    if (local_n == 0) { PERR(s, "empty local name after prefix"); return NULL; }

    /* Allocate node. */
    char *name_dup = strndup_safe(local_p, local_n);
    if (!name_dup) { PERR(s, "OOM"); return NULL; }
    XMLNode *node = calloc(1, sizeof(XMLNode));
    if (!node) { free(name_dup); PERR(s, "OOM"); return NULL; }
    node->local_name = name_dup;
    s->nodes++;

    /* Attributes */
    for (;;) {
        s_skip_ws(s);
        if (s_eof(s)) { PERR(s, "unterminated start tag"); free_tree(node); return NULL; }

        char c = *s->p;
        if (c == '>') { s->p++; break; }
        if (c == '/') {
            if (s_peek(s, 1) != '>') { PERR(s, "expected '/>'"); free_tree(node); return NULL; }
            s->p += 2;
            return node;  /* self-closing element */
        }

        const char *an_p; size_t an_n;
        if (parse_name(s, &an_p, &an_n) != 1) {
            PERR(s, "expected attribute name or '>'");
            free_tree(node);
            return NULL;
        }
        s_skip_ws(s);
        if (s_eof(s) || *s->p != '=') {
            PERR(s, "expected '=' in attribute");
            free_tree(node);
            return NULL;
        }
        s->p++;
        s_skip_ws(s);

        char *val = parse_attr_value(s);
        if (!val) { free_tree(node); return NULL; }

        /* Use temp NUL-terminated key. */
        char *kdup = strndup_safe(an_p, an_n);
        if (!kdup) { free(val); free_tree(node); PERR(s, "OOM"); return NULL; }
        if (add_attr(node, kdup, val) < 0) {
            free(kdup); free(val); free_tree(node); PERR(s, "OOM"); return NULL;
        }
        free(kdup);
        free(val);
    }

    /* Content. */
    s->depth++;
    int rc = parse_content(s, node);
    s->depth--;
    if (rc < 0) { free_tree(node); return NULL; }

    /* End tag: "</name>" with optional namespace prefix matching open. */
    if (!s_starts_with(s, "</")) {
        PERR(s, "expected end tag");
        free_tree(node);
        return NULL;
    }
    s->p += 2;
    const char *en_p; size_t en_n;
    if (parse_name(s, &en_p, &en_n) != 1) {
        PERR(s, "expected end tag name");
        free_tree(node);
        return NULL;
    }
    /* Compare end name's local part with open name's local part. */
    const char *ecolon = memchr(en_p, ':', en_n);
    const char *el_p = ecolon ? ecolon + 1 : en_p;
    size_t      el_n = ecolon ? en_n - (size_t)(ecolon - en_p) - 1 : en_n;
    if (el_n != local_n || memcmp(el_p, local_p, el_n) != 0) {
        PERR(s, "mismatched end tag");
        free_tree(node);
        return NULL;
    }
    s_skip_ws(s);
    if (s_eof(s) || *s->p != '>') {
        PERR(s, "expected '>' to close end tag");
        free_tree(node);
        return NULL;
    }
    s->p++;
    return node;
}

/* ---- Public parse entry point ------------------------------------ */

static void compute_line_col(const char *base, const char *pos,
                             int *line, int *col) {
    *line = 1;
    *col = 1;
    for (const char *q = base; q < pos; q++) {
        if (*q == '\n') { (*line)++; *col = 1; }
        else { (*col)++; }
    }
}

XMLNode *parse_xml(const char *data, size_t len,
                   const xml_parse_opts_t *opts,
                   xml_parse_err_t *err) {
    if (err) memset(err, 0, sizeof(*err));
    if (!data) {
        if (err) err->err_msg = "null input";
        return NULL;
    }
    pstate_t s = {
        .src = data, .p = data, .end = data + len,
        .depth = 0,
        .max_depth = (opts && opts->max_depth) ? opts->max_depth : DEFAULT_MAX_DEPTH,
        .nodes = 0,
        .max_nodes = (opts && opts->max_nodes) ? opts->max_nodes : DEFAULT_MAX_NODES,
        .allow_doctype = opts ? opts->allow_doctype : 0,
        .err = NULL,
        .err_pos = NULL,
    };

    if (skip_prolog(&s) < 0) goto fail;
    s_skip_ws(&s);
    if (s_eof(&s)) { PERR(&s, "no root element"); goto fail; }
    if (*s.p != '<') { PERR(&s, "expected '<' before root"); goto fail; }

    XMLNode *root = parse_element(&s);
    if (!root) goto fail;

    /* Trailing miscellany (comments / PIs / whitespace) is allowed. */
    for (;;) {
        s_skip_ws(&s);
        if (s_eof(&s)) break;
        if (s_starts_with(&s, "<!--")) {
            if (skip_comment(&s) < 0) { free_tree(root); goto fail; }
            continue;
        }
        if (s_starts_with(&s, "<?")) {
            if (skip_pi(&s) < 0) { free_tree(root); goto fail; }
            continue;
        }
        PERR(&s, "trailing content after root element");
        free_tree(root);
        goto fail;
    }
    return root;

fail:
    if (err) {
        err->err_msg = s.err ? s.err : "unknown parse error";
        err->err_offset = s.err_pos ? (size_t)(s.err_pos - s.src) : 0;
        compute_line_col(s.src, s.err_pos ? s.err_pos : s.p,
                         &err->err_line, &err->err_col);
    }
    return NULL;
}
