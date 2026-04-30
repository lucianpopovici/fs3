/* xml_parser.h
 *
 * Small DOM-style XML library.
 *
 * The original API (create_node, add_child, add_attr, find_node,
 * serialize_node, free_tree) is preserved unchanged in signature;
 * implementations are hardened and serialize_node now properly
 * escapes special characters in content and attribute values.
 *
 * New facilities:
 *   - parse_xml()      : parse an XML byte buffer into a DOM tree
 *   - xml_serialize()  : serialize via a caller-supplied write callback,
 *                        so output can go to a memory buffer, a socket,
 *                        or anything else.
 *   - xml_serialize_to_buf() : convenience wrapper for fixed buffers.
 *   - xml_set_content() / xml_set_content_n(): assign text content
 *                        (handles allocation and replaces any existing
 *                        content; preferred over direct field assignment).
 *   - find_child()     : find a direct child by local name (non-recursive,
 *                        unlike find_node which recurses).
 *   - get_attr()       : look up an attribute value by key.
 *
 * Memory model: each XMLNode owns its name, content, attribute strings,
 * and child pointers. free_tree() walks the tree and releases everything.
 * Callers may still write directly to node->content; if doing so, ensure
 * any previous value is freed first, or use xml_set_content() to do it
 * for you.
 *
 * Allocation failure: builders return -1 on out-of-memory; create_node
 * returns NULL. Callers that ignore these return values will see a node
 * with missing children/attrs but no crash. The parser propagates errors
 * via xml_parse_err_t.
 *
 * The parser is intentionally NOT a full XML 1.0 conformant implementation.
 * It accepts the subset that real-world REST APIs (S3, ATOM, etc.) emit:
 * elements, attributes, character data with entity references, comments,
 * the XML declaration, processing instructions, and CDATA sections.
 * It rejects DOCTYPE by default (refuses to process DTDs, which prevents
 * XXE attacks). It does not resolve external entities, ever.
 */
#ifndef XML_PARSER_H
#define XML_PARSER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct XMLNode {
    char  *local_name;     /* element name (namespace prefix stripped on parse) */
    char  *content;        /* concatenated character data, or NULL */
    char **attr_keys;
    char **attr_values;
    int    attr_count;
    int    attr_cap;       /* allocated capacity of attr_keys/attr_values */
    struct XMLNode **children;
    int    child_count;
    int    child_cap;      /* allocated capacity of children */
    struct XMLNode *parent;
} XMLNode;

/* ------------------------------------------------------------------ */
/* DOM building (existing API, hardened implementations)              */
/* ------------------------------------------------------------------ */

/* Allocate a node with the given name. Returns NULL on OOM. */
XMLNode* create_node(const char *name);

/* Append child to parent. Returns 0 on success, -1 on OOM.
 * Old void-returning signature: callers ignoring the result still build. */
int add_child(XMLNode *parent, XMLNode *child);

/* Append attribute to node. Returns 0 on success, -1 on OOM. */
int add_attr(XMLNode *node, const char *key, const char *val);

/* Recursively find first node with the given local_name (depth-first). */
XMLNode* find_node(XMLNode *root, const char *name);

/* Serialize to a FILE*. Properly escapes special characters in content
 * and attribute values. Indent is the starting column. */
void serialize_node(FILE *out, XMLNode *node, int indent);

/* Recursively free node and all descendants. */
void free_tree(XMLNode *node);

/* ------------------------------------------------------------------ */
/* New helpers                                                        */
/* ------------------------------------------------------------------ */

/* Set node->content from a NUL-terminated string, freeing any previous
 * value. Pass NULL to clear. Returns 0 on success, -1 on OOM. */
int xml_set_content(XMLNode *node, const char *content);

/* Same, but for a non-NUL-terminated byte range of length n.
 * The library copies the bytes and adds a NUL terminator. */
int xml_set_content_n(XMLNode *node, const char *content, size_t n);

/* Find the first DIRECT child of `parent` whose local_name equals `name`.
 * Returns NULL if not found. Unlike find_node(), does not recurse. */
XMLNode* find_child(XMLNode *parent, const char *name);

/* Return attribute value for the given key, or NULL if absent. */
const char* get_attr(const XMLNode *node, const char *key);

/* ------------------------------------------------------------------ */
/* Serialization with a write callback                                */
/* ------------------------------------------------------------------ */

/* User-supplied write function. Should return 0 on success, non-zero on
 * error (which aborts serialization and is returned by xml_serialize). */
typedef int (*xml_write_fn)(void *ctx, const char *data, size_t len);

/* Serialize tree via callback. Returns 0 on success, or the non-zero
 * value returned by the callback on write error. `indent` is the
 * starting column (typically 0). */
int xml_serialize(const XMLNode *root, xml_write_fn write_fn, void *ctx,
                  int indent);

/* Serialize into a fixed-capacity buffer. On success, sets *out_len to
 * the number of bytes written (NOT including a NUL terminator; the
 * function does NOT NUL-terminate). Returns 0 on success, -1 if the
 * buffer would overflow (in which case the buffer's contents are
 * undefined and *out_len is unset). */
int xml_serialize_to_buf(const XMLNode *root, char *buf, size_t cap,
                         size_t *out_len);

/* ------------------------------------------------------------------ */
/* Parser                                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    int max_depth;       /* nesting cap; 0 means use default (64) */
    int max_nodes;       /* total node cap; 0 means use default (65536) */
    int allow_doctype;   /* 0 (default): DOCTYPE → error. 1: skip silently. */
} xml_parse_opts_t;

typedef struct {
    const char *err_msg;     /* static string; NULL on success */
    size_t      err_offset;  /* byte offset into input where error was detected */
    int         err_line;    /* 1-based */
    int         err_col;     /* 1-based */
} xml_parse_err_t;

/* Parse `len` bytes starting at `data`. Returns the root element on
 * success, or NULL on parse error. If `err` is non-NULL it is filled in
 * (err_msg = NULL means success). `opts` may be NULL for defaults.
 *
 * Caller owns the returned tree and must release it with free_tree().
 * The library does NOT alias into `data`; it copies bytes as needed. */
XMLNode* parse_xml(const char *data, size_t len,
                   const xml_parse_opts_t *opts,
                   xml_parse_err_t *err);

#ifdef __cplusplus
}
#endif

#endif /* XML_PARSER_H */
