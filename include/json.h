/* include/json.h — small strict JSON reader + escaped writer
 *
 * Used for bucket policies (item 9) and admin API bodies (item 11).
 * Strict by design (security review S6): RFC 8259 grammar only, no
 * comments or trailing commas, duplicate object keys rejected, nesting
 * depth and total node count capped, strings must be valid UTF-8 with
 * no raw control characters. Numbers are kept as their text.
 */
#ifndef FS3_JSON_H
#define FS3_JSON_H

#include <stddef.h>

typedef enum { JSON_NULL, JSON_BOOL, JSON_NUM, JSON_STR, JSON_ARR, JSON_OBJ } json_type_t;

typedef struct json json_t;
struct json {
    json_type_t type;
    char       *key;       /* member name when inside an object */
    char       *str;       /* JSON_STR: decoded UTF-8; JSON_NUM: text */
    size_t      str_n;
    int         b;         /* JSON_BOOL */
    json_t     *child;     /* first element/member */
    json_t     *next;      /* next sibling */
    size_t      n_children;
};

/* Parse `n` bytes. max_depth/max_nodes: 0 = defaults (8 / 4096).
 * Returns NULL on any error. */
json_t *json_parse(const char *s, size_t n, int max_depth, int max_nodes);
void    json_free(json_t *j);

/* Object member by name (NULL if absent or not an object). */
const json_t *json_get(const json_t *obj, const char *key);
/* JSON_STR value or NULL. */
const char   *json_str(const json_t *j);

/* Append `s` as a quoted, escaped JSON string to out[*o..cap). Returns 0,
 * or -1 if it does not fit (out is left NUL-terminated). */
int json_put_str(char *out, size_t cap, size_t *o, const char *s);

#endif
