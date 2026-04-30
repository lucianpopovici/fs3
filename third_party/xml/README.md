# XML library — extended for fs3

This is your XML library, with two correctness fixes and three additions.
The original public API is preserved unchanged.

## Files

- `xml_parser.h` — public API. Existing names kept; new names added.
- `xml_parser.c` — single implementation file.
- `tests/test_xml.c` — 25 test cases covering original API, escaping,
  buffer serializer, parser, security limits, and round-trips.
- `tests/test_legacy.c` — verifies your original calling pattern still
  works (direct `node->content = strdup(...)` assignments,
  void-style `add_child`/`add_attr` calls).
- `tests/test_fuzz.c` — quick brute-force fuzzer; 50k random inputs
  must produce zero crashes.

## Critical fixes

### 1. XML escaping in `serialize_node`

Previously, content like `cat&dog<2>.jpg` was written verbatim,
producing malformed XML. Now `&`, `<`, `>` in content are escaped to
`&amp;`, `&lt;`, `&gt;`; attribute values additionally escape `"` and
normalize whitespace per the XML spec.

This is the single most important change. SDKs that received the old
output would either reject the response or interpret `<2>` as a tag.

### 2. OOM-safe builders

`create_node` now returns NULL if `calloc` or `strdup` fails (instead
of segfaulting on the next `strdup`). `add_child` and `add_attr` now
return `int` (0 on success, -1 on failure). Callers that ignored the
old `void` return continue to compile; on OOM they'll see a node with
missing children/attrs but no crash.

### 3. O(n) growth for children and attributes

`add_child`/`add_attr` previously did one `realloc` per call (O(n²)
total). Now they grow capacity by doubling, giving amortized O(1) per
add. For a `Delete` request with 1000 keys this is a real difference.

## Extensions

### Write-callback serializer

```c
typedef int (*xml_write_fn)(void *ctx, const char *data, size_t len);
int xml_serialize(const XMLNode *root, xml_write_fn cb, void *ctx, int indent);
int xml_serialize_to_buf(const XMLNode *root, char *buf, size_t cap,
                         size_t *out_len);
```

`xml_serialize` lets the caller direct output anywhere — a memory
buffer, a socket, a custom log. `xml_serialize_to_buf` is the simple
case for fixed-size buffers (used by fs3 to write directly into
the connection's `wbuf`). The existing `serialize_node(FILE*)` is
still there; it now wraps `xml_serialize` internally.

### Helpers

```c
int          xml_set_content  (XMLNode *node, const char *content);
int          xml_set_content_n(XMLNode *node, const char *content, size_t n);
XMLNode     *find_child       (XMLNode *parent, const char *name);
const char  *get_attr         (const XMLNode *node, const char *key);
```

`xml_set_content` properly frees any previous content; preferred over
direct field assignment but the field stays public so existing code
keeps working. `find_child` is non-recursive (unlike `find_node`),
which is what you want when iterating children of a known parent.

### Parser

```c
typedef struct {
    int max_depth;       /* default 64 */
    int max_nodes;       /* default 65536 */
    int allow_doctype;   /* default 0 — DOCTYPE rejected */
} xml_parse_opts_t;

typedef struct {
    const char *err_msg;
    size_t      err_offset;
    int         err_line;
    int         err_col;
} xml_parse_err_t;

XMLNode *parse_xml(const char *data, size_t len,
                   const xml_parse_opts_t *opts,
                   xml_parse_err_t *err);
```

Recursive-descent parser, ~280 lines. Handles:

- Elements, attributes, character data, entity references.
- The five standard named entities (`&lt;` `&gt;` `&amp;` `&apos;`
  `&quot;`) and numeric character references (`&#nnn;`, `&#xhhh;`)
  decoded into UTF-8.
- CDATA sections.
- XML declaration `<?xml ...?>` and processing instructions (skipped).
- Comments (skipped).
- UTF-8 BOM (skipped).
- Namespaces: prefixes are stripped from element names. `<s3:Foo>`
  parses as `local_name = "Foo"`. `xmlns:s3="..."` is exposed as a
  regular attribute.

Does NOT handle:

- DTDs / DOCTYPE — rejected by default. Set `allow_doctype = 1` to
  skip silently. We never resolve external entities, so XXE attacks
  are not possible.
- User-defined entities — `&undefined;` is a parse error. This (plus
  no DTD) makes billion-laughs attacks structurally impossible.
- XML 1.1, schemas, xml:space.

Bounded recursion (default 64) and bounded node count (default 65536)
prevent stack overflow and memory exhaustion from malicious input.

## Building

The library has no dependencies. Compile `xml_parser.c` alongside
your other sources, with `-Ipath/to/xml_parser_dir` for the header.

```
gcc -O2 -Wall -Iinclude -Ithird_party/xml \
    your_code.c third_party/xml/xml_parser.c -o your_binary
```

## Running the tests

```
cd third_party/xml
gcc -O2 -g -Wall -Wextra -fsanitize=address,undefined \
    tests/test_xml.c xml_parser.c -o test_xml
./test_xml          # → ALL TESTS PASSED

gcc -O2 -g -fsanitize=address,undefined \
    tests/test_fuzz.c xml_parser.c -o test_fuzz
./test_fuzz 50000   # → 50000 errored, 0 crashed
```

## Backwards compatibility

Existing callers of your library work without modification:

- `XMLNode *n = create_node("foo")` — unchanged.
- `n->content = strdup("text")` — still allowed; the field is public.
- `add_child(parent, child)` — return value (now `int`) safely ignored.
- `add_attr(node, "k", "v")` — same.
- `serialize_node(stdout, root, 0)` — same. Output is now correctly
  escaped; if your existing callers were emitting content with `<` or
  `&` they were producing broken XML before.
- `find_node(root, "name")` — unchanged.
- `free_tree(root)` — unchanged.

The `XMLNode` struct gained two fields (`attr_cap`, `child_cap`) at
the end of the struct. Anything that constructs `XMLNode` directly
without `create_node` (which is unsupported but possible) should
zero-initialize. `calloc`-based code is fine.
