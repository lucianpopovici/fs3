/* test_xml.c — exhaustive tests for the extended XML library.
 *
 * Covers:
 *   1. Backwards compat: original API still works
 *   2. Escaping in serialize (the critical fix)
 *   3. Buffer-callback serializer
 *   4. Parser: realistic S3 inputs round-trip
 *   5. Parser security: nesting limits, XXE prevention, malformed input
 *   6. Edge cases: empty content, self-closing, whitespace handling
 */

#include "xml_parser.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, msg) do {                                          \
    if (!(cond)) {                                                     \
        fprintf(stderr, "FAIL [%s:%d] %s: %s\n",                       \
                __FILE__, __LINE__, __func__, msg);                    \
        failures++;                                                    \
    }                                                                  \
} while (0)

#define CHECK_STR_EQ(got, want) do {                                   \
    if (strcmp((got), (want)) != 0) {                                  \
        fprintf(stderr, "FAIL [%s:%d] %s:\n  got:  %s\n  want: %s\n",  \
                __FILE__, __LINE__, __func__, (got), (want));          \
        failures++;                                                    \
    }                                                                  \
} while (0)

/* ---- Test 1: original API ----------------------------------------- */

static void t_original_api(void) {
    XMLNode *root = create_node("root");
    CHECK(root != NULL, "create_node returns non-NULL");
    CHECK(strcmp(root->local_name, "root") == 0, "name set");

    XMLNode *child = create_node("child");
    CHECK(add_child(root, child) == 0, "add_child returns 0");
    CHECK(root->child_count == 1, "child_count incremented");
    CHECK(root->children[0] == child, "child stored");
    CHECK(child->parent == root, "parent linked");

    CHECK(add_attr(root, "k1", "v1") == 0, "add_attr returns 0");
    CHECK(add_attr(root, "k2", "v2") == 0, "second attr");
    CHECK(root->attr_count == 2, "attr_count");
    CHECK(strcmp(root->attr_keys[0], "k1") == 0, "attr key 0");
    CHECK(strcmp(root->attr_values[1], "v2") == 0, "attr value 1");

    XMLNode *found = find_node(root, "child");
    CHECK(found == child, "find_node finds child");
    CHECK(find_node(root, "missing") == NULL, "find_node misses absent");

    free_tree(root);
}

/* ---- Test 2: O(n²) growth replaced by capacity-doubling ----------- */

static void t_capacity_doubling(void) {
    XMLNode *root = create_node("root");
    /* Add 1000 children. Old code did 1000 reallocs; new code does ~10. */
    for (int i = 0; i < 1000; i++) {
        char name[16];
        snprintf(name, sizeof(name), "c%d", i);
        XMLNode *c = create_node(name);
        CHECK(add_child(root, c) == 0, "add_child large N");
    }
    CHECK(root->child_count == 1000, "1000 children");
    CHECK(root->child_cap >= 1000, "capacity at least count");
    CHECK(root->child_cap <= 2048, "capacity not pathological");

    /* Same for attrs */
    for (int i = 0; i < 100; i++) {
        char k[16], v[16];
        snprintf(k, sizeof(k), "k%d", i);
        snprintf(v, sizeof(v), "v%d", i);
        CHECK(add_attr(root, k, v) == 0, "add_attr large N");
    }
    CHECK(root->attr_count == 100, "100 attrs");

    free_tree(root);
}

/* ---- Test 3: escaping in serialization ---------------------------- */

static int sb_write(void *ctx, const char *data, size_t len) {
    char **acc = ctx;
    size_t old = *acc ? strlen(*acc) : 0;
    char *n = realloc(*acc, old + len + 1);
    if (!n) return -1;
    memcpy(n + old, data, len);
    n[old + len] = '\0';
    *acc = n;
    return 0;
}

static char *serialize_to_string(const XMLNode *node) {
    char *acc = NULL;
    if (xml_serialize(node, sb_write, &acc, 0) != 0) {
        free(acc);
        return NULL;
    }
    return acc;
}

static void t_escaping_content(void) {
    XMLNode *root = create_node("Key");
    xml_set_content(root, "photos/cat&dog<2>.jpg");
    char *out = serialize_to_string(root);
    CHECK(out != NULL, "serialize succeeded");
    CHECK_STR_EQ(out, "<Key>photos/cat&amp;dog&lt;2&gt;.jpg</Key>\n");
    free(out);
    free_tree(root);
}

static void t_escaping_attr(void) {
    XMLNode *root = create_node("Resource");
    /* Attribute value with all special chars */
    add_attr(root, "data", "a&b<c>d\"e'f\tg\nh\ri");
    char *out = serialize_to_string(root);
    CHECK(out != NULL, "serialize OK");
    /* Attr values escape: & < > " and normalize \t \n \r */
    CHECK_STR_EQ(out,
        "<Resource data=\"a&amp;b&lt;c&gt;d&quot;e'f&#9;g&#10;h&#13;i\"/>\n");
    free(out);
    free_tree(root);
}

static void t_escaping_disabled_in_attrs(void) {
    /* Single quotes don't need escaping in double-quoted attrs */
    XMLNode *root = create_node("R");
    add_attr(root, "k", "with'apostrophe");
    char *out = serialize_to_string(root);
    CHECK_STR_EQ(out, "<R k=\"with'apostrophe\"/>\n");
    free(out);
    free_tree(root);
}

/* ---- Test 4: realistic S3 emit ------------------------------------ */

static void t_s3_list_bucket_result(void) {
    XMLNode *root = create_node("ListBucketResult");
    add_attr(root, "xmlns", "http://s3.amazonaws.com/doc/2006-03-01/");

    XMLNode *name = create_node("Name");
    xml_set_content(name, "my-bucket");
    add_child(root, name);

    XMLNode *contents = create_node("Contents");
    add_child(root, contents);

    XMLNode *key = create_node("Key");
    /* Tricky key: ampersand and less-than that would have broken Phase 0 */
    xml_set_content(key, "photos/cat&dog<2>.jpg");
    add_child(contents, key);

    XMLNode *etag = create_node("ETag");
    xml_set_content(etag, "\"d41d8cd98f00b204e9800998ecf8427e\"");
    add_child(contents, etag);

    char *out = serialize_to_string(root);
    CHECK(out != NULL, "serialized");

    /* Result must be valid XML: no raw < or > or & in content */
    int has_amp_entity = strstr(out, "&amp;") != NULL;
    int has_lt_entity  = strstr(out, "&lt;")  != NULL;
    int has_gt_entity  = strstr(out, "&gt;")  != NULL;
    CHECK(has_amp_entity, "ampersand escaped");
    CHECK(has_lt_entity,  "less-than escaped");
    CHECK(has_gt_entity,  "greater-than escaped");

    /* The ETag's quotes inside content must remain literal */
    CHECK(strstr(out, "<ETag>\"d41d8cd9") != NULL, "etag quotes literal");

    free(out);
    free_tree(root);
}

/* ---- Test 5: xml_serialize_to_buf --------------------------------- */

static void t_serialize_to_buf(void) {
    XMLNode *root = create_node("Hello");
    xml_set_content(root, "world");

    char buf[64];
    size_t n = 0;
    int rc = xml_serialize_to_buf(root, buf, sizeof(buf), &n);
    CHECK(rc == 0, "to_buf success");
    CHECK(n > 0, "wrote bytes");
    CHECK(n < sizeof(buf), "fits");
    /* verify by null-terminating and comparing */
    buf[n] = '\0';
    CHECK_STR_EQ(buf, "<Hello>world</Hello>\n");

    /* Overflow detection */
    char small[5];
    rc = xml_serialize_to_buf(root, small, sizeof(small), &n);
    CHECK(rc == -1, "overflow detected");

    free_tree(root);
}

/* ---- Test 6: parser basics ---------------------------------------- */

static void t_parse_simple(void) {
    const char *xml = "<root><a>hello</a><b>world</b></root>";
    xml_parse_err_t err = {0};
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, &err);
    CHECK(root != NULL, "parse simple OK");
    if (!root) {
        fprintf(stderr, "  err: %s at line %d col %d\n",
                err.err_msg, err.err_line, err.err_col);
        return;
    }
    CHECK_STR_EQ(root->local_name, "root");
    CHECK(root->child_count == 2, "2 children");
    CHECK_STR_EQ(root->children[0]->local_name, "a");
    CHECK_STR_EQ(root->children[0]->content, "hello");
    CHECK_STR_EQ(root->children[1]->content, "world");
    free_tree(root);
}

static void t_parse_attrs(void) {
    const char *xml = "<elem k1=\"v1\" k2='v2 with spaces'/>";
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, NULL);
    CHECK(root != NULL, "parse self-closing with attrs");
    CHECK(root->attr_count == 2, "2 attrs");
    CHECK_STR_EQ(get_attr(root, "k1"), "v1");
    CHECK_STR_EQ(get_attr(root, "k2"), "v2 with spaces");
    CHECK(root->child_count == 0, "no children");
    CHECK(root->content == NULL, "no content");
    free_tree(root);
}

static void t_parse_entities(void) {
    const char *xml = "<x>a&amp;b&lt;c&gt;d&quot;e&apos;f&#65;g&#x42;h</x>";
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, NULL);
    CHECK(root != NULL, "parse entities");
    CHECK_STR_EQ(root->content, "a&b<c>d\"e'fAgBh");
    free_tree(root);
}

static void t_parse_cdata(void) {
    const char *xml = "<x><![CDATA[<not-a-tag>&also-not</fake>]]></x>";
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, NULL);
    CHECK(root != NULL, "parse CDATA");
    CHECK_STR_EQ(root->content, "<not-a-tag>&also-not</fake>");
    free_tree(root);
}

static void t_parse_namespace_strip(void) {
    const char *xml = "<s3:Foo xmlns:s3=\"urn:x\"><s3:Bar>hi</s3:Bar></s3:Foo>";
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, NULL);
    CHECK(root != NULL, "parse namespaced");
    CHECK_STR_EQ(root->local_name, "Foo");
    CHECK_STR_EQ(get_attr(root, "xmlns:s3"), "urn:x");
    CHECK(root->child_count == 1, "1 child");
    CHECK_STR_EQ(root->children[0]->local_name, "Bar");
    free_tree(root);
}

static void t_parse_xml_decl(void) {
    const char *xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<root/>";
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, NULL);
    CHECK(root != NULL, "parse with XML decl");
    if (root) CHECK_STR_EQ(root->local_name, "root");
    free_tree(root);
}

static void t_parse_comments(void) {
    const char *xml = "<!-- before --><root><!-- inside --><c/></root>";
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, NULL);
    CHECK(root != NULL, "parse with comments");
    if (root) CHECK(root->child_count == 1, "comment doesn't become child");
    free_tree(root);
}

static void t_parse_bom(void) {
    const char xml[] = "\xef\xbb\xbf<root/>";
    XMLNode *root = parse_xml(xml, sizeof(xml) - 1, NULL, NULL);
    CHECK(root != NULL, "parse with UTF-8 BOM");
    free_tree(root);
}

/* ---- Test 7: realistic S3 input parsing --------------------------- */

static void t_parse_complete_multipart(void) {
    /* Real CompleteMultipartUpload body shape */
    const char *xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<CompleteMultipartUpload>\n"
        "  <Part>\n"
        "    <PartNumber>1</PartNumber>\n"
        "    <ETag>\"a54357aff0632cce46d942af68356b38\"</ETag>\n"
        "  </Part>\n"
        "  <Part>\n"
        "    <PartNumber>2</PartNumber>\n"
        "    <ETag>\"0c78aef83f66abc1fa1e8477f296d394\"</ETag>\n"
        "  </Part>\n"
        "</CompleteMultipartUpload>";

    xml_parse_err_t err = {0};
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, &err);
    CHECK(root != NULL, "parse CompleteMultipartUpload");
    if (!root) {
        fprintf(stderr, "  err: %s at line %d col %d\n",
                err.err_msg, err.err_line, err.err_col);
        return;
    }
    CHECK_STR_EQ(root->local_name, "CompleteMultipartUpload");

    /* Iterate Part children */
    int n_parts = 0;
    for (int i = 0; i < root->child_count; i++) {
        if (strcmp(root->children[i]->local_name, "Part") == 0) {
            XMLNode *part = root->children[i];
            XMLNode *pn = find_child(part, "PartNumber");
            XMLNode *et = find_child(part, "ETag");
            CHECK(pn && pn->content, "PartNumber present");
            CHECK(et && et->content, "ETag present");
            n_parts++;
        }
    }
    CHECK(n_parts == 2, "2 parts");

    free_tree(root);
}

static void t_parse_delete_multi(void) {
    /* Multi-object Delete request */
    const char *xml =
        "<Delete>"
        "<Object><Key>key1</Key></Object>"
        "<Object><Key>key2&amp;weird</Key></Object>"
        "<Object><Key>key3</Key><VersionId>v1</VersionId></Object>"
        "<Quiet>true</Quiet>"
        "</Delete>";
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, NULL);
    CHECK(root != NULL, "parse Delete");
    CHECK_STR_EQ(root->local_name, "Delete");

    int n_objs = 0;
    for (int i = 0; i < root->child_count; i++) {
        if (strcmp(root->children[i]->local_name, "Object") == 0) {
            XMLNode *obj = root->children[i];
            XMLNode *k = find_child(obj, "Key");
            CHECK(k != NULL, "Object has Key");
            n_objs++;
        }
    }
    CHECK(n_objs == 3, "3 objects");

    /* Verify entity decoding worked: key2 should contain literal '&' */
    XMLNode *obj2 = root->children[1];
    XMLNode *key2 = find_child(obj2, "Key");
    CHECK_STR_EQ(key2->content, "key2&weird");

    free_tree(root);
}

/* ---- Test 8: parser security limits ------------------------------- */

static void t_max_depth(void) {
    /* Build deeply nested input: <a><a><a>...</a></a></a> */
    char xml[2048];
    int half = 100;
    int pos = 0;
    for (int i = 0; i < half; i++) pos += snprintf(xml + pos, sizeof(xml)-pos, "<a>");
    for (int i = 0; i < half; i++) pos += snprintf(xml + pos, sizeof(xml)-pos, "</a>");

    /* Default limit is 64 → should fail */
    xml_parse_err_t err = {0};
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, &err);
    CHECK(root == NULL, "deep nesting rejected at default depth");
    CHECK(err.err_msg != NULL, "error reported");

    /* Raise the limit and retry — should succeed */
    xml_parse_opts_t opts = { .max_depth = 200, 0, 0 };
    XMLNode *r2 = parse_xml(xml, strlen(xml), &opts, NULL);
    CHECK(r2 != NULL, "deep nesting accepted with raised limit");
    free_tree(r2);
}

static void t_doctype_rejected(void) {
    /* The classic XXE setup. Even if we can't trigger fetching, we should
     * refuse to even see a DOCTYPE by default. */
    const char *xml =
        "<!DOCTYPE foo ["
        "<!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>"
        "<root>&xxe;</root>";
    xml_parse_err_t err = {0};
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, &err);
    CHECK(root == NULL, "DOCTYPE rejected by default");
    CHECK(err.err_msg && strstr(err.err_msg, "DOCTYPE"), "error mentions DOCTYPE");
}

static void t_undefined_entity_rejected(void) {
    const char *xml = "<x>&undefined_entity;</x>";
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, NULL);
    CHECK(root == NULL, "undefined entity rejected");
}

static void t_billion_laughs_safe(void) {
    /* Without DTD support and without entity expansion, billion-laughs
     * is impossible. But verify a DOCTYPE attempt is rejected cleanly. */
    const char *xml =
        "<!DOCTYPE lolz ["
        "<!ENTITY lol \"lol\">"
        "<!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;\">"
        "]>"
        "<lolz>&lol2;</lolz>";
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, NULL);
    CHECK(root == NULL, "billion laughs rejected (DOCTYPE refused)");
}

static void t_malformed(void) {
    struct { const char *xml; const char *what; } cases[] = {
        { "<unclosed>",                "unclosed root" },
        { "<a></b>",                   "tag mismatch" },
        { "<a attr=>",                 "missing attr value" },
        { "<a attr=\"unterm",          "unterminated attr value" },
        { "<a><b></a></b>",            "improper nesting" },
        { "",                          "empty input" },
        { "no element here",           "no root" },
        { "<a><![CDATA[never closed",  "unterminated cdata" },
        { "<a><!-- never closes",      "unterminated comment" },
        { "<a><b/></a>extra",          "trailing content" },
        { "<&>",                       "invalid name char" },
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(cases[0]); i++) {
        xml_parse_err_t err = {0};
        XMLNode *root = parse_xml(cases[i].xml, strlen(cases[i].xml), NULL, &err);
        if (root != NULL) {
            fprintf(stderr, "FAIL: '%s' should have failed (%s) but parsed\n",
                    cases[i].xml, cases[i].what);
            failures++;
            free_tree(root);
        }
    }
}

/* ---- Test 9: round-trip parse → serialize ------------------------- */

static void t_roundtrip(void) {
    const char *xml =
        "<root xmlns=\"urn:test\">"
        "<a id=\"1\">hello &amp; world</a>"
        "<b><c/></b>"
        "</root>";
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, NULL);
    CHECK(root != NULL, "parse for roundtrip");
    if (!root) return;

    char *out = serialize_to_string(root);
    CHECK(out != NULL, "serialize roundtrip");

    /* Parse the serialized output again and compare structures */
    XMLNode *r2 = parse_xml(out, strlen(out), NULL, NULL);
    CHECK(r2 != NULL, "re-parse OK");
    if (r2) {
        CHECK_STR_EQ(r2->local_name, "root");
        CHECK_STR_EQ(get_attr(r2, "xmlns"), "urn:test");
        XMLNode *a = find_child(r2, "a");
        CHECK(a != NULL, "found a");
        if (a) CHECK_STR_EQ(a->content, "hello & world");
        free_tree(r2);
    }
    free(out);
    free_tree(root);
}

/* ---- Test 10: xml_set_content edge cases -------------------------- */

static void t_set_content(void) {
    XMLNode *n = create_node("x");
    CHECK(xml_set_content(n, "first") == 0, "set first");
    CHECK_STR_EQ(n->content, "first");
    CHECK(xml_set_content(n, "second") == 0, "replace");
    CHECK_STR_EQ(n->content, "second");
    CHECK(xml_set_content(n, NULL) == 0, "clear");
    CHECK(n->content == NULL, "cleared to NULL");

    CHECK(xml_set_content_n(n, "abcdef", 3) == 0, "partial");
    CHECK_STR_EQ(n->content, "abc");
    free_tree(n);
}

/* ---- Test 11: error reporting line/col ---------------------------- */

static void t_error_position(void) {
    const char *xml = "<a>\n<b>\n<bad attr=>\n</b></a>";
    xml_parse_err_t err = {0};
    XMLNode *root = parse_xml(xml, strlen(xml), NULL, &err);
    CHECK(root == NULL, "error returned");
    CHECK(err.err_line == 3, "error on line 3");
    /* col should point at or near the '=' */
    CHECK(err.err_col > 0, "col set");
}

/* ---- Main --------------------------------------------------------- */

int main(void) {
    t_original_api();
    t_capacity_doubling();
    t_escaping_content();
    t_escaping_attr();
    t_escaping_disabled_in_attrs();
    t_s3_list_bucket_result();
    t_serialize_to_buf();
    t_parse_simple();
    t_parse_attrs();
    t_parse_entities();
    t_parse_cdata();
    t_parse_namespace_strip();
    t_parse_xml_decl();
    t_parse_comments();
    t_parse_bom();
    t_parse_complete_multipart();
    t_parse_delete_multi();
    t_max_depth();
    t_doctype_rejected();
    t_undefined_entity_rejected();
    t_billion_laughs_safe();
    t_malformed();
    t_roundtrip();
    t_set_content();
    t_error_position();

    if (failures == 0) {
        printf("ALL TESTS PASSED\n");
        return 0;
    } else {
        printf("%d FAILURES\n", failures);
        return 1;
    }
}
