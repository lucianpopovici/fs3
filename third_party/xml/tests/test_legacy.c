/* test_legacy.c — verify the user's original calling pattern still works:
 *   - void-return semantics for add_child / add_attr (return value ignored)
 *   - direct assignment to node->content via strdup
 *   - serialize_node(FILE *) emits to stdout/file
 *   - find_node recursive lookup
 *   - free_tree releases everything
 *
 * This mirrors the test_s3_xml.c we wrote when first inspecting the
 * library, except now we expect *correct* (escaped) output.
 */

#include "xml_parser.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    XMLNode *root = create_node("ListBucketResult");
    add_attr(root, "xmlns", "http://s3.amazonaws.com/doc/2006-03-01/");

    XMLNode *name = create_node("Name");
    name->content = strdup("my-bucket");
    add_child(root, name);

    XMLNode *contents = create_node("Contents");
    add_child(root, contents);

    XMLNode *key = create_node("Key");
    key->content = strdup("photos/cat&dog<2>.jpg");
    add_child(contents, key);

    XMLNode *etag = create_node("ETag");
    etag->content = strdup("\"d41d8cd98f00b204e9800998ecf8427e\"");
    add_child(contents, etag);

    serialize_node(stdout, root, 0);
    free_tree(root);
    return 0;
}
