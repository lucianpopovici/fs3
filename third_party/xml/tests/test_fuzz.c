/* test_fuzz.c — Quick brute-force fuzzer.
 *
 * Generates many random byte strings and feeds them to parse_xml.
 * Goal: parser must never crash, leak, or hang. Errors are expected;
 * crashes are not. ASan/UBSan + bounded depth provide the safety net.
 */

#include "xml_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static unsigned long g_seed;
static unsigned long lcg(void) {
    g_seed = g_seed * 6364136223846793005UL + 1442695040888963407UL;
    return g_seed;
}

int main(int argc, char **argv) {
    int iterations = (argc > 1) ? atoi(argv[1]) : 10000;
    g_seed = (unsigned long)time(NULL);

    int parsed_ok = 0;
    int errored = 0;

    /* Mix of fully-random and "looks like XML" inputs. */
    for (int i = 0; i < iterations; i++) {
        size_t n = (size_t)(lcg() % 2048);
        char *buf = malloc(n);
        if (!buf) { fprintf(stderr, "OOM at iter %d\n", i); return 1; }

        if ((i & 3) == 0) {
            /* Fully random bytes */
            for (size_t j = 0; j < n; j++) buf[j] = (char)(lcg() & 0xFF);
        } else {
            /* Bias toward XML-like characters so the parser does real work */
            static const char xml_chars[] =
                "<>/?!=\"' \n\tabcdefghijklmnopqrstuvwxyzABCDEFG0123456789&;[]";
            for (size_t j = 0; j < n; j++) {
                buf[j] = xml_chars[lcg() % (sizeof(xml_chars) - 1)];
            }
        }

        XMLNode *root = parse_xml(buf, n, NULL, NULL);
        if (root) { parsed_ok++; free_tree(root); }
        else      { errored++; }

        free(buf);
    }
    printf("Fuzzed %d iterations: %d parsed, %d errored, 0 crashed\n",
           iterations, parsed_ok, errored);
    return 0;
}
