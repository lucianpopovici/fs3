/* tests/test_json.c — strict JSON reader: grammar, duplicates, limits,
 * UTF-8, escaping; then a mutation fuzz (must not crash). */
#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pass, fail;
#define CHECK(c, m) do { if (c) pass++; else { fail++; \
    fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, m); } } while (0)

static int ok(const char *s) {
    json_t *j = json_parse(s, strlen(s), 0, 0);
    json_free(j);
    return j != NULL;
}

int main(int argc, char **argv) {
    CHECK(ok("{\"a\":1,\"b\":[true,false,null,\"x\",-1.5e3]}"), "basic");
    CHECK(ok("  \"s\"  "), "scalar");
    CHECK(!ok("{\"a\":1,\"a\":2}"), "duplicate key");
    CHECK(!ok("{\"a\":1,}"), "trailing comma");
    CHECK(!ok("[1,]"), "trailing comma arr");
    CHECK(!ok("{'a':1}"), "single quotes");
    CHECK(!ok("{\"a\":01}"), "leading zero");
    CHECK(!ok("{\"a\":1} x"), "trailing garbage");
    CHECK(!ok("\"a\x01b\""), "raw control char");
    CHECK(!ok("\"\\ud800\""), "lone surrogate");
    CHECK(!ok("\"\\u0000\""), "embedded NUL");
    CHECK(!ok("\"\xc0\xaf\""), "overlong UTF-8");
    CHECK(ok("\"\\ud83d\\ude00 caf\xc3\xa9\""), "surrogate pair + UTF-8");
    CHECK(!ok("[[[[[[[[[[1]]]]]]]]]]"), "depth > 8");
    CHECK(ok("[[[[[[[[1]]]]]]]]"), "depth 8");
    CHECK(!ok("/* c */ 1"), "comments");
    CHECK(!ok(""), "empty");
    {
        const char *esc = "{\"k\":\"v\\n\\\"q\\\"\"}";
        json_t *j = json_parse(esc, strlen(esc), 0, 0);
        CHECK(j && json_str(json_get(j, "k")) && strcmp(json_str(json_get(j, "k")), "v\n\"q\"") == 0,
              "escapes decoded");
        json_free(j);
    }
    {
        char big[20000];
        size_t o = 0;
        big[o++] = '[';
        for (int i = 0; i < 5000; i++) { big[o++] = '1'; big[o++] = ','; }
        big[o++] = '1'; big[o++] = ']';
        CHECK(json_parse(big, o, 0, 4096) == NULL, "node cap");
    }
    {
        char out[64]; size_t o = 0;
        CHECK(json_put_str(out, sizeof(out), &o, "a\"b\\c\n<") == 0
              && strcmp(out, "\"a\\\"b\\\\c\\u000a\\u003c\"") == 0, "writer escapes");
        o = 0;
        CHECK(json_put_str(out, 4, &o, "toolong") < 0, "writer overflow");
    }

    long iters = argc > 1 ? atol(argv[1]) : 50000;
    static const char *seeds[] = {
        "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\","
        "\"Action\":[\"s3:GetObject\"],\"Resource\":\"arn:aws:s3:::b/*\","
        "\"Condition\":{\"IpAddress\":{\"aws:SourceIp\":[\"10.0.0.0/8\"]}}}]}",
        "[1,2.5e-3,-0,\"\\u00e9\",{\"a\":null}]",
    };
    unsigned long long r = 12345;
    char buf[1024];
    for (long it = 0; it < iters; it++) {
        const char *s = seeds[it % 2];
        size_t n = strlen(s);
        memcpy(buf, s, n);
        for (int m = 0; m < 1 + (int)(it % 5); m++) {
            r ^= r << 13; r ^= r >> 7; r ^= r << 17;
            size_t at = r % n;
            if (r & 1) buf[at] = (char)(r >> 8);
            else buf[at] = "{}[]\",:\\u0e"[(r >> 8) % 11];
        }
        json_free(json_parse(buf, n, 0, 0));
    }
    printf("===== json: %d passed, %d failed (%ld fuzz iterations) =====\n", pass, fail, iters);
    return fail != 0;
}
