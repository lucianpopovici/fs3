/* tests/test_ssekeys.c — SSE-S3 key file parser and object marker TLV:
 * valid and invalid files, TLV round trip and malformed records, then a
 * fuzz loop over both. Usage: test_ssekeys [iterations]. */
#include "ssekeys.h"
#include "store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pass, fail;
#define CHECK(name, cond) do { if (cond) pass++; else { fail++; printf("FAIL: %s (line %d)\n", name, __LINE__); } } while (0)
static unsigned long long rng = 88172645463325252ull;
static unsigned rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (unsigned)rng; }

#define HEX64 "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

static int parse(const char *t) {
    char ids[8][SSEKEYS_ID_MAX + 1];
    uint8_t keys[8][32];
    char err[200];
    return ssekeys_parse(t, strlen(t), ids, keys, 8, err, sizeof(err));
}

int main(int argc, char **argv) {
    char ids[8][SSEKEYS_ID_MAX + 1];
    uint8_t keys[8][32];
    char err[200];
    const char *ok = "# comment\n\n  k1 " HEX64 "  \r\nold.2024_x-1\t" HEX64 "\n";
    CHECK("two keys", ssekeys_parse(ok, strlen(ok), ids, keys, 8, err, sizeof(err)) == 2);
    CHECK("ids", !strcmp(ids[0], "k1") && !strcmp(ids[1], "old.2024_x-1"));
    CHECK("key bytes", keys[0][0] == 0x00 && keys[0][1] == 0x11 && keys[0][31] == 0xff);
    CHECK("empty file", parse("") < 0);
    CHECK("comments only", parse("# x\n\n") < 0);
    CHECK("no id", parse(HEX64 "\n") < 0);
    CHECK("short key", parse("k1 0011\n") < 0);
    CHECK("long key", parse("k1 " HEX64 "00\n") < 0);
    CHECK("non-hex", parse("k1 zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\n") < 0);
    CHECK("bad id chars", parse("k/1 " HEX64 "\n") < 0);
    CHECK("id too long", parse("abcdefghijabcdefghijabcdefghijabc " HEX64 "\n") < 0);
    CHECK("duplicate id", parse("k1 " HEX64 "\nk1 " HEX64 "\n") < 0);
    CHECK("all-zero key", parse("k1 0000000000000000000000000000000000000000000000000000000000000000\n") < 0);
    {
        char big[8 * 80 + 100] = "";
        for (int i = 0; i < 9; i++) {
            char l[90];
            snprintf(l, sizeof(l), "k%d " HEX64 "\n", i);
            strcat(big, l);
        }
        CHECK("over the max", parse(big) < 0);
    }

    uint8_t t[SSEKEYS_TLV_MAX + 64];
    size_t n = ssekeys_tlv_encode("k1", t);
    char id[SSEKEYS_ID_MAX + 1];
    CHECK("tlv round trip", ssekeys_tlv_find(t, n, id) == 1 && !strcmp(id, "k1"));
    CHECK("absent", ssekeys_tlv_find(NULL, 0, id) == 0);
    {
        /* Among other records. */
        uint8_t m[128] = { 1, 0, 3, 0, 0, 0, 'a', 'b', 'c' };
        memcpy(m + 9, t, n);
        CHECK("found after another record", ssekeys_tlv_find(m, 9 + n, id) == 1);
        CHECK("truncated", ssekeys_tlv_find(m, 9 + n - 1, id) < 0);
        memcpy(m + 9 + n, t, n);
        CHECK("duplicate marker refused", ssekeys_tlv_find(m, 9 + 2 * n, id) < 0);
    }
    t[7] = 9;
    CHECK("bad id length", ssekeys_tlv_find(t, n, id) < 0);
    t[7] = 2; t[6] = 2;
    CHECK("bad version", ssekeys_tlv_find(t, n, id) < 0);
    t[6] = 1; t[8] = '/';
    CHECK("bad id chars in tlv", ssekeys_tlv_find(t, n, id) < 0);

    long iters = argc > 1 ? atol(argv[1]) : 50000, found = 0, parsed = 0;
    for (long it = 0; it < iters; it++) {
        uint8_t buf[512];
        size_t bn;
        if (it & 1) {
            bn = ssekeys_tlv_encode("key-0", buf);
            if (it % 5 == 0) { bn = rnd() % 64; for (size_t i = 0; i < bn; i++) buf[i] = (uint8_t)rnd(); }
            else for (int m = 1 + (int)(rnd() % 3); m--;) buf[rnd() % bn] ^= (uint8_t)(1u << (rnd() % 8));
            if (ssekeys_tlv_find(buf, bn, id) == 1) { found++; if (strlen(id) > SSEKEYS_ID_MAX) fail++; }
        } else {
            const char *seed = "k1 " HEX64 "\nk2 " HEX64 "\n";
            bn = strlen(seed);
            memcpy(buf, seed, bn);
            for (int m = 1 + (int)(rnd() % 4); m--;) buf[rnd() % bn] = (uint8_t)rnd();
            if (it % 7 == 0) bn = rnd() % bn;
            char e2[200];
            if (ssekeys_parse((const char *)buf, bn, ids, keys, 8, e2, sizeof(e2)) > 0) parsed++;
        }
    }
    printf("fuzz: %ld iterations (%ld markers, %ld key files accepted)\n", iters, found, parsed);
    printf("===== ssekeys: %d passed, %d failed =====\n", pass, fail);
    return fail ? 1 : 0;
}
