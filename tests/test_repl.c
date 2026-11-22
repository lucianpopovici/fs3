/* tests/test_repl.c — replication journal records and rule parsing:
 * round trips, torn/corrupt records, validation rules, then a fuzz loop
 * over both decoders (mutated valid inputs and noise). Must never crash;
 * run under ASan/UBSan for memory errors. Usage: test_repl [iterations]. */
#include "repl.h"
#include "store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* repl.c audits rule changes and failures; not under test here. */
void audit_event(const char *who, const char *what) { (void)who; (void)what; }

static int pass, fail;
#define CHECK(name, cond) do { if (cond) pass++; else { fail++; printf("FAIL: %s (line %d)\n", name, __LINE__); } } while (0)

static unsigned long long rng = 0x2545F4914F6CDD1Dull;
static unsigned rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (unsigned)rng; }

static int parse(const char *j, const repl_rule_t *old, int tls, repl_rule_t *out) {
    char err[300];
    return repl_rule_parse(j, strlen(j), old, tls, out, err, sizeof(err));
}

static void t_records(void) {
    uint8_t buf[4096];
    repl_rec_t a = { .seq = 42, .mtime_ms = 1700000000123ULL, .op = STORE_CHANGE_PUT };
    strcpy(a.key, "dir/ké y");
    a.key_len = strlen(a.key);
    size_t n = repl_rec_encode(&a, buf, sizeof(buf));
    CHECK("encode size", n == REPL_REC_HDR + REPL_REC_FIXED + a.key_len);
    repl_rec_t b;
    CHECK("decode", repl_rec_decode(buf, n, &b) == (long)n);
    CHECK("round trip", b.seq == 42 && b.mtime_ms == a.mtime_ms && b.op == a.op
                        && b.key_len == a.key_len && !strcmp(b.key, a.key));
    for (size_t k = 0; k < n; k++) CHECK("partial record = need more", repl_rec_decode(buf, k, &b) == 0);
    int all = 1;
    for (size_t i = 0; i < n; i++) {
        buf[i] ^= 0x40;
        if (repl_rec_decode(buf, n, &b) > 0) all = 0;
        buf[i] ^= 0x40;
    }
    CHECK("every single-byte flip is detected", all);
    repl_rec_t big = { .seq = 1, .op = STORE_CHANGE_DELETE, .key_len = REPL_KEY_MAX };
    memset(big.key, 'k', REPL_KEY_MAX);
    n = repl_rec_encode(&big, buf, sizeof(buf));
    CHECK("max key encodes", n > 0 && repl_rec_decode(buf, n, &b) == (long)n && b.key_len == REPL_KEY_MAX);
    big.key_len = REPL_KEY_MAX + 1;
    CHECK("oversized key refused", repl_rec_encode(&big, buf, sizeof(buf)) == 0);
    CHECK("too small buffer refused", repl_rec_encode(&a, buf, 10) == 0);
    /* Two back to back. */
    size_t n1 = repl_rec_encode(&a, buf, sizeof(buf));
    a.seq = 43;
    size_t n2 = repl_rec_encode(&a, buf + n1, sizeof(buf) - n1);
    CHECK("second record", repl_rec_decode(buf + n1, n2, &b) == (long)n2 && b.seq == 43);
}

static void t_rules(void) {
    repl_rule_t r, old;
    CHECK("minimal https rule", parse("{\"endpoint\":\"https://s3.example.com\",\"bucket\":\"bk1\","
          "\"access_key\":\"AK\",\"secret_key\":\"SK\"}", NULL, 1, &r) == 0);
    CHECK("defaults", !strcmp(r.region, "us-east-1") && r.verify_tls && r.deletes
                      && !r.allow_plain_http && !r.virtual_host);
    CHECK("https without TLS build refused", parse("{\"endpoint\":\"https://s3.example.com\","
          "\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\"}", NULL, 0, &r) < 0);
    CHECK("trailing slash trimmed", parse("{\"endpoint\":\"https://h.example/\",\"bucket\":\"bk1\","
          "\"access_key\":\"AK\",\"secret_key\":\"SK\"}", NULL, 1, &r) == 0 && !strcmp(r.endpoint, "https://h.example"));
    const char *bad[] = {
        "{\"endpoint\":\"http://10.0.0.5\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\"}",
        "{\"endpoint\":\"http://s3.example.com\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\",\"allow_plain_http\":true}",
        "{\"endpoint\":\"https://u:p@h\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\"}",
        "{\"endpoint\":\"https://h/p\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\"}",
        "{\"endpoint\":\"https://h?x\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\"}",
        "{\"endpoint\":\"ftp://h\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\"}",
        "{\"endpoint\":\"https://h\",\"bucket\":\"B1\",\"access_key\":\"AK\",\"secret_key\":\"SK\"}",
        "{\"endpoint\":\"https://h\",\"bucket\":\"bk1\",\"access_key\":\"A K\",\"secret_key\":\"SK\"}",
        "{\"endpoint\":\"https://h\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"S\\nK\"}",
        "{\"endpoint\":\"https://h\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\",\"region\":\"US\"}",
        "{\"endpoint\":\"https://h\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\",\"verify_tls\":false}",
        "{\"endpoint\":\"https://h\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\",\"verify_tls\":\"no\"}",
        "{\"endpoint\":\"https://h\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\",\"addressing\":\"dns\"}",
        "{\"endpoint\":\"https://h\",\"bucket\":\"a.b\",\"access_key\":\"AK\",\"secret_key\":\"SK\",\"addressing\":\"virtual\"}",
        "{\"endpoint\":\"https://h\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\",\"prefix\":\"a\\r\\nb\"}",
        "{\"endpoint\":\"https://h\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\",\"storage_class\":\"x y\"}",
        "{\"endpoint\":\"https://h\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\",\"extra\":1}",
        "{\"endpoint\":\"https://h\",\"bucket\":\"bk1\",\"access_key\":\"AK\"}",
        "{\"endpoint\":\"https://h\",\"bucket\":\"bk1\"}",
        "[]", "", "{", "null",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
        char nm[64];
        snprintf(nm, sizeof(nm), "bad rule %zu refused", i);
        CHECK(nm, parse(bad[i], NULL, 1, &r) < 0);
    }
    CHECK("plain http to a private host with opt-in", parse("{\"endpoint\":\"http://192.168.1.20:9000\","
          "\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\",\"allow_plain_http\":true}", NULL, 1, &r) == 0);
    CHECK("verify_tls false on a private host", parse("{\"endpoint\":\"https://[fd00::1]:9443\","
          "\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"SK\",\"verify_tls\":false}", NULL, 1, &r) == 0);
    CHECK("loopback v6 is private", parse("{\"endpoint\":\"http://[::1]:9000\",\"bucket\":\"bk1\","
          "\"access_key\":\"AK\",\"secret_key\":\"SK\",\"allow_plain_http\":true}", NULL, 1, &r) == 0);
    CHECK("172.32 is not private", parse("{\"endpoint\":\"http://172.32.0.1\",\"bucket\":\"bk1\","
          "\"access_key\":\"AK\",\"secret_key\":\"SK\",\"allow_plain_http\":true}", NULL, 1, &r) < 0);
    parse("{\"endpoint\":\"https://h\",\"bucket\":\"bk1\",\"access_key\":\"AK\",\"secret_key\":\"OLDSECRET\"}", NULL, 1, &old);
    CHECK("secret kept when omitted, same key", parse("{\"endpoint\":\"https://h2\",\"bucket\":\"bk2\","
          "\"access_key\":\"AK\"}", &old, 1, &r) == 0 && !strcmp(r.secret_key, "OLDSECRET"));
    CHECK("secret not carried to another key", parse("{\"endpoint\":\"https://h2\",\"bucket\":\"bk2\","
          "\"access_key\":\"AK2\"}", &old, 1, &r) < 0);
    CHECK("secret_key_set from GET output is tolerated", parse("{\"endpoint\":\"https://h\",\"bucket\":\"bk1\","
          "\"access_key\":\"AK\",\"secret_key_set\":true}", &old, 1, &r) == 0);
}

static const char *RULE_SEEDS[] = {
    "{\"endpoint\":\"https://s3.eu-central-003.backblazeb2.com\",\"region\":\"eu-central-003\","
    "\"bucket\":\"nas-photos\",\"access_key\":\"K003abc\",\"secret_key\":\"K003secret\",\"prefix\":\"p/\","
    "\"addressing\":\"virtual\",\"verify_tls\":true,\"deletes\":false,\"storage_class\":\"STANDARD_IA\"}",
    "{\"endpoint\":\"http://127.0.0.1:9000\",\"bucket\":\"rep\",\"access_key\":\"a\",\"secret_key\":\"b\","
    "\"allow_plain_http\":true}",
};

static void fuzz(long iters) {
    static uint8_t buf[8192];
    repl_rule_t r, old;
    memset(&old, 0, sizeof(old));
    strcpy(old.access_key, "a");
    strcpy(old.secret_key, "b");
    long ok_rules = 0, ok_recs = 0;
    for (long it = 0; it < iters; it++) {
        size_t n;
        if (it & 1) {
            const char *seed = RULE_SEEDS[rnd() % 2];
            n = strlen(seed);
            memcpy(buf, seed, n);
            if (it % 10 == 9) { n = rnd() % 600; for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)rnd(); }
            else for (int m = 1 + (int)(rnd() % 6); m-- && n;) {
                size_t at = rnd() % n;
                switch (rnd() % 4) {
                case 0: buf[at] = (uint8_t)rnd(); break;
                case 1: n = at; break;
                case 2: if (n < sizeof(buf) - 1) { memmove(buf + at + 1, buf + at, n - at); buf[at] = "\"{}[],:\\0"[rnd() % 9]; n++; } break;
                default: memmove(buf + at, buf + at + 1, n - at - 1); n--; break;
                }
            }
            char err[300];
            if (repl_rule_parse((const char *)buf, n, (it & 2) ? &old : NULL, (int)(it & 4), &r, err, sizeof(err)) == 0) ok_rules++;
        } else {
            repl_rec_t rec = { .seq = rnd(), .mtime_ms = rnd(), .op = 1 + (int)(rnd() % 2), .key_len = 1 + rnd() % 64 };
            for (size_t i = 0; i < rec.key_len; i++) rec.key[i] = (char)(1 + rnd() % 255);
            n = repl_rec_encode(&rec, buf, sizeof(buf));
            if (it % 10 == 8) { n = rnd() % 200; for (size_t i = 0; i < n; i++) buf[i] = (uint8_t)rnd(); }
            else if (it % 3) { int m = 1 + (int)(rnd() % 3); while (m--) buf[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8)); }
            repl_rec_t out;
            long k = repl_rec_decode(buf, n, &out);
            if (k > 0) { ok_recs++; if ((size_t)k > n || out.key_len > REPL_KEY_MAX) { fail++; printf("FAIL: decode overran\n"); } }
        }
    }
    printf("fuzz: %ld iterations, %ld rules and %ld records accepted\n", iters, ok_rules, ok_recs);
}

int main(int argc, char **argv) {
    t_records();
    t_rules();
    fuzz(argc > 1 ? atol(argv[1]) : 50000);
    printf("===== %d passed, %d failed =====\n", pass, fail);
    return fail ? 1 : 0;
}
