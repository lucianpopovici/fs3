/* tests/test_policy.c — bucket policy compiler + evaluator (item 9):
 * grammar strictness, deny precedence, wildcards, prefix resources,
 * conditions, public-access detection; then a mutation fuzz. */
#include "policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pass, fail;
#define CHECK(c, m) do { if (c) pass++; else { fail++; \
    fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, m); } } while (0)

static const s3_str_t B = { "bk", 2 };

static policy_t *comp(const char *j, policy_check_t *chk) {
    return policy_compile(j, strlen(j), B, chk);
}

static policy_effect_t ev(const policy_t *p, const char *user, const char *act,
                          const char *key, const char *ip, int secure) {
    policy_req_t r = { .user = user, .action = act, .bucket = B,
                       .key = { key, strlen(key) }, .source_ip = ip, .secure = secure };
    return policy_eval(p, &r);
}

#define S(x) "{\"Version\":\"2012-10-17\",\"Statement\":[" x "]}"

int main(int argc, char **argv) {
    policy_check_t chk;
    /* Grammar. */
    CHECK(!comp("{\"Version\":\"2008-10-17\",\"Statement\":[]}", &chk), "old version");
    CHECK(!comp(S("{\"Effect\":\"Allow\",\"NotPrincipal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::bk\"}"), &chk), "NotPrincipal");
    CHECK(!comp(S("{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::other/*\"}"), &chk), "other bucket");
    CHECK(!comp(S("{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::*\"}"), &chk), "bucket wildcard");
    CHECK(!comp(S("{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::bk\","
                  "\"Condition\":{\"DateGreaterThan\":{\"aws:CurrentTime\":\"x\"}}}"), &chk), "unknown operator");
    CHECK(!comp(S("{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::bk\","
                  "\"Condition\":{\"IpAddress\":{\"aws:SourceIp\":\"300.1.1.1/8\"}}}"), &chk), "bad CIDR");
    CHECK(!comp(S("{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"iam:*\",\"Resource\":\"arn:aws:s3:::bk\"}"), &chk), "non-s3 action");
    CHECK(!comp(S("{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::bk\",\"Effect\":\"Deny\"}"), &chk), "duplicate key");
    CHECK(!comp(S("{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:****?*\",\"Resource\":\"arn:aws:s3:::bk\"}"), &chk), "too many stars");

    /* Public read: anonymous GetObject under public/. */
    policy_t *p = comp(S("{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\","
                         "\"Resource\":\"arn:aws:s3:::bk/public/*\"}"), &chk);
    CHECK(p && chk.public_read && !chk.public_write, "public read detected");
    CHECK(ev(p, "", "s3:GetObject", "public/a.txt", NULL, 0) == POLICY_ALLOW, "anon get public");
    CHECK(ev(p, "", "s3:GetObject", "private/a.txt", NULL, 0) == POLICY_NONE, "anon get private");
    CHECK(ev(p, "", "s3:PutObject", "public/a.txt", NULL, 0) == POLICY_NONE, "anon put");
    policy_free(p);

    p = comp(S("{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"*\"},\"Action\":\"s3:*\",\"Resource\":\"arn:aws:s3:::bk/*\"}"), &chk);
    CHECK(p && chk.public_write, "public write detected (s3:*)");
    policy_free(p);

    /* Users, deny precedence, NotAction, conditions. */
    p = comp(S(
        "{\"Sid\":\"share\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"arn:aws:iam:::user/bob\",\"carol\"]},"
        " \"Action\":[\"s3:Get*\",\"s3:ListBucket\"],\"Resource\":[\"arn:aws:s3:::bk\",\"arn:aws:s3:::bk/home/bob/*\"]},"
        "{\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::bk\",\"arn:aws:s3:::bk/*\"],"
        " \"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}},"
        "{\"Effect\":\"Deny\",\"Principal\":{\"AWS\":\"carol\"},\"NotAction\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::bk/*\"},"
        "{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"dave\"},\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::bk/*\","
        " \"Condition\":{\"IpAddress\":{\"aws:SourceIp\":[\"10.0.0.0/8\",\"2001:db8::/32\"]}}}"), &chk);
    CHECK(p != NULL, "compiles");
    CHECK(!chk.public_read, "deny-only * is not public");
    CHECK(ev(p, "bob", "s3:GetObject", "home/bob/x", "1.2.3.4", 1) == POLICY_ALLOW, "bob get own prefix");
    CHECK(ev(p, "bob", "s3:GetObject", "home/alice/x", "1.2.3.4", 1) == POLICY_NONE, "bob other prefix");
    CHECK(ev(p, "bob", "s3:GetObject", "home/bob/x", "1.2.3.4", 0) == POLICY_DENY, "deny non-TLS wins");
    CHECK(ev(p, "bob", "s3:ListBucket", "", "1.2.3.4", 1) == POLICY_ALLOW, "bucket ARN");
    CHECK(ev(p, "carol", "s3:PutObject", "home/bob/x", NULL, 1) == POLICY_DENY, "NotAction deny");
    CHECK(ev(p, "carol", "s3:GetObject", "home/bob/x", NULL, 1) == POLICY_ALLOW, "carol get");
    CHECK(ev(p, "dave", "s3:GetObject", "a", "10.1.2.3", 1) == POLICY_ALLOW, "ip in range");
    CHECK(ev(p, "dave", "s3:GetObject", "a", "::ffff:10.1.2.3", 1) == POLICY_ALLOW, "v4-mapped v6");
    CHECK(ev(p, "dave", "s3:GetObject", "a", "2001:db8::1", 1) == POLICY_ALLOW, "v6 range");
    CHECK(ev(p, "dave", "s3:GetObject", "a", "11.1.2.3", 1) == POLICY_NONE, "ip out of range");
    CHECK(ev(p, "dave", "s3:GetObject", "a", NULL, 1) == POLICY_NONE, "no ip");
    policy_free(p);

    CHECK(policy_glob("s3:Get*", (s3_str_t){ "s3:GetObject", 12 }), "glob");
    CHECK(!policy_glob("s3:Get*Acl", (s3_str_t){ "s3:GetObject", 12 }), "glob suffix");
    CHECK(policy_glob("a?c", (s3_str_t){ "abc", 3 }), "glob ?");
    {
        char big[5000];
        memset(big, 'a', sizeof(big));
        CHECK(!policy_glob("*a*a*a*b", (s3_str_t){ big, sizeof(big) }), "pathological glob terminates");
    }

    /* Fuzz: mutated policies never crash. */
    long iters = argc > 1 ? atol(argv[1]) : 20000;
    const char *seed = S("{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"bob\"]},\"Action\":[\"s3:Get*\"],"
                         "\"Resource\":\"arn:aws:s3:::bk/home/*\",\"Condition\":{\"IpAddress\":"
                         "{\"aws:SourceIp\":\"10.0.0.0/8\"},\"StringLike\":{\"s3:prefix\":\"home/*\"}}}");
    size_t sn = strlen(seed);
    char buf[2048];
    unsigned long long r = 99;
    for (long it = 0; it < iters; it++) {
        memcpy(buf, seed, sn);
        for (int m = 0; m < 1 + (int)(it % 4); m++) {
            r ^= r << 13; r ^= r >> 7; r ^= r << 17;
            buf[r % sn] = (r & 1) ? (char)(r >> 9) : "{}[]\":,*?/"[(r >> 9) % 10];
        }
        policy_t *q = policy_compile(buf, sn, B, NULL);
        if (q) { ev(q, "bob", "s3:GetObject", "home/x", "10.0.0.1", 1); policy_free(q); }
    }
    printf("===== policy: %d passed, %d failed (%ld fuzz iterations) =====\n", pass, fail, iters);
    return fail != 0;
}
