/* tests/test_sigv4.c — unit tests for SigV4 primitives
 *
 * Vectors are from AWS's official docs:
 *   https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
 *   https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html
 *
 * The signing-key derivation example below uses the canonical AWS
 * worked example from the IAM "Examples of how to derive a signing key"
 * page, which has been stable since 2012:
 *
 *   secret    = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
 *   date      = "20120215"
 *   region    = "us-east-1"
 *   service   = "iam"
 *   kSigning hex =
 *     f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d
 */

#include "sigv4.h"
#include "conn.h"
#include "s3.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* These are the test hooks declared in sigv4.c when SIGV4_TESTING is set.
 * We declare them here rather than in sigv4.h to keep the public header
 * clean. The build system compiles sigv4.c with -DSIGV4_TESTING for this
 * test binary. */
int  sigv4_test_canon_query (const char *q, size_t q_n, char *out, size_t cap);
int  sigv4_test_pct_encode  (const char *in, size_t in_n, char *out, size_t cap);
int  sigv4_test_pct_decode  (const char *in, size_t in_n, char *out, size_t cap);
int  sigv4_test_trim_collapse(const char *in, size_t in_n, char *out, size_t cap);
void sigv4_test_derive_key  (const char *secret, size_t s_n,
                             const char *date, size_t d_n,
                             const char *region, size_t r_n,
                             const char *service, size_t srv_n,
                             uint8_t out[32]);
void sigv4_test_sha256      (const void *in, size_t n, uint8_t out[32]);
void sigv4_test_hex_encode  (const uint8_t *in, size_t n, char *out);

/* Body-hash streaming API (declared in sigv4.h, but using void* to keep
 * OpenSSL out of the public API). */
void *sigv4_body_hash_begin(void);
void  sigv4_body_hash_update(void *ctx, const void *data, size_t n);
int   sigv4_body_hash_verify(void *ctx, const char expected[64]);
void  sigv4_body_hash_free(void *ctx);

/* ---------------------------------------------------------------- */

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) do {                                       \
    if (cond) { g_pass++; }                                         \
    else { fprintf(stderr, "FAIL: %s (%s:%d)\n",                    \
                   msg, __FILE__, __LINE__); g_fail++; }            \
} while (0)

#define CHECK_EQ_STR(got, got_n, want, msg) do {                    \
    int _ok = ((got_n) == (int)strlen(want)                         \
               && memcmp((got), (want), (got_n)) == 0);             \
    if (_ok) { g_pass++; }                                          \
    else { fprintf(stderr, "FAIL: %s\n  want: '%s'\n  got:  '%.*s'\n",\
                   msg, want, got_n, got); g_fail++; }              \
} while (0)

#define CHECK_EQ_HEX(got, want_hex, msg) do {                       \
    char _hex[65];                                                  \
    sigv4_test_hex_encode(got, 32, _hex); _hex[64] = 0;             \
    if (strcmp(_hex, want_hex) == 0) { g_pass++; }                  \
    else { fprintf(stderr, "FAIL: %s\n  want: %s\n  got:  %s\n",    \
                   msg, want_hex, _hex); g_fail++; }                \
} while (0)

/* ---------------------------------------------------------------- */
/* Primitives                                                       */
/* ---------------------------------------------------------------- */

static void t_sha256_empty(void) {
    /* Well-known SHA-256("") */
    uint8_t out[32];
    sigv4_test_sha256("", 0, out);
    CHECK_EQ_HEX(out,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "sha256 of empty string");
}

static void t_sha256_abc(void) {
    /* Well-known SHA-256("abc") */
    uint8_t out[32];
    sigv4_test_sha256("abc", 3, out);
    CHECK_EQ_HEX(out,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sha256 of 'abc'");
}

static void t_pct_encode(void) {
    char out[64];
    int n = sigv4_test_pct_encode("hello world", 11, out, sizeof(out));
    CHECK_EQ_STR(out, n, "hello%20world", "pct encode space");

    n = sigv4_test_pct_encode("a/b", 3, out, sizeof(out));
    CHECK_EQ_STR(out, n, "a%2Fb", "pct encode slash (strict mode)");

    n = sigv4_test_pct_encode("abcXYZ-_.~", 10, out, sizeof(out));
    CHECK_EQ_STR(out, n, "abcXYZ-_.~", "unreserved chars unchanged");

    n = sigv4_test_pct_encode("a=b&c", 5, out, sizeof(out));
    CHECK_EQ_STR(out, n, "a%3Db%26c", "pct encode reserved");
}

static void t_pct_decode(void) {
    char out[64];
    int n = sigv4_test_pct_decode("hello%20world", 13, out, sizeof(out));
    CHECK_EQ_STR(out, n, "hello world", "pct decode %20");

    n = sigv4_test_pct_decode("a%2Fb", 5, out, sizeof(out));
    CHECK_EQ_STR(out, n, "a/b", "pct decode slash");

    n = sigv4_test_pct_decode("nofangs", 7, out, sizeof(out));
    CHECK_EQ_STR(out, n, "nofangs", "pct decode no escapes");

    /* Malformed escapes left as-is. */
    n = sigv4_test_pct_decode("a%2", 3, out, sizeof(out));
    CHECK_EQ_STR(out, n, "a%2", "pct decode malformed left as-is");
}

static void t_trim_collapse(void) {
    char out[64];
    int n = sigv4_test_trim_collapse("  hello  world  ", 16, out, sizeof(out));
    CHECK_EQ_STR(out, n, "hello world", "trim and collapse");

    n = sigv4_test_trim_collapse("\t a\t\tb \tc \t", 11, out, sizeof(out));
    CHECK_EQ_STR(out, n, "a b c", "tabs and runs");

    n = sigv4_test_trim_collapse("nopadding", 9, out, sizeof(out));
    CHECK_EQ_STR(out, n, "nopadding", "no whitespace");

    n = sigv4_test_trim_collapse("    ", 4, out, sizeof(out));
    CHECK_EQ_STR(out, n, "", "all whitespace");
}

/* ---------------------------------------------------------------- */
/* Canonical query                                                  */
/* ---------------------------------------------------------------- */

static void t_canon_query_empty(void) {
    char out[64];
    int n = sigv4_test_canon_query("", 0, out, sizeof(out));
    CHECK(n == 0, "empty query produces empty string");
}

static void t_canon_query_single(void) {
    char out[64];
    int n = sigv4_test_canon_query("a=1", 3, out, sizeof(out));
    CHECK_EQ_STR(out, n, "a=1", "single pair unchanged");
}

static void t_canon_query_sort(void) {
    char out[64];
    int n = sigv4_test_canon_query("b=2&a=1", 7, out, sizeof(out));
    CHECK_EQ_STR(out, n, "a=1&b=2", "sorted by key");
}

static void t_canon_query_reencode(void) {
    char out[64];
    /* ?key=hello world&other=a/b — value with space, value with slash */
    int n = sigv4_test_canon_query("key=hello%20world&other=a%2Fb", 29,
                                   out, sizeof(out));
    CHECK_EQ_STR(out, n, "key=hello%20world&other=a%2Fb",
                 "decode + sort + re-encode preserves canonical form");
}

static void t_canon_query_no_value(void) {
    char out[64];
    int n = sigv4_test_canon_query("acl=&policy=", 12, out, sizeof(out));
    CHECK_EQ_STR(out, n, "acl=&policy=", "empty values keep '='");
}

static void t_canon_query_aws_example(void) {
    /* From AWS S3 SigV4 docs:
     *   "prefix=somePrefix&marker=someMarker&max-keys=20"
     * sorts to:
     *   "marker=someMarker&max-keys=20&prefix=somePrefix"
     */
    const char *in = "prefix=somePrefix&marker=someMarker&max-keys=20";
    char out[256];
    int n = sigv4_test_canon_query(in, strlen(in), out, sizeof(out));
    CHECK_EQ_STR(out, n,
                 "marker=someMarker&max-keys=20&prefix=somePrefix",
                 "AWS S3 docs example");
}

/* ---------------------------------------------------------------- */
/* Signing key derivation (the canonical worked example)            */
/* ---------------------------------------------------------------- */

static void t_signing_key_aws_iam_example(void) {
    /* AWS IAM docs worked example, byte-exact. */
    const char *secret  = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const char *date    = "20120215";
    const char *region  = "us-east-1";
    const char *service = "iam";

    uint8_t kSigning[32];
    sigv4_test_derive_key(secret, strlen(secret),
                          date, strlen(date),
                          region, strlen(region),
                          service, strlen(service),
                          kSigning);

    CHECK_EQ_HEX(kSigning,
        "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d",
        "AWS IAM signing key example");
}

/* ---------------------------------------------------------------- */
/* End-to-end: full sigv4_verify against a known-good request       */
/* ---------------------------------------------------------------- */

/* Ground-truth vector generated by botocore (the AWS Python SDK) for:
 *
 *   GET http://examplebucket.s3.amazonaws.com/test.txt
 *   Range: bytes=0-9
 *   X-Amz-Date: 20130524T000000Z
 *   (no x-amz-content-sha256 — botocore omits it for GET)
 *
 *   access_key = "AKIAIOSFODNN7EXAMPLE"
 *   secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
 *
 * Authorization: AWS4-HMAC-SHA256
 *   Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,
 *   SignedHeaders=host;range;x-amz-date,
 *   Signature=5d66fb2d81386a1a76b0d6d11ff033d15eef06699e0706d32b211f38fde2462c
 *
 * This is what a real AWS SDK produces, not a hand-transcribed docs
 * example. */
static void t_verify_aws_s3_get_example(void) {
    sigv4_verifier_t *v = sigv4_create();
    sigv4_add_cred(v, "AKIAIOSFODNN7EXAMPLE",
                      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    sigv4_set_clock(v, 1369353600);  /* 20130524T000000Z */

    conn_t c = {0};
    c.req.method = (s3_str_t){ "GET", 3 };
    c.req.path   = (s3_str_t){ "/test.txt", 9 };
    c.req.query  = (s3_str_t){ NULL, 0 };

    static const struct {
        const char *k;
        const char *val;
    } H[] = {
        { "host",          "examplebucket.s3.amazonaws.com" },
        { "range",         "bytes=0-9" },
        { "x-amz-date",    "20130524T000000Z" },
        { "authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=5d66fb2d81386a1a76b0d6d11ff033d15eef06699e0706d32b211f38fde2462c" },
    };
    size_t nh = sizeof(H)/sizeof(H[0]);
    for (size_t i = 0; i < nh; i++) {
        c.req.headers[i].k = (s3_str_t){ H[i].k, strlen(H[i].k) };
        c.req.headers[i].v = (s3_str_t){ H[i].val, strlen(H[i].val) };
    }
    c.req.n_headers = nh;

    s3_err_t e = sigv4_verify(v, &c);
    CHECK(e == S3_OK, "AWS S3 GET (botocore vector) verifies");
    if (e != S3_OK) fprintf(stderr, "  got s3_err=%d\n", (int)e);

    sigv4_destroy(v);
}

static void t_verify_wrong_signature(void) {
    sigv4_verifier_t *v = sigv4_create();
    sigv4_add_cred(v, "AKIAIOSFODNN7EXAMPLE",
                      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    sigv4_set_clock(v, 1369353600);

    conn_t c = {0};
    c.req.method = (s3_str_t){ "GET", 3 };
    c.req.path   = (s3_str_t){ "/test.txt", 9 };

    static const struct { const char *k, *v; } H[] = {
        { "host",          "examplebucket.s3.amazonaws.com" },
        { "range",         "bytes=0-9" },
        { "x-amz-date",    "20130524T000000Z" },
        /* Last hex digit changed from 'c' to 'd' */
        { "authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-date, Signature=5d66fb2d81386a1a76b0d6d11ff033d15eef06699e0706d32b211f38fde2462d" },
    };
    for (size_t i = 0; i < 4; i++) {
        c.req.headers[i].k = (s3_str_t){ H[i].k, strlen(H[i].k) };
        c.req.headers[i].v = (s3_str_t){ H[i].v, strlen(H[i].v) };
    }
    c.req.n_headers = 4;

    s3_err_t e = sigv4_verify(v, &c);
    CHECK(e == S3_ERR_SIGNATURE_DOES_NOT_MATCH,
          "tampered signature → SignatureDoesNotMatch");
    sigv4_destroy(v);
}

static void t_verify_unknown_access_key(void) {
    sigv4_verifier_t *v = sigv4_create();
    sigv4_add_cred(v, "AKIAOTHER", "secret");
    sigv4_set_clock(v, 1369353600);

    conn_t c = {0};
    c.req.method = (s3_str_t){ "GET", 3 };
    c.req.path   = (s3_str_t){ "/test.txt", 9 };

    static const struct { const char *k, *v; } H[] = {
        { "host",                 "examplebucket.s3.amazonaws.com" },
        { "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "x-amz-date",           "20130524T000000Z" },
        { "authorization",        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=0000000000000000000000000000000000000000000000000000000000000000" },
    };
    for (size_t i = 0; i < 4; i++) {
        c.req.headers[i].k = (s3_str_t){ H[i].k, strlen(H[i].k) };
        c.req.headers[i].v = (s3_str_t){ H[i].v, strlen(H[i].v) };
    }
    c.req.n_headers = 4;

    s3_err_t e = sigv4_verify(v, &c);
    CHECK(e == S3_ERR_ACCESS_DENIED, "unknown access key → AccessDenied");
    sigv4_destroy(v);
}

static void t_verify_skewed_time(void) {
    sigv4_verifier_t *v = sigv4_create();
    sigv4_add_cred(v, "AKIAIOSFODNN7EXAMPLE",
                      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    /* Server clock is one hour off from the request. */
    sigv4_set_clock(v, 1369353600 + 3600);

    conn_t c = {0};
    c.req.method = (s3_str_t){ "GET", 3 };
    c.req.path   = (s3_str_t){ "/test.txt", 9 };

    static const struct { const char *k, *v; } H[] = {
        { "host",                 "examplebucket.s3.amazonaws.com" },
        { "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "x-amz-date",           "20130524T000000Z" },
        { "authorization",        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=0000000000000000000000000000000000000000000000000000000000000000" },
    };
    for (size_t i = 0; i < 4; i++) {
        c.req.headers[i].k = (s3_str_t){ H[i].k, strlen(H[i].k) };
        c.req.headers[i].v = (s3_str_t){ H[i].v, strlen(H[i].v) };
    }
    c.req.n_headers = 4;

    s3_err_t e = sigv4_verify(v, &c);
    CHECK(e == S3_ERR_REQUEST_TIME_TOO_SKEWED,
          "1h skew → RequestTimeTooSkewed");
    sigv4_destroy(v);
}

static void t_verify_missing_authorization(void) {
    sigv4_verifier_t *v = sigv4_create();
    sigv4_add_cred(v, "AKIA", "s");

    conn_t c = {0};
    c.req.method = (s3_str_t){ "GET", 3 };
    c.req.path   = (s3_str_t){ "/", 1 };
    c.req.headers[0].k = (s3_str_t){ "host", 4 };
    c.req.headers[0].v = (s3_str_t){ "x.example", 9 };
    c.req.n_headers = 1;

    s3_err_t e = sigv4_verify(v, &c);
    CHECK(e == S3_ERR_ACCESS_DENIED, "missing Authorization → AccessDenied");
    sigv4_destroy(v);
}

static void t_verify_malformed_authorization(void) {
    sigv4_verifier_t *v = sigv4_create();
    sigv4_add_cred(v, "AKIA", "s");

    conn_t c = {0};
    c.req.method = (s3_str_t){ "GET", 3 };
    c.req.path   = (s3_str_t){ "/", 1 };
    static const struct { const char *k, *v; } H[] = {
        { "host",          "x.example" },
        { "x-amz-date",    "20130524T000000Z" },
        { "authorization", "Bearer xyz" },         /* not SigV4 */
    };
    for (size_t i = 0; i < 3; i++) {
        c.req.headers[i].k = (s3_str_t){ H[i].k, strlen(H[i].k) };
        c.req.headers[i].v = (s3_str_t){ H[i].v, strlen(H[i].v) };
    }
    c.req.n_headers = 3;

    s3_err_t e = sigv4_verify(v, &c);
    CHECK(e == S3_ERR_ACCESS_DENIED, "malformed Authorization → AccessDenied");
    sigv4_destroy(v);
}

/* ---------------------------------------------------------------- */
/* Additional botocore-generated vectors                            */
/* ---------------------------------------------------------------- */

/* All three vectors below were generated by botocore at fixed time
 * 20240115T120000Z (Unix 1705320000), credentials as in the IAM
 * worked example, region us-east-1, service s3. */

#define BOTOCORE_FIXED_TIME 1705320000

static void t_verify_put_with_body(void) {
    sigv4_verifier_t *v = sigv4_create();
    sigv4_add_cred(v, "AKIAIOSFODNN7EXAMPLE",
                      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    sigv4_set_clock(v, BOTOCORE_FIXED_TIME);

    conn_t c = {0};
    c.req.method = (s3_str_t){ "PUT", 3 };
    c.req.path   = (s3_str_t){ "/myobject", 9 };

    static const struct { const char *k, *v; } H[] = {
        { "host",                 "mybucket.s3.amazonaws.com" },
        { "content-type",         "text/plain" },
        { "x-amz-content-sha256", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" },
        { "x-amz-date",           "20240115T120000Z" },
        { "authorization",        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20240115/us-east-1/s3/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=dd77ca52918e39d0be56902320afea5c954ed33abf374dc0713d2639dbb95c6c" },
    };
    for (size_t i = 0; i < 5; i++) {
        c.req.headers[i].k = (s3_str_t){ H[i].k, strlen(H[i].k) };
        c.req.headers[i].v = (s3_str_t){ H[i].v, strlen(H[i].v) };
    }
    c.req.n_headers = 5;

    s3_err_t e = sigv4_verify(v, &c);
    CHECK(e == S3_OK, "S3SigV4Auth PUT-with-body verifies");
    if (e != S3_OK) fprintf(stderr, "  got s3_err=%d\n", (int)e);
    sigv4_destroy(v);
}

static void t_verify_get_with_query(void) {
    sigv4_verifier_t *v = sigv4_create();
    sigv4_add_cred(v, "AKIAIOSFODNN7EXAMPLE",
                      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    sigv4_set_clock(v, BOTOCORE_FIXED_TIME);

    conn_t c = {0};
    c.req.method = (s3_str_t){ "GET", 3 };
    c.req.path   = (s3_str_t){ "/", 1 };
    c.req.query  = (s3_str_t){ "prefix=foo&max-keys=10", 22 };

    static const struct { const char *k, *v; } H[] = {
        { "host",                 "mybucket.s3.amazonaws.com" },
        { "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "x-amz-date",           "20240115T120000Z" },
        { "authorization",        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20240115/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=02ecac44951e6df32cd7d52ba8a5e08c7294cc42e2bb91103dfc4b00a22c5a03" },
    };
    for (size_t i = 0; i < 4; i++) {
        c.req.headers[i].k = (s3_str_t){ H[i].k, strlen(H[i].k) };
        c.req.headers[i].v = (s3_str_t){ H[i].v, strlen(H[i].v) };
    }
    c.req.n_headers = 4;

    s3_err_t e = sigv4_verify(v, &c);
    CHECK(e == S3_OK, "S3SigV4Auth GET-with-query verifies");
    if (e != S3_OK) fprintf(stderr, "  got s3_err=%d\n", (int)e);
    sigv4_destroy(v);
}

static void t_verify_delete(void) {
    sigv4_verifier_t *v = sigv4_create();
    sigv4_add_cred(v, "AKIAIOSFODNN7EXAMPLE",
                      "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY");
    sigv4_set_clock(v, BOTOCORE_FIXED_TIME);

    conn_t c = {0};
    c.req.method = (s3_str_t){ "DELETE", 6 };
    c.req.path   = (s3_str_t){ "/key1", 5 };

    static const struct { const char *k, *v; } H[] = {
        { "host",                 "mybucket.s3.amazonaws.com" },
        { "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
        { "x-amz-date",           "20240115T120000Z" },
        { "authorization",        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20240115/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=ab4f5e25c12f1a3378abbf7fd3b43a72cc4e6fc47a6e346811ec9edee1054caa" },
    };
    for (size_t i = 0; i < 4; i++) {
        c.req.headers[i].k = (s3_str_t){ H[i].k, strlen(H[i].k) };
        c.req.headers[i].v = (s3_str_t){ H[i].v, strlen(H[i].v) };
    }
    c.req.n_headers = 4;

    s3_err_t e = sigv4_verify(v, &c);
    CHECK(e == S3_OK, "S3SigV4Auth DELETE verifies");
    if (e != S3_OK) fprintf(stderr, "  got s3_err=%d\n", (int)e);
    sigv4_destroy(v);
}

/* ---------------------------------------------------------------- */
/* Body-hash streaming API                                          */
/* ---------------------------------------------------------------- */

static void t_body_hash_empty(void) {
    void *ctx = sigv4_body_hash_begin();
    /* SHA-256("") */
    int ok = sigv4_body_hash_verify(ctx,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    sigv4_body_hash_free(ctx);
    CHECK(ok, "body hash empty matches SHA256(\"\")");
}

static void t_body_hash_single_chunk(void) {
    void *ctx = sigv4_body_hash_begin();
    sigv4_body_hash_update(ctx, "hello world", 11);
    int ok = sigv4_body_hash_verify(ctx,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    sigv4_body_hash_free(ctx);
    CHECK(ok, "body hash single chunk matches SHA256(\"hello world\")");
}

static void t_body_hash_multiple_chunks(void) {
    /* Verify streaming updates across multiple chunks yield the same
     * hash as a single update — the property that makes the on_body
     * callback correct under partial reads. */
    void *ctx = sigv4_body_hash_begin();
    sigv4_body_hash_update(ctx, "hello", 5);
    sigv4_body_hash_update(ctx, " ", 1);
    sigv4_body_hash_update(ctx, "world", 5);
    int ok = sigv4_body_hash_verify(ctx,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    sigv4_body_hash_free(ctx);
    CHECK(ok, "body hash chunked matches single-buffer hash");
}

static void t_body_hash_mismatch(void) {
    void *ctx = sigv4_body_hash_begin();
    sigv4_body_hash_update(ctx, "different bytes", 15);
    int ok = sigv4_body_hash_verify(ctx,
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    sigv4_body_hash_free(ctx);
    CHECK(!ok, "body hash mismatch detected");
}

/* ---------------------------------------------------------------- */

int main(void) {
    t_sha256_empty();
    t_sha256_abc();
    t_pct_encode();
    t_pct_decode();
    t_trim_collapse();
    t_canon_query_empty();
    t_canon_query_single();
    t_canon_query_sort();
    t_canon_query_reencode();
    t_canon_query_no_value();
    t_canon_query_aws_example();
    t_signing_key_aws_iam_example();
    t_verify_aws_s3_get_example();
    t_verify_wrong_signature();
    t_verify_unknown_access_key();
    t_verify_skewed_time();
    t_verify_missing_authorization();
    t_verify_malformed_authorization();
    t_verify_put_with_body();
    t_verify_get_with_query();
    t_verify_delete();
    t_body_hash_empty();
    t_body_hash_single_chunk();
    t_body_hash_multiple_chunks();
    t_body_hash_mismatch();

    fprintf(stderr, "===== %d passed, %d failed =====\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
