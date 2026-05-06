/* src/sigv4.c — AWS Signature V4 (header-mode) verification
 *
 * Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html
 *            (the "Examples of how to derive a signing key" page)
 *
 * Pipeline:
 *   1. Parse the Authorization header for credential, signed_headers, signature.
 *   2. Build the canonical request:
 *        METHOD\n
 *        canonical-uri\n
 *        canonical-query-string\n
 *        canonical-headers\n           (one per line, ends with extra \n)
 *        signed-headers\n              (semicolon-joined header names)
 *        x-amz-content-sha256-value    (or "UNSIGNED-PAYLOAD")
 *   3. Build the string-to-sign:
 *        AWS4-HMAC-SHA256\n
 *        x-amz-date\n
 *        credential-scope\n            (date/region/service/aws4_request)
 *        SHA256(canonical-request) hex
 *   4. Derive the signing key via HMAC chain:
 *        kDate     = HMAC("AWS4" + secret, date-yyyymmdd)
 *        kRegion   = HMAC(kDate, region)
 *        kService  = HMAC(kRegion, service)
 *        kSigning  = HMAC(kService, "aws4_request")
 *   5. signature = HEX(HMAC(kSigning, string-to-sign))
 *   6. Constant-time compare with the client's claimed signature.
 *
 * Each major step is a small file-static function so it can be tested
 * in isolation against AWS's published test vectors (see test_sigv4.c).
 */

#include "sigv4.h"
#include "conn.h"
#include "log.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ===================================================================== */
/* Crypto primitives                                                      */
/* ===================================================================== */

static void sha256(const void *in, size_t in_len, uint8_t out[32]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, in, in_len);
    unsigned int n = 32;
    EVP_DigestFinal_ex(ctx, out, &n);
    EVP_MD_CTX_free(ctx);
}

static void hmac_sha256(const void *key, size_t key_len,
                        const void *msg, size_t msg_len,
                        uint8_t out[32]) {
    unsigned int n = 32;
    HMAC(EVP_sha256(),
         key, (int)key_len,
         (const unsigned char *)msg, msg_len,
         out, &n);
}

static void hex_encode(const uint8_t *in, size_t in_len, char *out) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; i++) {
        out[2*i + 0] = H[(in[i] >> 4) & 0xF];
        out[2*i + 1] = H[ in[i]       & 0xF];
    }
}

/* ===================================================================== */
/* Credential store                                                       */
/* ===================================================================== */

typedef struct cred {
    char       *access_key;
    uint8_t    *secret_key;     /* not NUL-terminated, as bytes */
    size_t      secret_len;
    struct cred *next;
} cred_t;

struct sigv4_verifier {
    cred_t   *creds;
    int64_t   fixed_now;        /* 0 = real clock */
    int       max_skew;         /* seconds */
};

sigv4_verifier_t *sigv4_create(void) {
    sigv4_verifier_t *v = calloc(1, sizeof(*v));
    if (!v) return NULL;
    v->max_skew = 900;          /* 15 minutes — AWS default */
    return v;
}

void sigv4_destroy(sigv4_verifier_t *v) {
    if (!v) return;
    cred_t *c = v->creds;
    while (c) {
        cred_t *next = c->next;
        free(c->access_key);
        if (c->secret_key) {
            /* Zero secrets before freeing. */
            OPENSSL_cleanse(c->secret_key, c->secret_len);
            free(c->secret_key);
        }
        free(c);
        c = next;
    }
    free(v);
}

int sigv4_add_cred(sigv4_verifier_t *v,
                   const char *access_key,
                   const char *secret_key) {
    if (!v || !access_key || !secret_key) return -1;
    /* Reject duplicate access keys. */
    for (cred_t *c = v->creds; c; c = c->next) {
        if (strcmp(c->access_key, access_key) == 0) return -1;
    }
    cred_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    c->access_key = strdup(access_key);
    size_t sn = strlen(secret_key);
    c->secret_key = malloc(sn);
    if (!c->access_key || !c->secret_key) {
        free(c->access_key); free(c->secret_key); free(c);
        return -1;
    }
    memcpy(c->secret_key, secret_key, sn);
    c->secret_len = sn;
    c->next = v->creds;
    v->creds = c;
    return 0;
}

void sigv4_set_clock(sigv4_verifier_t *v, int64_t fixed_now) {
    if (v) v->fixed_now = fixed_now;
}

void sigv4_set_max_skew(sigv4_verifier_t *v, int max_skew) {
    if (v && max_skew > 0) v->max_skew = max_skew;
}

static const cred_t *cred_lookup(const sigv4_verifier_t *v,
                                 const char *ak, size_t ak_len) {
    for (const cred_t *c = v->creds; c; c = c->next) {
        if (strlen(c->access_key) == ak_len
            && memcmp(c->access_key, ak, ak_len) == 0) {
            return c;
        }
    }
    return NULL;
}

/* ===================================================================== */
/* Header & encoding helpers                                              */
/* ===================================================================== */

/* Find a header by lowercase name. Returns NULL if absent. */
static const s3_str_t *hdr_lookup(const conn_t *c, const char *lc_name) {
    for (size_t i = 0; i < c->req.n_headers; i++) {
        if (s3_str_eq_lit(c->req.headers[i].k, lc_name)) {
            return &c->req.headers[i].v;
        }
    }
    return NULL;
}

static int is_unreserved(unsigned char ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
        || (ch >= '0' && ch <= '9')
        || ch == '-' || ch == '_' || ch == '.' || ch == '~';
}

/* RFC 3986 strict percent-encode for the *query string*. The `/` is
 * encoded too (S3 SigV4 query encoding rule). Returns bytes written or
 * -1 on overflow. */
static int pct_encode_strict(const char *in, size_t in_len, char *out, size_t cap) {
    static const char H[] = "0123456789ABCDEF";
    size_t o = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char ch = (unsigned char)in[i];
        if (is_unreserved(ch)) {
            if (o + 1 > cap) return -1;
            out[o++] = (char)ch;
        } else {
            if (o + 3 > cap) return -1;
            out[o++] = '%';
            out[o++] = H[(ch >> 4) & 0xF];
            out[o++] = H[ ch       & 0xF];
        }
    }
    return (int)o;
}

/* Decode percent-escapes in place into `out`. Returns bytes written.
 * Malformed escapes are left as-is. */
static int pct_decode(const char *in, size_t in_len, char *out, size_t cap) {
    size_t o = 0;
    for (size_t i = 0; i < in_len; i++) {
        if (in[i] == '%' && i + 2 < in_len
            && isxdigit((unsigned char)in[i+1])
            && isxdigit((unsigned char)in[i+2])) {
            char buf[3] = { in[i+1], in[i+2], 0 };
            unsigned long v = strtoul(buf, NULL, 16);
            if (o + 1 > cap) return -1;
            out[o++] = (char)v;
            i += 2;
        } else {
            if (o + 1 > cap) return -1;
            out[o++] = in[i];
        }
    }
    return (int)o;
}

/* Trim leading/trailing OWS (space, tab) and collapse internal runs of
 * whitespace to single spaces. RFC 7230 + AWS docs interpretation.
 * Writes to `out`, returns bytes written or -1 on overflow. */
static int trim_and_collapse_ws(const char *in, size_t in_len,
                                char *out, size_t cap) {
    size_t s = 0, e = in_len;
    while (s < e && (in[s] == ' ' || in[s] == '\t')) s++;
    while (e > s && (in[e-1] == ' ' || in[e-1] == '\t')) e--;
    size_t o = 0;
    int last_was_ws = 0;
    for (size_t i = s; i < e; i++) {
        char ch = in[i];
        if (ch == ' ' || ch == '\t') {
            if (!last_was_ws) {
                if (o + 1 > cap) return -1;
                out[o++] = ' ';
                last_was_ws = 1;
            }
        } else {
            if (o + 1 > cap) return -1;
            out[o++] = ch;
            last_was_ws = 0;
        }
    }
    return (int)o;
}

/* ===================================================================== */
/* Canonical-URI (S3 flavor: NOT double-encoded)                          */
/* ===================================================================== */

/* For S3, the canonical URI is just the URL-path portion, normalized:
 *   - leading slash preserved
 *   - already-encoded path is left encoded
 *   - empty path becomes "/"
 *   - the path is NOT decoded then re-encoded (that's the non-S3 rule)
 *
 * Returns bytes written or -1 on overflow. Per AWS docs, S3 uses the
 * "URI-encoded once" rule (vs "URI-encoded twice" for other services). */
static int canon_uri_s3(s3_str_t path, char *out, size_t cap) {
    if (path.n == 0) {
        if (cap < 1) return -1;
        out[0] = '/';
        return 1;
    }
    if (path.n > cap) return -1;
    memcpy(out, path.p, path.n);
    return (int)path.n;
}

/* ===================================================================== */
/* Canonical query string                                                 */
/* ===================================================================== */

typedef struct {
    char *k;       size_t k_n;
    char *v;       size_t v_n;
} qpair_t;

static int qpair_cmp(const void *a, const void *b) {
    const qpair_t *x = a, *y = b;
    size_t n = x->k_n < y->k_n ? x->k_n : y->k_n;
    int r = memcmp(x->k, y->k, n);
    if (r) return r;
    if (x->k_n != y->k_n) return x->k_n < y->k_n ? -1 : 1;
    /* Tiebreak on value. */
    n = x->v_n < y->v_n ? x->v_n : y->v_n;
    r = memcmp(x->v, y->v, n);
    if (r) return r;
    if (x->v_n != y->v_n) return x->v_n < y->v_n ? -1 : 1;
    return 0;
}

/* Build canonical query string into `out`. Returns bytes written or -1.
 * Uses a temporary heap buffer (the input may need decode + re-encode). */
static int build_canonical_query(s3_str_t query, char *out, size_t cap) {
    if (query.n == 0) return 0;

    /* Worst case: every byte triples after re-encode, plus the original.
     * We allocate 4× plus pair overhead; safe upper bound. */
    size_t scratch_cap = query.n * 4 + 64;
    char *scratch = malloc(scratch_cap);
    if (!scratch) return -1;

    /* Phase 1: split on '&', decode each side of '=', store qpair_t
     * pointers into scratch. Since qpair_cmp needs stable storage, we
     * lay out pairs back-to-back inside scratch. */
    size_t scratch_used = 0;
    size_t pair_cap = 16;
    size_t pair_n = 0;
    qpair_t *pairs = malloc(pair_cap * sizeof(*pairs));
    if (!pairs) { free(scratch); return -1; }

    size_t i = 0;
    while (i < query.n) {
        size_t start = i;
        while (i < query.n && query.p[i] != '&') i++;
        size_t end = i;
        /* skip the '&' */
        if (i < query.n) i++;
        if (end == start) continue; /* empty pair, ignore */

        /* Find '=' within [start, end) */
        size_t eq = start;
        while (eq < end && query.p[eq] != '=') eq++;

        size_t k_in_n = eq - start;
        size_t v_in_n = (eq < end) ? (end - eq - 1) : 0;
        const char *k_in = query.p + start;
        const char *v_in = (eq < end) ? query.p + eq + 1 : "";

        /* Decode key */
        if (scratch_used + k_in_n > scratch_cap) goto oom;
        int k_n = pct_decode(k_in, k_in_n, scratch + scratch_used, scratch_cap - scratch_used);
        if (k_n < 0) goto oom;
        char *k = scratch + scratch_used;
        scratch_used += (size_t)k_n;

        /* Decode value */
        if (scratch_used + v_in_n > scratch_cap) goto oom;
        int v_n = pct_decode(v_in, v_in_n, scratch + scratch_used, scratch_cap - scratch_used);
        if (v_n < 0) goto oom;
        char *v = scratch + scratch_used;
        scratch_used += (size_t)v_n;

        if (pair_n == pair_cap) {
            pair_cap *= 2;
            qpair_t *np = realloc(pairs, pair_cap * sizeof(*pairs));
            if (!np) goto oom;
            pairs = np;
        }
        pairs[pair_n].k = k; pairs[pair_n].k_n = (size_t)k_n;
        pairs[pair_n].v = v; pairs[pair_n].v_n = (size_t)v_n;
        pair_n++;
    }

    qsort(pairs, pair_n, sizeof(*pairs), qpair_cmp);

    /* Phase 2: re-encode and emit. */
    size_t o = 0;
    for (size_t p = 0; p < pair_n; p++) {
        if (p > 0) {
            if (o + 1 > cap) goto oom;
            out[o++] = '&';
        }
        int n = pct_encode_strict(pairs[p].k, pairs[p].k_n, out + o, cap - o);
        if (n < 0) goto oom;
        o += (size_t)n;
        if (o + 1 > cap) goto oom;
        out[o++] = '=';
        n = pct_encode_strict(pairs[p].v, pairs[p].v_n, out + o, cap - o);
        if (n < 0) goto oom;
        o += (size_t)n;
    }

    free(pairs);
    free(scratch);
    return (int)o;

oom:
    free(pairs);
    free(scratch);
    return -1;
}

/* ===================================================================== */
/* Canonical headers + signed-headers list                                */
/* ===================================================================== */

/* Build canonical headers section using the signed-headers list from
 * the Authorization header. Returns bytes written or -1.
 *
 * Output format (S3 SigV4 spec):
 *     <name>:<value>\n
 *     <name>:<value>\n
 *     ...
 *     \n
 *
 * Names are taken verbatim from `signed_headers` (already lowercase
 * per spec); values come from c->req.headers and are trimmed +
 * collapsed. The trailing blank line is part of the canonical headers
 * section. */
static int build_canonical_headers(const conn_t *c, s3_str_t signed_headers,
                                   char *out, size_t cap) {
    size_t o = 0;
    size_t i = 0;
    while (i < signed_headers.n) {
        /* Skip leading semicolons */
        while (i < signed_headers.n && signed_headers.p[i] == ';') i++;
        size_t start = i;
        while (i < signed_headers.n && signed_headers.p[i] != ';') i++;
        size_t name_n = i - start;
        if (name_n == 0) continue;
        const char *name = signed_headers.p + start;

        /* Find header value */
        s3_str_t hname = { name, name_n };
        const s3_str_t *hv = NULL;
        for (size_t h = 0; h < c->req.n_headers; h++) {
            if (s3_str_eq(c->req.headers[h].k, hname)) {
                hv = &c->req.headers[h].v;
                break;
            }
        }
        if (!hv) return -1;     /* signed header missing — malformed request */

        /* Emit "name:" */
        if (o + name_n + 1 > cap) return -1;
        memcpy(out + o, name, name_n);
        o += name_n;
        out[o++] = ':';

        /* Emit trimmed/collapsed value */
        int vn = trim_and_collapse_ws(hv->p, hv->n, out + o, cap - o);
        if (vn < 0) return -1;
        o += (size_t)vn;

        if (o + 1 > cap) return -1;
        out[o++] = '\n';
    }

    /* Trailing blank line that terminates canonical-headers. */
    if (o + 1 > cap) return -1;
    out[o++] = '\n';
    return (int)o;
}

/* Just the SignedHeaders list, semicolon-joined (e.g. "host;x-amz-date"),
 * which is the line BETWEEN canonical headers and body hash. */
static int copy_signed_headers(s3_str_t signed_headers, char *out, size_t cap) {
    /* The SignedHeaders value is already in the right form per spec
     * (lowercase, semicolon-separated, alphabetical). We just copy it. */
    if (signed_headers.n > cap) return -1;
    memcpy(out, signed_headers.p, signed_headers.n);
    return (int)signed_headers.n;
}

/* ===================================================================== */
/* Canonical request                                                      */
/* ===================================================================== */

/* Build the full canonical request into `out`. Returns bytes written
 * or -1 on overflow. */
static int build_canonical_request(const conn_t *c, s3_str_t signed_headers,
                                   s3_str_t body_hash,
                                   char *out, size_t cap) {
    size_t o = 0;
    int n;

    /* Method */
    if (o + c->req.method.n + 1 > cap) return -1;
    memcpy(out + o, c->req.method.p, c->req.method.n);
    o += c->req.method.n;
    out[o++] = '\n';

    /* Canonical URI */
    n = canon_uri_s3(c->req.path, out + o, cap - o);
    if (n < 0) return -1;
    o += (size_t)n;
    if (o + 1 > cap) return -1;
    out[o++] = '\n';

    /* Canonical query string */
    n = build_canonical_query(c->req.query, out + o, cap - o);
    if (n < 0) return -1;
    o += (size_t)n;
    if (o + 1 > cap) return -1;
    out[o++] = '\n';

    /* Canonical headers (ends with trailing \n already) */
    n = build_canonical_headers(c, signed_headers, out + o, cap - o);
    if (n < 0) return -1;
    o += (size_t)n;

    /* Signed headers list */
    n = copy_signed_headers(signed_headers, out + o, cap - o);
    if (n < 0) return -1;
    o += (size_t)n;
    if (o + 1 > cap) return -1;
    out[o++] = '\n';

    /* Body hash */
    if (o + body_hash.n > cap) return -1;
    memcpy(out + o, body_hash.p, body_hash.n);
    o += body_hash.n;

    return (int)o;
}

/* ===================================================================== */
/* String to sign + signing key                                           */
/* ===================================================================== */

/* Build:
 *   AWS4-HMAC-SHA256\n
 *   <amz_date>\n
 *   <date>/<region>/<service>/aws4_request\n
 *   <hex(sha256(canonical_request))>
 */
static int build_string_to_sign(s3_str_t amz_date, s3_str_t scope,
                                const uint8_t cr_hash[32],
                                char *out, size_t cap) {
    size_t o = 0;
    static const char prefix[] = "AWS4-HMAC-SHA256\n";
    if (o + sizeof(prefix) - 1 > cap) return -1;
    memcpy(out + o, prefix, sizeof(prefix) - 1);
    o += sizeof(prefix) - 1;

    if (o + amz_date.n + 1 > cap) return -1;
    memcpy(out + o, amz_date.p, amz_date.n);
    o += amz_date.n;
    out[o++] = '\n';

    if (o + scope.n + 1 > cap) return -1;
    memcpy(out + o, scope.p, scope.n);
    o += scope.n;
    out[o++] = '\n';

    if (o + 64 > cap) return -1;
    hex_encode(cr_hash, 32, out + o);
    o += 64;
    return (int)o;
}

/* Derive signing key:
 *   kDate     = HMAC("AWS4" + secret, date)
 *   kRegion   = HMAC(kDate, region)
 *   kService  = HMAC(kRegion, service)
 *   kSigning  = HMAC(kService, "aws4_request")
 *
 * Each output is 32 bytes (HMAC-SHA256 size). */
static void derive_signing_key(const uint8_t *secret, size_t secret_len,
                               s3_str_t date, s3_str_t region, s3_str_t service,
                               uint8_t k_signing[32]) {
    /* "AWS4" + secret */
    char k0[256];
    if (secret_len + 4 > sizeof(k0)) {
        /* Practically secrets are <= 40 chars. If a user puts in a
         * pathologically long one we'd want to malloc. For now, refuse
         * gracefully by returning an all-zero key, which will fail the
         * signature compare. */
        memset(k_signing, 0, 32);
        return;
    }
    memcpy(k0, "AWS4", 4);
    memcpy(k0 + 4, secret, secret_len);

    uint8_t k_date[32], k_region[32], k_service[32];
    hmac_sha256(k0, secret_len + 4, date.p, date.n, k_date);
    hmac_sha256(k_date, 32, region.p, region.n, k_region);
    hmac_sha256(k_region, 32, service.p, service.n, k_service);
    hmac_sha256(k_service, 32, "aws4_request", 12, k_signing);

    OPENSSL_cleanse(k0, sizeof(k0));
    OPENSSL_cleanse(k_date, sizeof(k_date));
    OPENSSL_cleanse(k_region, sizeof(k_region));
    OPENSSL_cleanse(k_service, sizeof(k_service));
}

/* ===================================================================== */
/* Authorization header parse                                             */
/* ===================================================================== */

/* Parsed Authorization header:
 *   AWS4-HMAC-SHA256 Credential=AK/yyyymmdd/region/service/aws4_request,
 *                   SignedHeaders=host;x-amz-date,
 *                   Signature=hex
 */
typedef struct {
    s3_str_t access_key;
    s3_str_t date;          /* yyyymmdd */
    s3_str_t region;
    s3_str_t service;
    s3_str_t scope;         /* date/region/service/aws4_request */
    s3_str_t signed_headers;
    s3_str_t signature;
} auth_parts_t;

/* Returns 0 on success, -1 on malformed. Pieces point into auth.p. */
static int parse_authorization(s3_str_t auth, auth_parts_t *out) {
    static const char prefix[] = "AWS4-HMAC-SHA256 ";
    if (auth.n < sizeof(prefix) - 1
        || memcmp(auth.p, prefix, sizeof(prefix) - 1) != 0) {
        return -1;
    }
    s3_str_t rest = { auth.p + sizeof(prefix) - 1, auth.n - (sizeof(prefix) - 1) };

    s3_str_t cred = S3_STR_NULL, sh = S3_STR_NULL, sig = S3_STR_NULL;

    /* Split on commas (no quotes/escapes possible per spec). */
    size_t i = 0;
    while (i < rest.n) {
        /* Trim leading spaces. */
        while (i < rest.n && rest.p[i] == ' ') i++;
        size_t start = i;
        while (i < rest.n && rest.p[i] != ',') i++;
        size_t end = i;
        if (i < rest.n) i++; /* skip ',' */

        /* trim trailing spaces */
        while (end > start && rest.p[end-1] == ' ') end--;

        s3_str_t kv = { rest.p + start, end - start };
        size_t eq = 0;
        while (eq < kv.n && kv.p[eq] != '=') eq++;
        if (eq == kv.n) return -1;
        s3_str_t k = { kv.p, eq };
        s3_str_t v = { kv.p + eq + 1, kv.n - eq - 1 };

        if      (s3_str_eq_lit(k, "Credential"))    cred = v;
        else if (s3_str_eq_lit(k, "SignedHeaders")) sh   = v;
        else if (s3_str_eq_lit(k, "Signature"))     sig  = v;
        /* unknown keys: ignore */
    }

    if (cred.n == 0 || sh.n == 0 || sig.n == 0) return -1;

    /* Credential = ak/date/region/service/aws4_request. Split on '/'. */
    s3_str_t parts[5] = { S3_STR_NULL };
    int np = 0;
    size_t p = 0;
    while (p < cred.n && np < 5) {
        size_t s = p;
        while (p < cred.n && cred.p[p] != '/') p++;
        parts[np++] = (s3_str_t){ cred.p + s, p - s };
        if (p < cred.n) p++;
    }
    if (np != 5) return -1;
    if (!s3_str_eq_lit(parts[4], "aws4_request")) return -1;
    if (parts[1].n != 8) return -1;     /* yyyymmdd */
    for (size_t d = 0; d < 8; d++) {
        if (parts[1].p[d] < '0' || parts[1].p[d] > '9') return -1;
    }

    out->access_key     = parts[0];
    out->date           = parts[1];
    out->region         = parts[2];
    out->service        = parts[3];
    /* scope = "date/region/service/aws4_request" — the portion of cred
     * after the access key. */
    out->scope          = (s3_str_t){
        cred.p + parts[0].n + 1,
        cred.n - parts[0].n - 1,
    };
    out->signed_headers = sh;
    out->signature      = sig;
    return 0;
}

/* ===================================================================== */
/* Time / skew check                                                      */
/* ===================================================================== */

/* Parse "yyyymmddThhmmssZ" into Unix epoch seconds. Returns 0 on
 * success, -1 on bad format. */
static int parse_amz_date(s3_str_t d, int64_t *out) {
    if (d.n != 16 || d.p[8] != 'T' || d.p[15] != 'Z') return -1;
    for (size_t i = 0; i < 16; i++) {
        if (i == 8 || i == 15) continue;
        if (d.p[i] < '0' || d.p[i] > '9') return -1;
    }
    struct tm tm = {0};
    tm.tm_year = (d.p[0]-'0')*1000 + (d.p[1]-'0')*100 + (d.p[2]-'0')*10 + (d.p[3]-'0') - 1900;
    tm.tm_mon  = (d.p[4]-'0')*10 + (d.p[5]-'0') - 1;
    tm.tm_mday = (d.p[6]-'0')*10 + (d.p[7]-'0');
    tm.tm_hour = (d.p[9]-'0')*10 + (d.p[10]-'0');
    tm.tm_min  = (d.p[11]-'0')*10 + (d.p[12]-'0');
    tm.tm_sec  = (d.p[13]-'0')*10 + (d.p[14]-'0');
    /* timegm: GNU extension, available with _GNU_SOURCE which the
     * Makefile sets. */
    time_t t = timegm(&tm);
    if (t == (time_t)-1) return -1;
    *out = (int64_t)t;
    return 0;
}

/* ===================================================================== */
/* Top-level verify                                                       */
/* ===================================================================== */

/* Generous bound: HTTP requests with all signed headers shouldn't exceed
 * a few KB. The 32 KB buffer is way more than enough. */
#define CR_BUF_SZ      (32 * 1024)
#define STS_BUF_SZ     (1 * 1024)

s3_err_t sigv4_verify(const sigv4_verifier_t *v, const conn_t *c) {
    if (!v || !c) return S3_ERR_ACCESS_DENIED;

    /* 1. Authorization header */
    const s3_str_t *auth_h = hdr_lookup(c, "authorization");
    if (!auth_h) return S3_ERR_ACCESS_DENIED;

    auth_parts_t ap;
    if (parse_authorization(*auth_h, &ap) < 0) return S3_ERR_ACCESS_DENIED;

    /* 2. Required: x-amz-date and host */
    const s3_str_t *date_h = hdr_lookup(c, "x-amz-date");
    if (!date_h) return S3_ERR_ACCESS_DENIED;
    const s3_str_t *host_h = hdr_lookup(c, "host");
    if (!host_h) return S3_ERR_ACCESS_DENIED;

    /* 3. Skew check */
    int64_t now = v->fixed_now ? v->fixed_now : (int64_t)time(NULL);
    int64_t req_t;
    if (parse_amz_date(*date_h, &req_t) < 0) return S3_ERR_ACCESS_DENIED;
    int64_t delta = req_t > now ? req_t - now : now - req_t;
    if (delta > v->max_skew) return S3_ERR_REQUEST_TIME_TOO_SKEWED;

    /* 4. Body hash header. The S3 SigV4 contract is:
     *    - If x-amz-content-sha256 is present, use its value verbatim
     *      (which may be a hex hash, "UNSIGNED-PAYLOAD", or
     *      "STREAMING-AWS4-HMAC-SHA256-PAYLOAD").
     *    - If absent, AWS SDKs use SHA-256("") (i.e. the empty-body
     *      hash). botocore for example does this for GET/HEAD/DELETE
     *      requests with no body. We mirror that. */
    static const s3_str_t empty_sha256 = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 64
    };
    const s3_str_t *bh_h = hdr_lookup(c, "x-amz-content-sha256");
    s3_str_t body_hash = bh_h ? *bh_h : empty_sha256;

    /* STREAMING-UNSIGNED-PAYLOAD-TRAILER is a different framing
     * (standard HTTP chunked + trailers, not aws-chunked) and is not
     * yet implemented. STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER is
     * supported: the seed signature is verified here using the literal
     * as the body hash (per AWS spec), and the chunk decoder handles
     * the per-chunk signatures plus the trailer signature. */
    if (s3_str_eq_lit(body_hash, "STREAMING-UNSIGNED-PAYLOAD-TRAILER")) {
        return S3_ERR_NOT_IMPLEMENTED;
    }

    /* 5. Credential lookup */
    const cred_t *cr = cred_lookup(v, ap.access_key.p, ap.access_key.n);
    if (!cr) return S3_ERR_ACCESS_DENIED;

    /* 6. Build canonical request. */
    char *cr_buf = malloc(CR_BUF_SZ);
    if (!cr_buf) return S3_ERR_INTERNAL;
    int cr_n = build_canonical_request(c, ap.signed_headers, body_hash,
                                       cr_buf, CR_BUF_SZ);
    if (cr_n < 0) { free(cr_buf); return S3_ERR_ACCESS_DENIED; }

    /* 7. Hash canonical request → string-to-sign → signature */
    uint8_t cr_hash[32];
    sha256(cr_buf, (size_t)cr_n, cr_hash);
    free(cr_buf);

    char sts[STS_BUF_SZ];
    int sts_n = build_string_to_sign(*date_h, ap.scope, cr_hash, sts, sizeof(sts));
    if (sts_n < 0) return S3_ERR_INTERNAL;

    uint8_t k_signing[32];
    derive_signing_key(cr->secret_key, cr->secret_len,
                       ap.date, ap.region, ap.service, k_signing);

    uint8_t mac[32];
    hmac_sha256(k_signing, 32, sts, (size_t)sts_n, mac);
    OPENSSL_cleanse(k_signing, sizeof(k_signing));

    /* 8. Hex-encode and constant-time compare */
    char want[64];
    hex_encode(mac, 32, want);
    OPENSSL_cleanse(mac, sizeof(mac));

    if (ap.signature.n != 64) return S3_ERR_SIGNATURE_DOES_NOT_MATCH;
    if (CRYPTO_memcmp(want, ap.signature.p, 64) != 0) {
        return S3_ERR_SIGNATURE_DOES_NOT_MATCH;
    }
    return S3_OK;
}

/* ===================================================================== */
/* Body-hash verification                                                 */
/* ===================================================================== */

void *sigv4_body_hash_begin(void) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return NULL;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

void sigv4_body_hash_update(void *ctx, const void *data, size_t n) {
    if (!ctx || n == 0) return;
    EVP_DigestUpdate((EVP_MD_CTX *)ctx, data, n);
}

int sigv4_body_hash_verify(void *ctx, const char expected_hex[64]) {
    if (!ctx) return 0;
    uint8_t mac[32];
    unsigned int mac_n = 32;
    int ok = (EVP_DigestFinal_ex((EVP_MD_CTX *)ctx, mac, &mac_n) == 1
              && mac_n == 32);
    if (!ok) return 0;
    char got[64];
    hex_encode(mac, 32, got);
    /* Constant-time compare. We don't strictly need it here (this isn't
     * a secret), but it's cheap and consistent with our other compares. */
    return CRYPTO_memcmp(got, expected_hex, 64) == 0;
}

void sigv4_body_hash_free(void *ctx) {
    if (ctx) EVP_MD_CTX_free((EVP_MD_CTX *)ctx);
}

/* ===================================================================== */
/* Streaming chunked SigV4                                                */
/* ===================================================================== */

/* Returns 1 if the request is using a streaming aws-chunked framing
 * (with or without trailers), 0 otherwise. */
int sigv4_is_chunked(const conn_t *c) {
    const s3_str_t *bh = hdr_lookup(c, "x-amz-content-sha256");
    if (!bh) return 0;
    return s3_str_eq_lit(*bh, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
        || s3_str_eq_lit(*bh, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER");
}

/* Decoder state machine. Each chunk goes:
 *   READ_SIZE   — accumulating hex digits and ';' before the sig
 *   READ_SIG    — accumulating the 64 hex chars of chunk-signature
 *   READ_CRLF1  — \r\n after the chunk header
 *   READ_DATA   — chunk_size bytes of data
 *   READ_CRLF2  — \r\n after the chunk data
 *   DONE        — final 0-length chunk seen
 *   ERROR       — sticky error state
 *
 * The chunk header line is bounded: hex digits ≤ 16 chars, plus ';',
 * plus "chunk-signature=", plus 64 hex chars = ~85 bytes. We use a
 * 128-byte line buffer.
 *
 * Per-chunk signature verification:
 *   string-to-sign:
 *     AWS4-HMAC-SHA256-PAYLOAD\n
 *     <amz-date>\n
 *     <scope>\n
 *     <prev-signature>\n
 *     <SHA256("") hex>\n
 *     <SHA256(chunk-data) hex>
 *
 * The data hash is built incrementally as data arrives, finalized at
 * the end of the chunk, then the signature is checked.
 */

typedef enum {
    CST_SIZE = 0,
    CST_SIG,
    CST_CRLF1,
    CST_DATA,
    CST_CRLF2,
    CST_CRLF2_HALF,        /* saw \r at end of buffer; expect \n next */
    /* Trailer-mode states (only reachable when trailer_mode=1) */
    CST_TRAILER_LINE,      /* accumulating bytes of a trailer header line */
    CST_TRAILER_LF,        /* saw \r at end of trailer line, expect \n */
    CST_TRAILER_FINAL_LF,  /* saw \r at start of blank line, expect \n */
    CST_DONE,
    CST_ERROR,
} chunk_state_t;

/* Maximum trailer headers we'll accept on a single request. AWS clients
 * in practice send at most one (e.g. x-amz-checksum-sha256) plus the
 * mandatory x-amz-trailer-signature. */
#define SIGV4_MAX_TRAILERS 8

typedef struct {
    char   name[64];   size_t name_n;
    char   value[256]; size_t value_n;
} trailer_kv_t;

struct sigv4_chunk_decoder {
    /* Crypto state (immutable after begin) */
    uint8_t  signing_key[32];
    char     amz_date[16];
    size_t   amz_date_n;
    char     scope[128];
    size_t   scope_n;

    /* Rolling state */
    char     prev_sig[64];          /* "previous signature" — seed → chunk1 → chunk2 ... */
    chunk_state_t state;
    char     line[128];             /* chunk-header line accumulator */
    size_t   line_n;
    uint64_t chunk_size;            /* current chunk's data size */
    uint64_t chunk_remaining;       /* bytes of data still to read in current chunk */
    char     chunk_sig[64];         /* claimed signature for current chunk */
    int      chunk_sig_n;           /* position in chunk_sig as we accumulate */
    EVP_MD_CTX *data_hash_ctx;      /* SHA-256 of current chunk's data */
    int      seen_terminator;
    uint64_t expected_decoded;      /* x-amz-decoded-content-length, 0 = unbounded */
    uint64_t total_decoded;         /* sum of chunk_size seen */

    /* Trailer mode (STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER) */
    int           trailer_mode;
    char          trailer_line[1024];
    size_t        trailer_line_n;
    char          trailer_sig[64];        /* claimed x-amz-trailer-signature */
    int           trailer_sig_seen;
    trailer_kv_t  trailers[SIGV4_MAX_TRAILERS];
    int           trailer_n;

    /* Forwarding callback */
    sigv4_chunk_data_cb on_data;
    void               *user;
};

/* Parse "<hex>;chunk-signature=<64-hex>" from `line`. Returns 0 ok, -1 bad. */
static int parse_chunk_header(const char *line, size_t n,
                              uint64_t *out_size, char out_sig[64]) {
    /* Find ';' */
    size_t i = 0;
    while (i < n && line[i] != ';') i++;
    if (i == n) return -1;

    /* Parse hex size */
    if (i == 0 || i > 16) return -1;
    uint64_t sz = 0;
    for (size_t j = 0; j < i; j++) {
        char ch = line[j];
        int v;
        if      (ch >= '0' && ch <= '9') v = ch - '0';
        else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
        else return -1;
        sz = (sz << 4) | (uint64_t)v;
    }

    /* Expect ";chunk-signature=" */
    static const char tag[] = ";chunk-signature=";
    if (n - i < sizeof(tag) - 1 + 64) return -1;
    if (memcmp(line + i, tag, sizeof(tag) - 1) != 0) return -1;
    if (n - i - (sizeof(tag) - 1) != 64) return -1;
    memcpy(out_sig, line + i + sizeof(tag) - 1, 64);

    /* Validate hex chars in signature */
    for (int j = 0; j < 64; j++) {
        char ch = out_sig[j];
        if (!((ch >= '0' && ch <= '9')
              || (ch >= 'a' && ch <= 'f')
              || (ch >= 'A' && ch <= 'F'))) return -1;
    }

    *out_size = sz;
    return 0;
}

/* Compute the chunk signature for the current chunk and compare with
 * d->chunk_sig. Returns 1 if matched, 0 otherwise. d->data_hash_ctx
 * is finalized as a side effect; caller should re-init if needed. */
static int verify_chunk_sig(sigv4_chunk_decoder_t *d) {
    /* Constants: SHA-256("") in hex */
    static const char EMPTY_HASH[65] =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /* Finalize data hash. */
    uint8_t data_mac[32];
    char    data_hex[64];
    unsigned int n = 32;
    EVP_DigestFinal_ex(d->data_hash_ctx, data_mac, &n);
    hex_encode(data_mac, 32, data_hex);

    /* Build string-to-sign:
     *   AWS4-HMAC-SHA256-PAYLOAD\n
     *   <amz_date>\n
     *   <scope>\n
     *   <prev_sig>\n
     *   <empty_hash>\n
     *   <data_hex>
     */
    char sts[512];
    int o = 0;
    static const char prefix[] = "AWS4-HMAC-SHA256-PAYLOAD\n";
    memcpy(sts + o, prefix, sizeof(prefix) - 1); o += (int)sizeof(prefix) - 1;
    memcpy(sts + o, d->amz_date, d->amz_date_n);  o += (int)d->amz_date_n;
    sts[o++] = '\n';
    memcpy(sts + o, d->scope, d->scope_n);        o += (int)d->scope_n;
    sts[o++] = '\n';
    memcpy(sts + o, d->prev_sig, 64);             o += 64;
    sts[o++] = '\n';
    memcpy(sts + o, EMPTY_HASH, 64);              o += 64;
    sts[o++] = '\n';
    memcpy(sts + o, data_hex, 64);                o += 64;

    /* HMAC */
    uint8_t mac[32];
    hmac_sha256(d->signing_key, 32, sts, (size_t)o, mac);
    char want[64];
    hex_encode(mac, 32, want);

    int ok = (CRYPTO_memcmp(want, d->chunk_sig, 64) == 0);
    if (ok) {
        /* Roll prev_sig forward for the next chunk. */
        memcpy(d->prev_sig, d->chunk_sig, 64);
    }
    return ok;
}

/* Process one trailer header line:
 *   - split on ':'
 *   - lowercase name; trim+collapse value
 *   - if name is "x-amz-trailer-signature", stash the value into
 *     d->trailer_sig (must be 64 hex chars)
 *   - otherwise, store as a trailer for canonical-trailer hashing
 * Returns 0 on success, -1 on malformed line or buffer overflow.
 */
static int process_trailer_line(sigv4_chunk_decoder_t *d,
                                const char *line, size_t n) {
    /* Find ':' separator. */
    size_t colon = 0;
    while (colon < n && line[colon] != ':') colon++;
    if (colon == 0 || colon == n) return -1;

    /* Lowercase name into a small scratch. */
    char name_lc[64];
    if (colon > sizeof(name_lc)) return -1;
    for (size_t j = 0; j < colon; j++) {
        char ch = line[j];
        name_lc[j] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
    }

    /* Trim + collapse value. */
    char value[256];
    int v_n = trim_and_collapse_ws(line + colon + 1, n - colon - 1,
                                   value, sizeof(value));
    if (v_n < 0) return -1;

    /* Special case: x-amz-trailer-signature is the trailer sig itself. */
    static const char SIG_NAME[] = "x-amz-trailer-signature";
    static const size_t SIG_NAME_N = sizeof(SIG_NAME) - 1;
    if (colon == SIG_NAME_N && memcmp(name_lc, SIG_NAME, SIG_NAME_N) == 0) {
        if (v_n != 64) return -1;
        for (int j = 0; j < 64; j++) {
            char ch = value[j];
            if (!((ch >= '0' && ch <= '9')
                  || (ch >= 'a' && ch <= 'f')
                  || (ch >= 'A' && ch <= 'F'))) return -1;
        }
        if (d->trailer_sig_seen) return -1;     /* duplicate */
        memcpy(d->trailer_sig, value, 64);
        d->trailer_sig_seen = 1;
        return 0;
    }

    if (d->trailer_n >= SIGV4_MAX_TRAILERS) return -1;
    if ((size_t)v_n > sizeof(d->trailers[0].value)) return -1;

    /* Reject duplicates by name. */
    for (int t = 0; t < d->trailer_n; t++) {
        if (d->trailers[t].name_n == colon
            && memcmp(d->trailers[t].name, name_lc, colon) == 0) return -1;
    }

    trailer_kv_t *t = &d->trailers[d->trailer_n++];
    memcpy(t->name, name_lc, colon);
    t->name_n = colon;
    memcpy(t->value, value, (size_t)v_n);
    t->value_n = (size_t)v_n;
    return 0;
}

static int trailer_cmp(const void *a, const void *b) {
    const trailer_kv_t *x = a, *y = b;
    size_t n = x->name_n < y->name_n ? x->name_n : y->name_n;
    int r = memcmp(x->name, y->name, n);
    if (r) return r;
    if (x->name_n != y->name_n) return x->name_n < y->name_n ? -1 : 1;
    return 0;
}

/* Verify the trailer signature using:
 *   string-to-sign:
 *     AWS4-HMAC-SHA256-TRAILER\n
 *     <amz_date>\n
 *     <scope>\n
 *     <prev_sig>\n               (signature of the terminator chunk)
 *     hex(SHA256(canonical_trailers))
 *
 * canonical_trailers is the trailers, sorted by lowercased name, each
 * formatted as "<lc-name>:<trimmed-value>\n".
 *
 * Returns 1 if signature matches, 0 otherwise. */
static int verify_trailer_sig(sigv4_chunk_decoder_t *d) {
    if (!d->trailer_sig_seen) return 0;

    qsort(d->trailers, (size_t)d->trailer_n, sizeof(trailer_kv_t), trailer_cmp);

    char canon[2048];
    size_t o = 0;
    for (int t = 0; t < d->trailer_n; t++) {
        const trailer_kv_t *kv = &d->trailers[t];
        if (o + kv->name_n + 1 + kv->value_n + 1 > sizeof(canon)) return 0;
        memcpy(canon + o, kv->name, kv->name_n);
        o += kv->name_n;
        canon[o++] = ':';
        memcpy(canon + o, kv->value, kv->value_n);
        o += kv->value_n;
        canon[o++] = '\n';
    }

    uint8_t canon_mac[32];
    char    canon_hex[64];
    sha256(canon, o, canon_mac);
    hex_encode(canon_mac, 32, canon_hex);

    char sts[512];
    int p = 0;
    static const char prefix[] = "AWS4-HMAC-SHA256-TRAILER\n";
    memcpy(sts + p, prefix, sizeof(prefix) - 1); p += (int)sizeof(prefix) - 1;
    memcpy(sts + p, d->amz_date, d->amz_date_n);  p += (int)d->amz_date_n;
    sts[p++] = '\n';
    memcpy(sts + p, d->scope, d->scope_n);        p += (int)d->scope_n;
    sts[p++] = '\n';
    memcpy(sts + p, d->prev_sig, 64);             p += 64;
    sts[p++] = '\n';
    memcpy(sts + p, canon_hex, 64);               p += 64;

    uint8_t mac[32];
    char    want[64];
    hmac_sha256(d->signing_key, 32, sts, (size_t)p, mac);
    hex_encode(mac, 32, want);

    return CRYPTO_memcmp(want, d->trailer_sig, 64) == 0;
}

sigv4_chunk_decoder_t *sigv4_chunk_begin(const sigv4_verifier_t *v,
                                          const conn_t *c,
                                          uint64_t expected_decoded,
                                          sigv4_chunk_data_cb on_data,
                                          void *user) {
    if (!v || !c) return NULL;

    /* Re-parse Authorization to get scope, amz_date, signature. The
     * verifier already accepted these, so this should always succeed. */
    const s3_str_t *auth_h = hdr_lookup(c, "authorization");
    const s3_str_t *date_h = hdr_lookup(c, "x-amz-date");
    if (!auth_h || !date_h) return NULL;
    auth_parts_t ap;
    if (parse_authorization(*auth_h, &ap) < 0) return NULL;
    if (ap.signature.n != 64 || date_h->n > sizeof(((sigv4_chunk_decoder_t*)0)->amz_date))
        return NULL;
    if (ap.scope.n > sizeof(((sigv4_chunk_decoder_t*)0)->scope))
        return NULL;
    const cred_t *cr = cred_lookup(v, ap.access_key.p, ap.access_key.n);
    if (!cr) return NULL;

    sigv4_chunk_decoder_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->state = CST_SIZE;
    d->on_data = on_data;
    d->user = user;
    d->expected_decoded = expected_decoded;
    memcpy(d->amz_date, date_h->p, date_h->n);
    d->amz_date_n = date_h->n;
    memcpy(d->scope, ap.scope.p, ap.scope.n);
    d->scope_n = ap.scope.n;
    memcpy(d->prev_sig, ap.signature.p, 64);

    /* Detect trailer mode from x-amz-content-sha256. */
    const s3_str_t *bh = hdr_lookup(c, "x-amz-content-sha256");
    d->trailer_mode = (bh && s3_str_eq_lit(*bh,
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER")) ? 1 : 0;

    derive_signing_key(cr->secret_key, cr->secret_len,
                       ap.date, ap.region, ap.service, d->signing_key);

    d->data_hash_ctx = EVP_MD_CTX_new();
    if (!d->data_hash_ctx
        || EVP_DigestInit_ex(d->data_hash_ctx, EVP_sha256(), NULL) != 1) {
        sigv4_chunk_free(d);
        return NULL;
    }
    return d;
}

int sigv4_chunk_feed(sigv4_chunk_decoder_t *d, const char *data, size_t len) {
    if (!d || d->state == CST_ERROR) return -1;
    size_t i = 0;
    while (i < len) {
        switch (d->state) {
        case CST_SIZE:
        case CST_SIG: {
            /* Both states accumulate into d->line until we see \r. */
            while (i < len && data[i] != '\r') {
                if (d->line_n >= sizeof(d->line)) {
                    d->state = CST_ERROR; return -1;
                }
                d->line[d->line_n++] = data[i++];
            }
            if (i < len && data[i] == '\r') {
                /* Header complete. Parse it. */
                if (parse_chunk_header(d->line, d->line_n,
                                       &d->chunk_size, d->chunk_sig) < 0) {
                    d->state = CST_ERROR; return -1;
                }
                d->line_n = 0;
                d->state = CST_CRLF1;
                i++;  /* consume \r, expect \n next */
            }
            break;
        }
        case CST_CRLF1:
            if (data[i] != '\n') { d->state = CST_ERROR; return -1; }
            i++;
            d->chunk_remaining = d->chunk_size;
            d->total_decoded += d->chunk_size;
            /* Reset data hash for this chunk. */
            EVP_DigestInit_ex(d->data_hash_ctx, EVP_sha256(), NULL);
            if (d->chunk_size == 0) {
                /* Terminator chunk: verify the chunk signature, then
                 * either read trailer headers (trailer mode) or just
                 * consume the empty trailer-part terminator (\r\n). */
                if (!verify_chunk_sig(d)) {
                    d->state = CST_ERROR; return -1;
                }
                d->seen_terminator = 1;
                d->state = d->trailer_mode ? CST_TRAILER_LINE : CST_CRLF2;
            } else {
                d->state = CST_DATA;
            }
            break;

        case CST_DATA: {
            size_t take = len - i;
            if ((uint64_t)take > d->chunk_remaining) take = (size_t)d->chunk_remaining;
            EVP_DigestUpdate(d->data_hash_ctx, data + i, take);
            if (d->on_data && d->on_data(d->user, data + i, take) < 0) {
                d->state = CST_ERROR; return -1;
            }
            i += take;
            d->chunk_remaining -= take;
            if (d->chunk_remaining == 0) {
                /* Verify chunk signature now (data hash is finalized inside). */
                if (!verify_chunk_sig(d)) {
                    d->state = CST_ERROR; return -1;
                }
                d->state = CST_CRLF2;
            }
            break;
        }

        case CST_CRLF2: {
            if (data[i] != '\r') { d->state = CST_ERROR; return -1; }
            i++;
            if (i >= len) {
                /* \r consumed, but \n hasn't arrived yet. */
                d->state = CST_CRLF2_HALF;
                return 0;
            }
            if (data[i] != '\n') { d->state = CST_ERROR; return -1; }
            i++;
            d->state = d->seen_terminator ? CST_DONE : CST_SIZE;
            break;
        }

        case CST_CRLF2_HALF:
            if (data[i] != '\n') { d->state = CST_ERROR; return -1; }
            i++;
            d->state = d->seen_terminator ? CST_DONE : CST_SIZE;
            break;

        case CST_TRAILER_LINE:
            /* Accumulate bytes of the current trailer line until \r.
             * An immediate \r at line position 0 means we just hit the
             * blank-line terminator that ends the trailer-part. */
            while (i < len && data[i] != '\r') {
                if (d->trailer_line_n >= sizeof(d->trailer_line)) {
                    d->state = CST_ERROR; return -1;
                }
                d->trailer_line[d->trailer_line_n++] = data[i++];
            }
            if (i < len && data[i] == '\r') {
                i++;
                if (d->trailer_line_n == 0) {
                    d->state = CST_TRAILER_FINAL_LF;
                } else {
                    d->state = CST_TRAILER_LF;
                }
            }
            break;

        case CST_TRAILER_LF:
            if (data[i] != '\n') { d->state = CST_ERROR; return -1; }
            i++;
            if (process_trailer_line(d, d->trailer_line, d->trailer_line_n) < 0) {
                d->state = CST_ERROR; return -1;
            }
            d->trailer_line_n = 0;
            d->state = CST_TRAILER_LINE;
            break;

        case CST_TRAILER_FINAL_LF:
            if (data[i] != '\n') { d->state = CST_ERROR; return -1; }
            i++;
            if (!verify_trailer_sig(d)) { d->state = CST_ERROR; return -1; }
            d->state = CST_DONE;
            break;

        case CST_DONE:
            /* Extra bytes after terminator — ignore (some clients send
             * an extra \r\n). We could be strict but it costs nothing
             * to be tolerant here. */
            i++;
            break;

        case CST_ERROR:
            return -1;
        }
    }
    return 0;
}

int sigv4_chunk_finish(sigv4_chunk_decoder_t *d) {
    if (!d) return -1;
    if (d->state == CST_ERROR) return -1;
    if (!d->seen_terminator) return -1;
    /* For trailer mode, the trailer-part must have been fully consumed
     * (we reached CST_DONE) — otherwise the trailer signature was never
     * verified. For non-trailer mode, CST_DONE is the only "good" end
     * state too: the body may legitimately end at CRLF2_HALF for some
     * clients, but in that case the state machine has already advanced
     * to CST_DONE because the terminating CRLF was consumed. */
    if (d->state != CST_DONE) return -1;
    if (d->expected_decoded != 0
        && d->total_decoded != d->expected_decoded) {
        return -1;
    }
    return 0;
}

void sigv4_chunk_free(sigv4_chunk_decoder_t *d) {
    if (!d) return;
    if (d->data_hash_ctx) EVP_MD_CTX_free(d->data_hash_ctx);
    OPENSSL_cleanse(d->signing_key, sizeof(d->signing_key));
    free(d);
}

/* ===================================================================== */
/* Test hooks (only enabled when SIGV4_TESTING is defined)                */
/* ===================================================================== */
#ifdef SIGV4_TESTING

/* Internal helpers exposed to tests so we can drive each step against
 * AWS's published test vectors without round-tripping through a real
 * connection. */

int sigv4_test_canon_query (const char *q, size_t q_n, char *out, size_t cap);
int sigv4_test_pct_encode  (const char *in, size_t in_n, char *out, size_t cap);
int sigv4_test_pct_decode  (const char *in, size_t in_n, char *out, size_t cap);
int sigv4_test_trim_collapse(const char *in, size_t in_n, char *out, size_t cap);
void sigv4_test_derive_key (const char *secret, size_t secret_n,
                            const char *date, size_t date_n,
                            const char *region, size_t region_n,
                            const char *service, size_t service_n,
                            uint8_t out[32]);
void sigv4_test_sha256     (const void *in, size_t n, uint8_t out[32]);
void sigv4_test_hex_encode (const uint8_t *in, size_t n, char *out);

/* Build a canonical request from a fully-populated conn_t. Used to
 * compare against AWS's documented examples byte-for-byte. */
int sigv4_test_canonical_request_from_conn(
    const conn_t *c, const char *signed_headers,
    const char *body_hash, char *out, size_t cap);

int sigv4_test_canonical_request_from_conn(
    const conn_t *c, const char *signed_headers_lit,
    const char *body_hash_lit, char *out, size_t cap) {
    s3_str_t sh = { signed_headers_lit, strlen(signed_headers_lit) };
    s3_str_t bh = { body_hash_lit, strlen(body_hash_lit) };
    return build_canonical_request(c, sh, bh, out, cap);
}

int sigv4_test_canon_query(const char *q, size_t q_n, char *out, size_t cap) {
    s3_str_t s = { q, q_n };
    return build_canonical_query(s, out, cap);
}

int sigv4_test_pct_encode(const char *in, size_t in_n, char *out, size_t cap) {
    return pct_encode_strict(in, in_n, out, cap);
}

int sigv4_test_pct_decode(const char *in, size_t in_n, char *out, size_t cap) {
    return pct_decode(in, in_n, out, cap);
}

int sigv4_test_trim_collapse(const char *in, size_t in_n, char *out, size_t cap) {
    return trim_and_collapse_ws(in, in_n, out, cap);
}

void sigv4_test_derive_key(const char *secret, size_t secret_n,
                           const char *date, size_t date_n,
                           const char *region, size_t region_n,
                           const char *service, size_t service_n,
                           uint8_t out[32]) {
    s3_str_t d = { date, date_n }, r = { region, region_n }, s = { service, service_n };
    derive_signing_key((const uint8_t *)secret, secret_n, d, r, s, out);
}

void sigv4_test_sha256(const void *in, size_t n, uint8_t out[32]) {
    sha256(in, n, out);
}

void sigv4_test_hex_encode(const uint8_t *in, size_t n, char *out) {
    hex_encode(in, n, out);
}

#endif /* SIGV4_TESTING */
