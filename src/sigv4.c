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
    char       *user;           /* owner identity; defaults to access_key */
    uint8_t    *secret_key;     /* not NUL-terminated, as bytes */
    size_t      secret_len;
    sigv4_cred_attrs_t attrs;   /* expiry, disabled, read-only (item 4) */
    int64_t     last_used;      /* atomic; epoch s of the last verified request */
    struct cred *next;
} cred_t;

typedef struct admin {
    char         *user;
    struct admin *next;
} admin_t;

struct sigv4_verifier {
    cred_t   *creds;
    admin_t  *admins;           /* not swapped by sigv4_swap_creds */
    int64_t   fixed_now;        /* 0 = real clock */
    int       max_skew;         /* seconds */
    int64_t   presign_max_expires; /* seconds; 0 = AWS max (7 days) */
    int       no_presign_admin; /* refuse presigned URLs signed by admins */
};

sigv4_verifier_t *sigv4_create(void) {
    sigv4_verifier_t *v = calloc(1, sizeof(*v));
    if (!v) return NULL;
    v->max_skew = 900;          /* 15 minutes — AWS default */
    v->presign_max_expires = 86400;  /* 24 h (AWS allows 7 days) */
    return v;
}

void sigv4_destroy(sigv4_verifier_t *v) {
    if (!v) return;
    cred_t *c = v->creds;
    while (c) {
        cred_t *next = c->next;
        free(c->access_key);
        free(c->user);
        if (c->secret_key) {
            /* Zero secrets before freeing. */
            OPENSSL_cleanse(c->secret_key, c->secret_len);
            free(c->secret_key);
        }
        free(c);
        c = next;
    }
    admin_t *a = v->admins;
    while (a) {
        admin_t *next = a->next;
        free(a->user);
        free(a);
        a = next;
    }
    free(v);
}

void sigv4_swap_creds(sigv4_verifier_t *a, sigv4_verifier_t *b) {
    if (!a || !b) return;
    /* Last-used times live only in memory (and keys.state): carry them
     * across a reload by access key. */
    for (cred_t *n = b->creds; n; n = n->next)
        for (cred_t *o = a->creds; o; o = o->next)
            if (!strcmp(n->access_key, o->access_key)) {
                int64_t t = __atomic_load_n(&o->last_used, __ATOMIC_RELAXED);
                if (t > n->last_used) n->last_used = t;
                break;
            }
    cred_t *tmp = a->creds;
    a->creds = b->creds;
    b->creds = tmp;
}

int sigv4_add_cred(sigv4_verifier_t *v,
                   const char *access_key,
                   const char *secret_key) {
    return sigv4_add_cred_user(v, access_key, secret_key, NULL);
}

int sigv4_add_cred_user(sigv4_verifier_t *v,
                        const char *access_key,
                        const char *secret_key,
                        const char *user) {
    return sigv4_add_cred_ex(v, access_key, secret_key, user, NULL);
}

int sigv4_add_cred_ex(sigv4_verifier_t *v, const char *access_key, const char *secret_key,
                      const char *user, const sigv4_cred_attrs_t *attrs) {
    if (!v || !access_key || !secret_key) return -1;
    if (!user || !*user) user = access_key;
    if (strlen(user) > SIGV4_USER_MAX) return -1;
    /* Reject duplicate access keys. */
    for (cred_t *c = v->creds; c; c = c->next) {
        if (strcmp(c->access_key, access_key) == 0) return -1;
    }
    cred_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    c->access_key = strdup(access_key);
    c->user = strdup(user);
    size_t sn = strlen(secret_key);
    c->secret_key = malloc(sn);
    if (!c->access_key || !c->user || !c->secret_key) {
        free(c->access_key); free(c->user); free(c->secret_key); free(c);
        return -1;
    }
    memcpy(c->secret_key, secret_key, sn);
    c->secret_len = sn;
    if (attrs) c->attrs = *attrs;
    c->next = v->creds;
    v->creds = c;
    return 0;
}

int sigv4_add_admin(sigv4_verifier_t *v, const char *user) {
    if (!v || !user || !*user || strlen(user) > SIGV4_USER_MAX) return -1;
    admin_t *a = calloc(1, sizeof(*a));
    if (!a) return -1;
    a->user = strdup(user);
    if (!a->user) { free(a); return -1; }
    a->next = v->admins;
    v->admins = a;
    return 0;
}

static int is_admin(const sigv4_verifier_t *v, const char *user) {
    for (const admin_t *a = v->admins; a; a = a->next)
        if (strcmp(a->user, user) == 0) return 1;
    return 0;
}

void sigv4_set_clock(sigv4_verifier_t *v, int64_t fixed_now) {
    if (v) v->fixed_now = fixed_now;
}

void sigv4_set_presign_policy(sigv4_verifier_t *v, int64_t max_expires,
                              int no_admin) {
    if (!v) return;
    v->presign_max_expires = max_expires;
    v->no_presign_admin = no_admin;
}

void sigv4_set_max_skew(sigv4_verifier_t *v, int max_skew) {
    if (v && max_skew > 0) v->max_skew = max_skew;
}

int64_t sigv4_now(const sigv4_verifier_t *v) {
    return v && v->fixed_now ? v->fixed_now : (int64_t)time(NULL);
}

void sigv4_foreach_cred(const sigv4_verifier_t *v, sigv4_cred_cb cb, void *ctx) {
    if (!v || !cb) return;
    for (const cred_t *c = v->creds; c; c = c->next)
        cb(ctx, c->access_key, c->user, &c->attrs,
           __atomic_load_n(&c->last_used, __ATOMIC_RELAXED));
}

void sigv4_set_last_used(sigv4_verifier_t *v, const char *ak, int64_t t) {
    if (!v || !ak) return;
    for (cred_t *c = v->creds; c; c = c->next)
        if (!strcmp(c->access_key, ak)) {
            if (t > __atomic_load_n(&c->last_used, __ATOMIC_RELAXED))
                __atomic_store_n(&c->last_used, t, __ATOMIC_RELAXED);
            return;
        }
}

/* Why the last refused verify on this thread was refused (audit log
 * only; the client sees the same AccessDenied for all of these). */
static __thread const char *g_deny_reason;
const char *sigv4_last_deny_reason(void) { return g_deny_reason; }

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
static int build_canonical_query(s3_str_t query, const char *exclude,
                                 char *out, size_t cap) {
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

        /* Presigned URLs: X-Amz-Signature is not part of what was signed. */
        if (exclude && (size_t)k_n == strlen(exclude)
            && memcmp(k, exclude, (size_t)k_n) == 0)
            continue;

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
                                   s3_str_t body_hash, const char *q_exclude,
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
    n = build_canonical_query(c->req.query, q_exclude, out + o, cap - o);
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

/* Credential = ak/yyyymmdd/region/service/aws4_request. Fills the
 * access_key/date/region/service/scope fields of `out`. */
static int parse_credential(s3_str_t cred, auth_parts_t *out) {
    s3_str_t parts[5] = { S3_STR_NULL };
    int np = 0;
    size_t p = 0;
    while (p < cred.n && np < 5) {
        size_t s = p;
        while (p < cred.n && cred.p[p] != '/') p++;
        parts[np++] = (s3_str_t){ cred.p + s, p - s };
        if (p < cred.n) p++;
    }
    if (np != 5 || p != cred.n) return -1;
    if (!s3_str_eq_lit(parts[4], "aws4_request")) return -1;
    if (parts[0].n == 0) return -1;
    if (parts[1].n != 8) return -1;     /* yyyymmdd */
    for (size_t d = 0; d < 8; d++) {
        if (parts[1].p[d] < '0' || parts[1].p[d] > '9') return -1;
    }
    out->access_key = parts[0];
    out->date       = parts[1];
    out->region     = parts[2];
    out->service    = parts[3];
    /* scope = "date/region/service/aws4_request" */
    out->scope      = (s3_str_t){ cred.p + parts[0].n + 1,
                                  cred.n - parts[0].n - 1 };
    return 0;
}

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

    if (parse_credential(cred, out) < 0) return -1;
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
    return sigv4_verify_id(v, c, NULL);
}

/* Everything needed to verify one request's signature, from either the
 * Authorization header or a presigned URL's X-Amz-* query parameters. */
typedef struct {
    auth_parts_t ap;           /* credential pieces + signed headers */
    s3_str_t     signature;
    s3_str_t     amz_date;
    s3_str_t     body_hash;
    int64_t      expires;      /* presigned: X-Amz-Expires seconds */
    int          is_presigned;
} auth_params_t;

static int count_headers(const conn_t *c, const char *lc_name) {
    int n = 0;
    for (size_t i = 0; i < c->req.n_headers; i++)
        if (s3_str_eq_lit(c->req.headers[i].k, lc_name)) n++;
    return n;
}

static int parse_uint(s3_str_t v, int64_t max, int64_t *out) {
    if (v.n == 0 || v.n > 18) return -1;
    int64_t x = 0;
    for (size_t i = 0; i < v.n; i++) {
        if (v.p[i] < '0' || v.p[i] > '9') return -1;
        x = x * 10 + (v.p[i] - '0');
    }
    if (x > max) return -1;
    *out = x;
    return 0;
}

int sigv4_has_presign(const conn_t *c) {
    return conn_query_get(c, "X-Amz-Signature") != NULL;
}

/* Fill *p from the Authorization header or the presign query (never
 * both). Values point into the request; nothing is verified yet beyond
 * shape. */
static s3_err_t extract_auth_params(const conn_t *c, auth_params_t *p) {
    static const s3_str_t empty_sha256 = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 64
    };
    memset(p, 0, sizeof(*p));
    int n_auth = count_headers(c, "authorization");
    int presign = sigv4_has_presign(c);
    if (n_auth > 0 && presign) return S3_ERR_INVALID_ARGUMENT;
    /* Duplicates are a parser-differential risk with the proxy. */
    if (n_auth > 1 || count_headers(c, "x-amz-date") > 1
        || count_headers(c, "x-amz-content-sha256") > 1
        || count_headers(c, "host") > 1)
        return S3_ERR_ACCESS_DENIED;

    if (!presign) {
        const s3_str_t *auth_h = hdr_lookup(c, "authorization");
        if (!auth_h) return S3_ERR_ACCESS_DENIED;
        if (parse_authorization(*auth_h, &p->ap) < 0) return S3_ERR_ACCESS_DENIED;
        p->signature = p->ap.signature;
        const s3_str_t *date_h = hdr_lookup(c, "x-amz-date");
        if (!date_h) return S3_ERR_ACCESS_DENIED;
        p->amz_date = *date_h;
        /* If x-amz-content-sha256 is absent, AWS SDKs sign SHA-256("")
         * (botocore does this for GET/HEAD/DELETE). Mirror that. */
        const s3_str_t *bh_h = hdr_lookup(c, "x-amz-content-sha256");
        p->body_hash = bh_h ? *bh_h : empty_sha256;
        return S3_OK;
    }

    static const char *const qnames[] = {
        "X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires",
        "X-Amz-SignedHeaders", "X-Amz-Signature", "X-Amz-Content-Sha256",
        "X-Amz-Security-Token",
    };
    for (size_t i = 0; i < sizeof(qnames) / sizeof(*qnames); i++)
        if (conn_query_count(c, qnames[i]) > 1) return S3_ERR_AUTH_QUERY_PARAMS;
    if (conn_query_get(c, "X-Amz-Security-Token")) return S3_ERR_NOT_IMPLEMENTED;

    const conn_qparam_t *alg  = conn_query_get(c, "X-Amz-Algorithm");
    const conn_qparam_t *cred = conn_query_get(c, "X-Amz-Credential");
    const conn_qparam_t *date = conn_query_get(c, "X-Amz-Date");
    const conn_qparam_t *exp  = conn_query_get(c, "X-Amz-Expires");
    const conn_qparam_t *sh   = conn_query_get(c, "X-Amz-SignedHeaders");
    const conn_qparam_t *sig  = conn_query_get(c, "X-Amz-Signature");
    const conn_qparam_t *bh   = conn_query_get(c, "X-Amz-Content-Sha256");
    if (!alg || !cred || !date || !exp || !sh || !sig)
        return S3_ERR_AUTH_QUERY_PARAMS;
    if (!s3_str_eq_lit(alg->v, "AWS4-HMAC-SHA256")) return S3_ERR_AUTH_QUERY_PARAMS;
    if (parse_credential(cred->v, &p->ap) < 0) return S3_ERR_AUTH_QUERY_PARAMS;
    if (parse_uint(exp->v, 1000000000, &p->expires) < 0
        || p->expires < 1 || p->expires > 604800)
        return S3_ERR_AUTH_QUERY_PARAMS;
    if (sh->v.n == 0) return S3_ERR_AUTH_QUERY_PARAMS;
    p->ap.signed_headers = sh->v;
    p->signature = sig->v;
    p->amz_date = date->v;
    p->body_hash = bh ? bh->v : S3_STR_LIT("UNSIGNED-PAYLOAD");
    p->is_presigned = 1;
    return S3_OK;
}

/* Is `name` (lowercase) one of the semicolon-separated signed headers? */
static int header_is_signed(s3_str_t signed_headers, s3_str_t name) {
    size_t i = 0;
    while (i < signed_headers.n) {
        size_t s = i;
        while (i < signed_headers.n && signed_headers.p[i] != ';') i++;
        if (i - s == name.n && memcmp(signed_headers.p + s, name.p, name.n) == 0)
            return 1;
        if (i < signed_headers.n) i++;
    }
    return 0;
}

static s3_err_t verify_params(const sigv4_verifier_t *v, const conn_t *c,
                              const auth_params_t *p, sigv4_id_t *id_out) {
    /* S1: host must be signed (or a captured request replays against
     * another vhost/bucket mapping), and so must every x-amz-* header —
     * an unsigned x-amz-copy-source on a presigned PUT would otherwise
     * copy anything the signer can read. */
    if (!hdr_lookup(c, "host")) return S3_ERR_ACCESS_DENIED;
    if (!header_is_signed(p->ap.signed_headers, S3_STR_LIT("host")))
        return S3_ERR_ACCESS_DENIED;
    for (size_t i = 0; i < c->req.n_headers; i++) {
        s3_str_t k = c->req.headers[i].k;
        if (k.n >= 6 && memcmp(k.p, "x-amz-", 6) == 0
            && !header_is_signed(p->ap.signed_headers, k))
            return S3_ERR_ACCESS_DENIED;
    }
    /* Scope: service s3, date = date part of X-Amz-Date. */
    if (!s3_str_eq_lit(p->ap.service, "s3")) return S3_ERR_ACCESS_DENIED;
    if (p->amz_date.n < 8 || memcmp(p->amz_date.p, p->ap.date.p, 8) != 0)
        return S3_ERR_ACCESS_DENIED;

    int64_t now = v->fixed_now ? v->fixed_now : (int64_t)time(NULL);
    int64_t req_t;
    if (parse_amz_date(p->amz_date, &req_t) < 0) return S3_ERR_ACCESS_DENIED;
    if (p->is_presigned) {
        int64_t max = v->presign_max_expires > 0 ? v->presign_max_expires : 604800;
        if (p->expires > max) return S3_ERR_AUTH_QUERY_PARAMS;
        if (req_t > now + v->max_skew) return S3_ERR_REQUEST_TIME_TOO_SKEWED;
        if (now > req_t + p->expires) return S3_ERR_PRESIGN_EXPIRED;
    } else {
        int64_t delta = req_t > now ? req_t - now : now - req_t;
        if (delta > v->max_skew) return S3_ERR_REQUEST_TIME_TOO_SKEWED;
    }

    /* Unknown, disabled and expired keys get the same AccessDenied after
     * the same HMAC work (no timing or error-code oracle); the real
     * reason goes to the audit log only. */
    static const uint8_t dummy_secret[40] = "fs3-unknown-key-dummy-secret-0123456789";
    static const cred_t dummy = { .access_key = "", .user = "",
                                  .secret_key = (uint8_t *)dummy_secret,
                                  .secret_len = sizeof(dummy_secret) };
    const char *deny = NULL;
    const cred_t *cr = cred_lookup(v, p->ap.access_key.p, p->ap.access_key.n);
    if (!cr) { deny = "unknown_key"; cr = &dummy; }
    else if (cr->attrs.disabled) deny = "key_disabled";
    else if (cr->attrs.expires && now >= cr->attrs.expires) deny = "key_expired";
    else if (p->is_presigned && cr->attrs.expires && req_t + p->expires > cr->attrs.expires)
        deny = "presign_outlives_key";      /* a URL may not outlive its key */

    char *cr_buf = malloc(CR_BUF_SZ);
    if (!cr_buf) return S3_ERR_INTERNAL;
    int cr_n = build_canonical_request(c, p->ap.signed_headers, p->body_hash,
                                       p->is_presigned ? "X-Amz-Signature" : NULL,
                                       cr_buf, CR_BUF_SZ);
    if (cr_n < 0) { free(cr_buf); return S3_ERR_ACCESS_DENIED; }

    uint8_t cr_hash[32];
    sha256(cr_buf, (size_t)cr_n, cr_hash);
    free(cr_buf);

    char sts[STS_BUF_SZ];
    int sts_n = build_string_to_sign(p->amz_date, p->ap.scope, cr_hash,
                                     sts, sizeof(sts));
    if (sts_n < 0) return S3_ERR_INTERNAL;

    uint8_t k_signing[32];
    derive_signing_key(cr->secret_key, cr->secret_len,
                       p->ap.date, p->ap.region, p->ap.service, k_signing);
    uint8_t mac[32];
    hmac_sha256(k_signing, 32, sts, (size_t)sts_n, mac);
    OPENSSL_cleanse(k_signing, sizeof(k_signing));

    char want[64];
    hex_encode(mac, 32, want);
    OPENSSL_cleanse(mac, sizeof(mac));

    int sig_ok = p->signature.n == 64 && CRYPTO_memcmp(want, p->signature.p, 64) == 0;
    if (deny) { g_deny_reason = deny; return S3_ERR_ACCESS_DENIED; }
    if (!sig_ok) return S3_ERR_SIGNATURE_DOES_NOT_MATCH;
    __atomic_store_n(&((cred_t *)cr)->last_used, now, __ATOMIC_RELAXED);

    int admin = is_admin(v, cr->user);
    /* --no-presign-admin: admin identities cannot mint bearer URLs. */
    if (p->is_presigned && admin && v->no_presign_admin)
        return S3_ERR_ACCESS_DENIED;
    /* Copied out: a SIGHUP reload may free this cred before the request
     * that verified it is finished. */
    if (id_out) {
        snprintf(id_out->user, sizeof(id_out->user), "%s", cr->user);
        snprintf(id_out->access_key, sizeof(id_out->access_key), "%s",
                 cr->access_key);
        id_out->is_admin = admin;
        id_out->presigned = p->is_presigned;
        id_out->read_only = cr->attrs.read_only;
    }
    return S3_OK;
}

int sigv4_header_signed(const conn_t *c, const char *lc_name) {
    auth_params_t p;
    if (!c || extract_auth_params(c, &p) != S3_OK) return 0;
    size_t ln = strlen(lc_name);
    const char *h = p.ap.signed_headers.p;
    size_t n = p.ap.signed_headers.n, i = 0;
    while (i < n) {
        size_t st = i;
        while (i < n && h[i] != ';') i++;
        if (i - st == ln && strncasecmp(h + st, lc_name, ln) == 0) return 1;
        i++;
    }
    return 0;
}

s3_err_t sigv4_verify_id(const sigv4_verifier_t *v, const conn_t *c,
                         sigv4_id_t *id_out) {
    g_deny_reason = NULL;
    if (!v || !c) return S3_ERR_ACCESS_DENIED;
    auth_params_t p;
    s3_err_t e = extract_auth_params(c, &p);
    if (e != S3_OK) return e;
    return verify_params(v, c, &p, id_out);
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

/* Returns 1 if the request is using STREAMING-AWS4-HMAC-SHA256-PAYLOAD,
 * 0 otherwise. */
int sigv4_is_chunked(const conn_t *c) {
    return sigv4_stream_mode(c) == SIGV4_STREAM_SIGNED;
}

sigv4_stream_mode_t sigv4_stream_mode(const conn_t *c) {
    const s3_str_t *bh = hdr_lookup(c, "x-amz-content-sha256");
    if (!bh) return SIGV4_STREAM_NONE;
    if (s3_str_eq_lit(*bh, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"))
        return SIGV4_STREAM_SIGNED;
    if (s3_str_eq_lit(*bh, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"))
        return SIGV4_STREAM_SIGNED_TRAILER;
    if (s3_str_eq_lit(*bh, "STREAMING-UNSIGNED-PAYLOAD-TRAILER"))
        return SIGV4_STREAM_UNSIGNED_TRAILER;
    return SIGV4_STREAM_NONE;
}

/* aws-chunked decoder. Line-oriented: chunk-size lines and trailer lines
 * are accumulated (bounded) up to '\n' and must end in "\r\n"; data is
 * streamed through without buffering.
 *
 *   SIZE_LINE  "<hex>[;chunk-signature=<64hex>]\r\n"
 *   DATA       chunk_size bytes
 *   DATA_CRLF  "\r\n"
 *   after the zero-size chunk:
 *     SIGNED:            FINAL_CRLF "\r\n" → DONE
 *     *_TRAILER:         TRAILER_LINE* until an empty line → DONE
 *
 * Signed chunks: string-to-sign
 *     AWS4-HMAC-SHA256-PAYLOAD\n<date>\n<scope>\n<prev-sig>\n
 *     SHA256("")\nSHA256(chunk-data)
 * Signed trailer: string-to-sign
 *     AWS4-HMAC-SHA256-TRAILER\n<date>\n<scope>\n<prev-sig>\n
 *     SHA256(<name>:<value>\n ...)
 *
 * Bounds (security review S2): size line ≤ 128 bytes and ≤ 16 hex
 * digits, single chunk ≤ 2^40, trailer line ≤ 256 bytes, ≤ 4 trailers,
 * only names announced in x-amz-trailer. */

#define CHUNK_LINE_MAX     256
#define CHUNK_MAX_TRAILERS 4
#define CHUNK_MAX_SIZE     (1ull << 40)

typedef enum {
    CST_SIZE_LINE = 0,
    CST_DATA,
    CST_DATA_CRLF,
    CST_FINAL_CRLF,
    CST_TRAILER_LINE,
    CST_DONE,
    CST_ERROR,
} chunk_state_t;

struct sigv4_chunk_decoder {
    sigv4_stream_mode_t mode;
    int      verify;                /* check chunk/trailer signatures */

    /* Crypto state (immutable after begin) */
    uint8_t  signing_key[32];
    char     amz_date[16];
    size_t   amz_date_n;
    char     scope[128];
    size_t   scope_n;

    /* Rolling state */
    char     prev_sig[64];
    chunk_state_t state;
    char     line[CHUNK_LINE_MAX];
    size_t   line_n;
    int      crlf_seen;             /* bytes of a 2-byte CRLF consumed */
    uint64_t chunk_size;
    uint64_t chunk_remaining;
    char     chunk_sig[64];
    EVP_MD_CTX *data_hash_ctx;
    int      seen_terminator;
    uint64_t expected_decoded;
    uint64_t total_decoded;

    /* Trailers */
    char     allowed[CHUNK_MAX_TRAILERS][64];   /* from x-amz-trailer */
    int      n_allowed;
    char     tname[CHUNK_MAX_TRAILERS][64];
    char     tval[CHUNK_MAX_TRAILERS][CHUNK_LINE_MAX];
    size_t   tval_n[CHUNK_MAX_TRAILERS];
    int      n_trailers;
    EVP_MD_CTX *trailer_hash_ctx;   /* SHA-256 of canonical trailers */
    int      trailer_sig_ok;

    sigv4_chunk_data_cb on_data;
    void               *user;
};

static int hexdig(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static int is_hex64(const char *p) {
    for (int j = 0; j < 64; j++) if (hexdig(p[j]) < 0) return 0;
    return 1;
}

/* Parse a chunk-size line (CRLF stripped). Signed modes need exactly
 * ";chunk-signature=<64 hex>"; the unsigned mode takes a bare size and
 * ignores any chunk extensions. */
static int parse_size_line(sigv4_chunk_decoder_t *d, const char *line, size_t n) {
    size_t i = 0;
    while (i < n && line[i] != ';') i++;
    if (i == 0 || i > 16) return -1;
    uint64_t sz = 0;
    for (size_t j = 0; j < i; j++) {
        int v = hexdig(line[j]);
        if (v < 0) return -1;
        sz = (sz << 4) | (uint64_t)v;
    }
    if (sz > CHUNK_MAX_SIZE) return -1;
    if (d->mode == SIGV4_STREAM_UNSIGNED_TRAILER) {
        d->chunk_size = sz;
        return 0;
    }
    static const char tag[] = ";chunk-signature=";
    if (n - i != sizeof(tag) - 1 + 64) return -1;
    if (memcmp(line + i, tag, sizeof(tag) - 1) != 0) return -1;
    const char *sig = line + i + sizeof(tag) - 1;
    if (!is_hex64(sig)) return -1;
    memcpy(d->chunk_sig, sig, 64);
    d->chunk_size = sz;
    return 0;
}

/* Verify the current chunk's signature (data hash finalized here). */
static int verify_chunk_sig(sigv4_chunk_decoder_t *d) {
    static const char EMPTY_HASH[] =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    uint8_t data_mac[32];
    char    data_hex[64];
    unsigned int n = 32;
    EVP_DigestFinal_ex(d->data_hash_ctx, data_mac, &n);
    if (!d->verify) return 1;
    hex_encode(data_mac, 32, data_hex);

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

    uint8_t mac[32];
    hmac_sha256(d->signing_key, 32, sts, (size_t)o, mac);
    char want[64];
    hex_encode(mac, 32, want);
    int ok = (CRYPTO_memcmp(want, d->chunk_sig, 64) == 0);
    if (ok) memcpy(d->prev_sig, d->chunk_sig, 64);
    return ok;
}

static int verify_trailer_sig(sigv4_chunk_decoder_t *d, const char *sig) {
    uint8_t th[32];
    unsigned int n = 32;
    EVP_DigestFinal_ex(d->trailer_hash_ctx, th, &n);
    if (!d->verify) return 1;
    char th_hex[64];
    hex_encode(th, 32, th_hex);
    char sts[512];
    int o = 0;
    static const char prefix[] = "AWS4-HMAC-SHA256-TRAILER\n";
    memcpy(sts + o, prefix, sizeof(prefix) - 1); o += (int)sizeof(prefix) - 1;
    memcpy(sts + o, d->amz_date, d->amz_date_n);  o += (int)d->amz_date_n;
    sts[o++] = '\n';
    memcpy(sts + o, d->scope, d->scope_n);        o += (int)d->scope_n;
    sts[o++] = '\n';
    memcpy(sts + o, d->prev_sig, 64);             o += 64;
    sts[o++] = '\n';
    memcpy(sts + o, th_hex, 64);                  o += 64;
    uint8_t mac[32];
    hmac_sha256(d->signing_key, 32, sts, (size_t)o, mac);
    char want[64];
    hex_encode(mac, 32, want);
    return CRYPTO_memcmp(want, sig, 64) == 0;
}

/* A complete trailer line (CRLF stripped). Empty line ends the stream. */
static int handle_trailer_line(sigv4_chunk_decoder_t *d, const char *line,
                               size_t n) {
    if (n == 0) {
        if (d->mode == SIGV4_STREAM_SIGNED_TRAILER && !d->trailer_sig_ok)
            return -1;
        d->state = CST_DONE;
        return 0;
    }
    if (d->trailer_sig_ok) return -1;     /* nothing after the signature */
    const char *colon = memchr(line, ':', n);
    if (!colon || colon == line) return -1;
    size_t kn = (size_t)(colon - line);
    if (kn >= sizeof(d->tname[0])) return -1;
    char name[64];
    for (size_t i = 0; i < kn; i++) {
        char ch = line[i];
        name[i] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
    }
    name[kn] = '\0';
    const char *v = colon + 1;
    size_t vn = n - kn - 1;
    while (vn && (*v == ' ' || *v == '\t')) { v++; vn--; }
    while (vn && (v[vn-1] == ' ' || v[vn-1] == '\t')) vn--;

    if (strcmp(name, "x-amz-trailer-signature") == 0) {
        if (d->mode != SIGV4_STREAM_SIGNED_TRAILER) return -1;
        if (vn != 64 || !is_hex64(v)) return -1;
        if (!verify_trailer_sig(d, v)) return -1;
        d->trailer_sig_ok = 1;
        return 0;
    }
    int allowed = 0;
    for (int i = 0; i < d->n_allowed; i++)
        if (strcmp(d->allowed[i], name) == 0) allowed = 1;
    if (!allowed || d->n_trailers >= CHUNK_MAX_TRAILERS) return -1;
    for (int i = 0; i < d->n_trailers; i++)
        if (strcmp(d->tname[i], name) == 0) return -1;   /* duplicate */
    int t = d->n_trailers++;
    memcpy(d->tname[t], name, kn + 1);
    memcpy(d->tval[t], v, vn);
    d->tval_n[t] = vn;
    /* Canonical form for the trailer signature: "name:value\n". */
    EVP_DigestUpdate(d->trailer_hash_ctx, name, kn);
    EVP_DigestUpdate(d->trailer_hash_ctx, ":", 1);
    EVP_DigestUpdate(d->trailer_hash_ctx, v, vn);
    EVP_DigestUpdate(d->trailer_hash_ctx, "\n", 1);
    return 0;
}

/* Parse x-amz-trailer: "name[, name...]" into d->allowed. */
static int load_allowed_trailers(sigv4_chunk_decoder_t *d, const conn_t *c) {
    const s3_str_t *h = hdr_lookup(c, "x-amz-trailer");
    if (!h) return 0;
    size_t i = 0;
    while (i < h->n) {
        while (i < h->n && (h->p[i] == ' ' || h->p[i] == ',')) i++;
        size_t s = i;
        while (i < h->n && h->p[i] != ',') i++;
        size_t e = i;
        while (e > s && h->p[e-1] == ' ') e--;
        if (e == s) continue;
        if (d->n_allowed >= CHUNK_MAX_TRAILERS || e - s >= 64) return -1;
        char *dst = d->allowed[d->n_allowed++];
        for (size_t j = s; j < e; j++) {
            char ch = h->p[j];
            dst[j - s] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
        }
        dst[e - s] = '\0';
    }
    return 0;
}

sigv4_chunk_decoder_t *sigv4_chunk_begin(const sigv4_verifier_t *v,
                                          const conn_t *c,
                                          uint64_t expected_decoded,
                                          sigv4_chunk_data_cb on_data,
                                          void *user) {
    return sigv4_chunk_begin_mode(v, c, SIGV4_STREAM_SIGNED, 1,
                                  expected_decoded, on_data, user);
}

sigv4_chunk_decoder_t *sigv4_chunk_begin_mode(const sigv4_verifier_t *v,
                                              const conn_t *c,
                                              sigv4_stream_mode_t mode,
                                              int verify,
                                              uint64_t expected_decoded,
                                              sigv4_chunk_data_cb on_data,
                                              void *user) {
    if (!c || mode == SIGV4_STREAM_NONE) return NULL;
    if (mode == SIGV4_STREAM_UNSIGNED_TRAILER) verify = 0;

    sigv4_chunk_decoder_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->mode = mode;
    d->verify = verify;
    d->state = CST_SIZE_LINE;
    d->on_data = on_data;
    d->user = user;
    d->expected_decoded = expected_decoded;

    if (verify) {
        if (!v) { free(d); return NULL; }
        /* The verifier already accepted these, so this should succeed. */
        auth_params_t p;
        if (extract_auth_params(c, &p) != 0
            || p.signature.n != 64 || p.amz_date.n > sizeof(d->amz_date)
            || p.ap.scope.n > sizeof(d->scope)) {
            free(d); return NULL;
        }
        const cred_t *cr = cred_lookup(v, p.ap.access_key.p, p.ap.access_key.n);
        if (!cr) { free(d); return NULL; }
        memcpy(d->amz_date, p.amz_date.p, p.amz_date.n);
        d->amz_date_n = p.amz_date.n;
        memcpy(d->scope, p.ap.scope.p, p.ap.scope.n);
        d->scope_n = p.ap.scope.n;
        memcpy(d->prev_sig, p.signature.p, 64);
        derive_signing_key(cr->secret_key, cr->secret_len,
                           p.ap.date, p.ap.region, p.ap.service,
                           d->signing_key);
    }
    if (load_allowed_trailers(d, c) < 0) { sigv4_chunk_free(d); return NULL; }

    d->data_hash_ctx = EVP_MD_CTX_new();
    d->trailer_hash_ctx = EVP_MD_CTX_new();
    if (!d->data_hash_ctx || !d->trailer_hash_ctx
        || EVP_DigestInit_ex(d->data_hash_ctx, EVP_sha256(), NULL) != 1
        || EVP_DigestInit_ex(d->trailer_hash_ctx, EVP_sha256(), NULL) != 1) {
        sigv4_chunk_free(d);
        return NULL;
    }
    return d;
}

#define FAIL() do { d->state = CST_ERROR; return -1; } while (0)

/* Accumulate a CRLF-terminated line. Returns 1 when a full line is in
 * d->line (CRLF stripped, length d->line_n), 0 if more input is needed,
 * -1 on overflow / bare LF. */
static int take_line(sigv4_chunk_decoder_t *d, const char *data, size_t len,
                     size_t *i) {
    while (*i < len) {
        char ch = data[(*i)++];
        if (ch == '\n') {
            if (d->line_n == 0 || d->line[d->line_n - 1] != '\r') return -1;
            d->line_n--;
            return 1;
        }
        if (d->line_n >= sizeof(d->line)) return -1;
        d->line[d->line_n++] = ch;
    }
    return 0;
}

/* Consume the rest of a 2-byte CRLF. Returns 1 done, 0 need more, -1 bad. */
static int take_crlf(sigv4_chunk_decoder_t *d, const char *data, size_t len,
                     size_t *i) {
    while (*i < len && d->crlf_seen < 2) {
        char want = d->crlf_seen == 0 ? '\r' : '\n';
        if (data[*i] != want) return -1;
        (*i)++;
        d->crlf_seen++;
    }
    if (d->crlf_seen < 2) return 0;
    d->crlf_seen = 0;
    return 1;
}

int sigv4_chunk_feed(sigv4_chunk_decoder_t *d, const char *data, size_t len) {
    if (!d || d->state == CST_ERROR) return -1;
    size_t i = 0;
    while (i < len) {
        switch (d->state) {
        case CST_SIZE_LINE: {
            int r = take_line(d, data, len, &i);
            if (r < 0) FAIL();
            if (r == 0) return 0;
            if (parse_size_line(d, d->line, d->line_n) < 0) FAIL();
            d->line_n = 0;
            d->chunk_remaining = d->chunk_size;
            d->total_decoded += d->chunk_size;
            if (d->expected_decoded && d->total_decoded > d->expected_decoded)
                FAIL();
            EVP_DigestInit_ex(d->data_hash_ctx, EVP_sha256(), NULL);
            if (d->chunk_size == 0) {
                if (d->mode != SIGV4_STREAM_UNSIGNED_TRAILER
                    && !verify_chunk_sig(d)) FAIL();
                d->seen_terminator = 1;
                d->state = d->mode == SIGV4_STREAM_SIGNED ? CST_FINAL_CRLF
                                                          : CST_TRAILER_LINE;
            } else {
                d->state = CST_DATA;
            }
            break;
        }
        case CST_DATA: {
            size_t take = len - i;
            if ((uint64_t)take > d->chunk_remaining) take = (size_t)d->chunk_remaining;
            if (d->mode != SIGV4_STREAM_UNSIGNED_TRAILER)
                EVP_DigestUpdate(d->data_hash_ctx, data + i, take);
            if (d->on_data && d->on_data(d->user, data + i, take) < 0) FAIL();
            i += take;
            d->chunk_remaining -= take;
            if (d->chunk_remaining == 0) {
                if (d->mode != SIGV4_STREAM_UNSIGNED_TRAILER
                    && !verify_chunk_sig(d)) FAIL();
                d->state = CST_DATA_CRLF;
            }
            break;
        }
        case CST_DATA_CRLF:
        case CST_FINAL_CRLF: {
            int r = take_crlf(d, data, len, &i);
            if (r < 0) FAIL();
            if (r == 0) return 0;
            d->state = d->state == CST_FINAL_CRLF ? CST_DONE : CST_SIZE_LINE;
            break;
        }
        case CST_TRAILER_LINE: {
            int r = take_line(d, data, len, &i);
            if (r < 0) FAIL();
            if (r == 0) return 0;
            if (handle_trailer_line(d, d->line, d->line_n) < 0) FAIL();
            d->line_n = 0;
            break;
        }
        case CST_DONE:
            /* Tolerate a stray trailing CRLF some clients send; anything
             * else after the end of the stream is an error. */
            if (data[i] != '\r' && data[i] != '\n') FAIL();
            i++;
            break;
        case CST_ERROR:
            return -1;
        }
    }
    return 0;
}

#undef FAIL

int sigv4_chunk_finish(sigv4_chunk_decoder_t *d) {
    if (!d) return -1;
    if (d->state != CST_DONE) return -1;
    if (!d->seen_terminator) return -1;
    if (d->expected_decoded != 0
        && d->total_decoded != d->expected_decoded) {
        return -1;
    }
    return 0;
}

const char *sigv4_chunk_trailer(const sigv4_chunk_decoder_t *d,
                                const char *name, size_t *len_out) {
    if (!d) return NULL;
    for (int i = 0; i < d->n_trailers; i++) {
        if (strcmp(d->tname[i], name) == 0) {
            *len_out = d->tval_n[i];
            return d->tval[i];
        }
    }
    return NULL;
}

void sigv4_chunk_free(sigv4_chunk_decoder_t *d) {
    if (!d) return;
    if (d->data_hash_ctx) EVP_MD_CTX_free(d->data_hash_ctx);
    if (d->trailer_hash_ctx) EVP_MD_CTX_free(d->trailer_hash_ctx);
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
    return build_canonical_request(c, sh, bh, NULL, out, cap);
}

int sigv4_test_canon_query(const char *q, size_t q_n, char *out, size_t cap) {
    s3_str_t s = { q, q_n };
    return build_canonical_query(s, NULL, out, cap);
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
