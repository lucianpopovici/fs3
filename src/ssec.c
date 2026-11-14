/* src/ssec.c — SSE-C chunked AEAD (see include/ssec.h). */
#include "ssec.h"
#include "store.h"     /* S3_TLV_* */

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

static int hmac256(const uint8_t *k, size_t kn, const uint8_t *m, size_t mn, uint8_t out[32]) {
    unsigned int on = 32;
    return HMAC(EVP_sha256(), k, (int)kn, m, mn, out, &on) && on == 32 ? 0 : -1;
}

/* RFC 5869 with one output block (L = 32). */
int ssec_derive(const uint8_t key[32], const uint8_t salt[16], uint8_t kobj[32]) {
    uint8_t prk[32];
    if (hmac256(salt, 16, key, 32, prk) < 0) return -1;
    static const char info[] = "fs3-ssec-v1";
    uint8_t m[sizeof(info) - 1 + 1];
    memcpy(m, info, sizeof(info) - 1);
    m[sizeof(info) - 1] = 0x01;
    int rc = hmac256(prk, 32, m, sizeof(m), kobj);
    OPENSSL_cleanse(prk, sizeof(prk));
    return rc;
}

static void check_value(const uint8_t key[32], const uint8_t salt[16], uint8_t out[32]) {
    uint8_t m[16 + 5];
    memcpy(m, salt, 16);
    memcpy(m + 16, "check", 5);
    hmac256(key, 32, m, sizeof(m), out);
}

int ssec_info_new(const uint8_t key[32], ssec_info_t *out) {
    memset(out, 0, sizeof(*out));
    if (RAND_bytes(out->salt, 16) != 1) return -1;
    out->seg = SSEC_SEG;
    check_value(key, out->salt, out->check);
    return 0;
}

int ssec_key_matches(const uint8_t key[32], const ssec_info_t *i) {
    uint8_t c[32];
    check_value(key, i->salt, c);
    int ok = CRYPTO_memcmp(c, i->check, 32) == 0;
    OPENSSL_cleanse(c, sizeof(c));
    return ok;
}

static void nonce_of(uint32_t part, uint64_t idx, uint8_t n[12]) {
    for (int i = 0; i < 4; i++) n[i] = (uint8_t)(part >> (24 - 8 * i));
    for (int i = 0; i < 8; i++) n[4 + i] = (uint8_t)(idx >> (56 - 8 * i));
}

static int gcm(int enc, const uint8_t kobj[32], uint32_t part, uint64_t idx, int final,
               const char bucket_id[32], const uint8_t *in, size_t n, uint8_t *out,
               uint8_t tag[16]) {
    uint8_t nonce[12], aad[33];
    nonce_of(part, idx, nonce);
    memcpy(aad, bucket_id, 32);
    aad[32] = final ? 1 : 0;
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int len = 0, ok = x
        && EVP_CipherInit_ex(x, EVP_aes_256_gcm(), NULL, NULL, NULL, enc) == 1
        && EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1
        && EVP_CipherInit_ex(x, NULL, NULL, kobj, nonce, enc) == 1
        && EVP_CipherUpdate(x, NULL, &len, aad, sizeof(aad)) == 1
        && (n == 0 || EVP_CipherUpdate(x, out, &len, in, (int)n) == 1);
    if (ok && !enc) ok = EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1;
    if (ok) ok = EVP_CipherFinal_ex(x, out + (n ? (size_t)len : 0), &len) == 1;
    if (ok && enc) ok = EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(x);
    return ok ? 0 : -1;
}

int ssec_seal(const uint8_t kobj[32], uint32_t part, uint64_t idx, int final,
              const char bucket_id[32], const uint8_t *pt, size_t n, uint8_t *out) {
    return gcm(1, kobj, part, idx, final, bucket_id, pt, n, out, out + n);
}

int ssec_open(const uint8_t kobj[32], uint32_t part, uint64_t idx, int final,
              const char bucket_id[32], const uint8_t *ct, size_t n, uint8_t *pt) {
    if (n < SSEC_TAG) return -1;
    uint8_t tag[16];
    memcpy(tag, ct + n - SSEC_TAG, SSEC_TAG);
    int rc = gcm(0, kobj, part, idx, final, bucket_id, ct, n - SSEC_TAG, pt, tag);
    if (rc < 0) OPENSSL_cleanse(pt, n - SSEC_TAG);       /* never hand out unauthenticated bytes */
    return rc;
}

uint64_t ssec_cipher_len(uint64_t plain, uint32_t seg) {
    uint64_t nseg = plain ? (plain + seg - 1) / seg : 1;
    return plain + SSEC_TAG * nseg;
}

uint64_t ssec_plain_len(uint64_t cipher, uint32_t seg) {
    uint64_t nseg = (cipher + seg + SSEC_TAG - 1) / (seg + SSEC_TAG);
    if (nseg == 0) nseg = 1;
    return cipher >= SSEC_TAG * nseg ? cipher - SSEC_TAG * nseg : 0;
}

static void put_u32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static void put_u64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i)); }
static uint32_t get_u32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t get_u64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
    return v;
}

size_t ssec_tlv_encode(const ssec_info_t *i, uint8_t out[6 + SSEC_TLV_PAYLOAD]) {
    out[0] = S3_TLV_SSEC; out[1] = 0;
    put_u32(out + 2, SSEC_TLV_PAYLOAD);
    out[6] = 1;
    put_u32(out + 7, i->seg);
    memcpy(out + 11, i->salt, 16);
    memcpy(out + 27, i->check, 32);
    return 6 + SSEC_TLV_PAYLOAD;
}

/* Walk records; return the payload of `type` (1), none (0), bad (-1). */
static int tlv_get(const uint8_t *t, size_t n, unsigned type, const uint8_t **p, uint32_t *len) {
    size_t o = 0;
    int found = 0;
    while (o < n) {
        if (n - o < 6) return -1;
        unsigned ty = (unsigned)t[o] | (unsigned)t[o + 1] << 8;
        uint32_t l = get_u32(t + o + 2);
        if (l > n - o - 6) return -1;
        if (ty == type) {
            if (found) return -1;                 /* exactly one */
            *p = t + o + 6; *len = l; found = 1;
        }
        o += 6 + l;
    }
    return found;
}

int ssec_tlv_find(const uint8_t *tlv, size_t n, ssec_info_t *out) {
    const uint8_t *p; uint32_t l;
    int r = tlv ? tlv_get(tlv, n, S3_TLV_SSEC, &p, &l) : 0;
    if (r <= 0) return r;
    if (l != SSEC_TLV_PAYLOAD || p[0] != 1) return -1;
    out->seg = get_u32(p + 1);
    if (out->seg != SSEC_SEG) return -1;          /* the only segment size written */
    memcpy(out->salt, p + 5, 16);
    memcpy(out->check, p + 21, 32);
    return 1;
}

size_t ssec_parttable_encode(const ssec_part_t *pt, size_t n, uint8_t *out) {
    out[0] = S3_TLV_PART_TABLE; out[1] = 0;
    put_u32(out + 2, (uint32_t)(12 * n));
    for (size_t i = 0; i < n; i++) {
        put_u32(out + 6 + 12 * i, pt[i].part);
        put_u64(out + 10 + 12 * i, pt[i].plain);
    }
    return 6 + 12 * n;
}

int ssec_parttable_find(const uint8_t *tlv, size_t n, ssec_part_t **out, size_t *n_out) {
    *out = NULL; *n_out = 0;
    const uint8_t *p; uint32_t l;
    int r = tlv ? tlv_get(tlv, n, S3_TLV_PART_TABLE, &p, &l) : 0;
    if (r <= 0) return r;
    if (l == 0 || l % 12 || l / 12 > 10000) return -1;
    size_t k = l / 12;
    ssec_part_t *a = malloc(k * sizeof(*a));
    if (!a) return -1;
    for (size_t i = 0; i < k; i++) {
        a[i].part = get_u32(p + 12 * i);
        a[i].plain = get_u64(p + 4 + 12 * i);
        if (a[i].part < 1 || a[i].part > 10000 || (i && a[i].part <= a[i - 1].part)
            || a[i].plain > (1ULL << 40)) {
            free(a); return -1;
        }
    }
    *out = a; *n_out = k;
    return 1;
}
