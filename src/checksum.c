/* src/checksum.c — streaming checksums for x-amz-checksum-* (item 1). */

#include "checksum.h"

#include <openssl/evp.h>

#include <pthread.h>
#include <string.h>

/* ===================================================================== */
/* Slice-by-8 tables                                                      */
/* ===================================================================== */

#define POLY_CRC32     0xEDB88320u                 /* reflected 0x04C11DB7 */
#define POLY_CRC32C    0x82F63B78u                 /* reflected 0x1EDC6F41 */
#define POLY_CRC64NVME 0x9A6C9329AC4BC9B5ull       /* reflected 0xAD93D23594C93659 */

static uint32_t T32[8][256], T32C[8][256];
static uint64_t T64[8][256];
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static int g_have_sse42;
/* Test seam: force the portable CRC32C path. */
int cksum_disable_hw;

static void init_tables(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t a = i, b = i;
        uint64_t c = i;
        for (int k = 0; k < 8; k++) {
            a = (a >> 1) ^ ((a & 1) ? POLY_CRC32 : 0);
            b = (b >> 1) ^ ((b & 1) ? POLY_CRC32C : 0);
            c = (c >> 1) ^ ((c & 1) ? POLY_CRC64NVME : 0);
        }
        T32[0][i] = a; T32C[0][i] = b; T64[0][i] = c;
    }
    for (int t = 1; t < 8; t++) {
        for (int i = 0; i < 256; i++) {
            T32[t][i]  = (T32[t-1][i] >> 8)  ^ T32[0][T32[t-1][i] & 0xff];
            T32C[t][i] = (T32C[t-1][i] >> 8) ^ T32C[0][T32C[t-1][i] & 0xff];
            T64[t][i]  = (T64[t-1][i] >> 8)  ^ T64[0][T64[t-1][i] & 0xff];
        }
    }
#if defined(__x86_64__) && defined(__GNUC__)
    __builtin_cpu_init();
    g_have_sse42 = __builtin_cpu_supports("sse4.2");
#endif
}

static uint32_t crc32_sw(uint32_t (*T)[256], uint32_t crc,
                         const uint8_t *p, size_t n) {
    while (n && ((uintptr_t)p & 7)) { crc = (crc >> 8) ^ T[0][(crc ^ *p++) & 0xff]; n--; }
    while (n >= 8) {
        uint32_t lo = (uint32_t)p[0] | (uint32_t)p[1] << 8
                    | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
        crc ^= lo;
        crc = T[7][crc & 0xff] ^ T[6][(crc >> 8) & 0xff]
            ^ T[5][(crc >> 16) & 0xff] ^ T[4][crc >> 24]
            ^ T[3][p[4]] ^ T[2][p[5]] ^ T[1][p[6]] ^ T[0][p[7]];
        p += 8; n -= 8;
    }
    while (n--) crc = (crc >> 8) ^ T[0][(crc ^ *p++) & 0xff];
    return crc;
}

#if defined(__x86_64__) && defined(__GNUC__)
__attribute__((target("sse4.2")))
static uint32_t crc32c_hw(uint32_t crc, const uint8_t *p, size_t n) {
    uint64_t c = crc;
    while (n && ((uintptr_t)p & 7)) { c = __builtin_ia32_crc32qi((uint32_t)c, *p++); n--; }
    while (n >= 8) {
        uint64_t v;
        memcpy(&v, p, 8);
        c = __builtin_ia32_crc32di(c, v);
        p += 8; n -= 8;
    }
    while (n--) c = __builtin_ia32_crc32qi((uint32_t)c, *p++);
    return (uint32_t)c;
}
#endif

static uint64_t crc64_sw(uint64_t crc, const uint8_t *p, size_t n) {
    while (n >= 8) {
        uint64_t v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
        crc ^= v;
        crc = T64[7][crc & 0xff] ^ T64[6][(crc >> 8) & 0xff]
            ^ T64[5][(crc >> 16) & 0xff] ^ T64[4][(crc >> 24) & 0xff]
            ^ T64[3][(crc >> 32) & 0xff] ^ T64[2][(crc >> 40) & 0xff]
            ^ T64[1][(crc >> 48) & 0xff] ^ T64[0][crc >> 56];
        p += 8; n -= 8;
    }
    while (n--) crc = (crc >> 8) ^ T64[0][(crc ^ *p++) & 0xff];
    return crc;
}

/* ===================================================================== */
/* Streaming API                                                          */
/* ===================================================================== */

size_t cksum_digest_len(int algo) {
    switch (algo) {
    case S3_CKSUM_CRC32: case S3_CKSUM_CRC32C: return 4;
    case S3_CKSUM_CRC64NVME: return 8;
    case S3_CKSUM_SHA1: return 20;
    case S3_CKSUM_SHA256: return 32;
    case CKSUM_MD5: return 16;
    default: return 0;
    }
}

int cksum_begin(cksum_ctx_t *k, int algo) {
    pthread_once(&g_once, init_tables);
    memset(k, 0, sizeof(*k));
    const EVP_MD *md = NULL;
    switch (algo) {
    case S3_CKSUM_CRC32: case S3_CKSUM_CRC32C: k->crc32 = 0xFFFFFFFFu; break;
    case S3_CKSUM_CRC64NVME: k->crc64 = ~0ull; break;
    case S3_CKSUM_SHA1:   md = EVP_sha1();   break;
    case S3_CKSUM_SHA256: md = EVP_sha256(); break;
    case CKSUM_MD5:       md = EVP_md5();    break;
    default: return -1;
    }
    if (md) {
        EVP_MD_CTX *c = EVP_MD_CTX_new();
        if (!c || EVP_DigestInit_ex(c, md, NULL) != 1) {
            EVP_MD_CTX_free(c);
            return -1;
        }
        k->md = c;
    }
    k->algo = algo;
    return 0;
}

void cksum_update(cksum_ctx_t *k, const void *p, size_t n) {
    if (!k->algo || n == 0) return;
    const uint8_t *b = p;
    switch (k->algo) {
    case S3_CKSUM_CRC32: k->crc32 = crc32_sw(T32, k->crc32, b, n); break;
    case S3_CKSUM_CRC32C:
#if defined(__x86_64__) && defined(__GNUC__)
        if (g_have_sse42 && !cksum_disable_hw) { k->crc32 = crc32c_hw(k->crc32, b, n); break; }
#endif
        k->crc32 = crc32_sw(T32C, k->crc32, b, n);
        break;
    case S3_CKSUM_CRC64NVME: k->crc64 = crc64_sw(k->crc64, b, n); break;
    default: EVP_DigestUpdate((EVP_MD_CTX *)k->md, b, n); break;
    }
}

int cksum_final(cksum_ctx_t *k, uint8_t out[CKSUM_MAX_DIGEST], size_t *len) {
    if (!k->algo) return -1;
    switch (k->algo) {
    case S3_CKSUM_CRC32: case S3_CKSUM_CRC32C: {
        uint32_t v = ~k->crc32;
        out[0] = (uint8_t)(v >> 24); out[1] = (uint8_t)(v >> 16);
        out[2] = (uint8_t)(v >> 8);  out[3] = (uint8_t)v;
        *len = 4;
        break;
    }
    case S3_CKSUM_CRC64NVME: {
        uint64_t v = ~k->crc64;
        for (int i = 0; i < 8; i++) out[i] = (uint8_t)(v >> (56 - 8 * i));
        *len = 8;
        break;
    }
    default: {
        unsigned int n = 0;
        if (EVP_DigestFinal_ex((EVP_MD_CTX *)k->md, out, &n) != 1) return -1;
        *len = n;
        break;
    }
    }
    k->algo = 0;
    return 0;
}

void cksum_free(cksum_ctx_t *k) {
    if (k->md) EVP_MD_CTX_free((EVP_MD_CTX *)k->md);
    memset(k, 0, sizeof(*k));
}

int cksum_oneshot(int algo, const void *p, size_t n,
                  uint8_t out[CKSUM_MAX_DIGEST], size_t *len) {
    cksum_ctx_t k;
    if (cksum_begin(&k, algo) < 0) return -1;
    cksum_update(&k, p, n);
    int rc = cksum_final(&k, out, len);
    cksum_free(&k);
    return rc;
}

/* ===================================================================== */
/* Names                                                                  */
/* ===================================================================== */

static const struct { int algo; const char *lower, *upper, *xml, *hdr; } NAMES[] = {
    { S3_CKSUM_CRC32,     "crc32",     "CRC32",     "ChecksumCRC32",     "x-amz-checksum-crc32" },
    { S3_CKSUM_CRC32C,    "crc32c",    "CRC32C",    "ChecksumCRC32C",    "x-amz-checksum-crc32c" },
    { S3_CKSUM_SHA1,      "sha1",      "SHA1",      "ChecksumSHA1",      "x-amz-checksum-sha1" },
    { S3_CKSUM_SHA256,    "sha256",    "SHA256",    "ChecksumSHA256",    "x-amz-checksum-sha256" },
    { S3_CKSUM_CRC64NVME, "crc64nvme", "CRC64NVME", "ChecksumCRC64NVME", "x-amz-checksum-crc64nvme" },
};
#define N_NAMES (sizeof(NAMES) / sizeof(NAMES[0]))

static int ieq(s3_str_t a, const char *b) {
    size_t n = strlen(b);
    if (a.n != n) return 0;
    for (size_t i = 0; i < n; i++) {
        char x = a.p[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (x != b[i]) return 0;
    }
    return 1;
}

int cksum_algo_from_name(s3_str_t name) {
    for (size_t i = 0; i < N_NAMES; i++)
        if (ieq(name, NAMES[i].lower)) return NAMES[i].algo;
    return 0;
}

int cksum_algo_from_header(s3_str_t h) {
    for (size_t i = 0; i < N_NAMES; i++)
        if (ieq(h, NAMES[i].hdr)) return NAMES[i].algo;
    return 0;
}

#define NAME_FN(fn, field)                                   \
    const char *fn(int algo) {                               \
        for (size_t i = 0; i < N_NAMES; i++)                 \
            if (NAMES[i].algo == algo) return NAMES[i].field; \
        return "";                                           \
    }
NAME_FN(cksum_header_name, hdr)
NAME_FN(cksum_upper_name, upper)
NAME_FN(cksum_xml_name, xml)

/* ===================================================================== */
/* base64                                                                 */
/* ===================================================================== */

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_encode(const uint8_t *in, size_t n, char *out) {
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)in[i+1] << 8;
        if (i + 2 < n) v |= in[i+2];
        out[o++] = B64[(v >> 18) & 63];
        out[o++] = B64[(v >> 12) & 63];
        out[o++] = i + 1 < n ? B64[(v >> 6) & 63] : '=';
        out[o++] = i + 2 < n ? B64[v & 63] : '=';
    }
    out[o] = '\0';
    return o;
}

static int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int base64_decode(const char *in, size_t n, uint8_t *out, size_t cap) {
    if (n % 4 != 0) return -1;
    size_t o = 0;
    for (size_t i = 0; i < n; i += 4) {
        int v[4], pad = 0;
        for (int j = 0; j < 4; j++) {
            char c = in[i + j];
            if (c == '=') {
                /* Padding only in the last quantum's last two places. */
                if (i + 4 != n || j < 2) return -1;
                v[j] = 0; pad++;
            } else {
                if (pad) return -1;
                if ((v[j] = b64val(c)) < 0) return -1;
            }
        }
        uint32_t x = (uint32_t)v[0] << 18 | (uint32_t)v[1] << 12
                   | (uint32_t)v[2] << 6 | (uint32_t)v[3];
        size_t take = 3 - (size_t)pad;
        if (o + take > cap) return -1;
        out[o++] = (uint8_t)(x >> 16);
        if (take > 1) out[o++] = (uint8_t)(x >> 8);
        if (take > 2) out[o++] = (uint8_t)x;
    }
    return (int)o;
}
