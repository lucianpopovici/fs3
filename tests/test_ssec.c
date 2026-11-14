/* tests/test_ssec.c — SSE-C chunked AEAD (round 2, item 8): fixed-vector
 * key derivation, round trips, wrong key, tamper cases (flip, swap two
 * segments, truncate at a segment boundary, splice from another object or
 * bucket), size algebra, and a fuzz run of the SSEC / PART_TABLE TLV
 * parsers: ./tests/test_ssec [iterations] */
#include "ssec.h"
#include "store.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pass, fail;
#define CHECK(c, msg) do { if (c) pass++; else { fail++; printf("FAIL %s:%d %s\n", __FILE__, __LINE__, msg); } } while (0)

static const char BID[33] = "0123456789abcdef0123456789abcdef";
static const char BID2[33] = "fedcba9876543210fedcba9876543210";

/* Seal a whole "object" the way the writer does: full segments non-final,
 * the last one final. Returns ciphertext length. */
static size_t seal_obj(const uint8_t k[32], uint32_t part, const char *bid,
                       const uint8_t *pt, size_t n, uint8_t *out, uint32_t seg) {
    size_t nseg = n ? (n + seg - 1) / seg : 1, o = 0;
    for (size_t i = 0; i < nseg; i++) {
        size_t len = i + 1 < nseg ? seg : n - i * seg;
        ssec_seal(k, part, i, i + 1 == nseg, bid, pt + i * seg, len, out + o);
        o += len + SSEC_TAG;
    }
    return o;
}

static int open_obj(const uint8_t k[32], uint32_t part, const char *bid,
                    const uint8_t *ct, size_t cn, uint8_t *pt, uint32_t seg) {
    size_t o = 0, i = 0, po = 0;
    while (o < cn) {
        size_t len = cn - o > seg + SSEC_TAG ? seg + SSEC_TAG : cn - o;
        int final = o + len == cn;
        if (ssec_open(k, part, i, final, bid, ct + o, len, pt + po) < 0) return -1;
        po += len - SSEC_TAG; o += len; i++;
    }
    return (int)po;
}

static void t_derive_vector(void) {
    uint8_t key[32], salt[16], k1[32], k2[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 16; i++) salt[i] = (uint8_t)(0xa0 + i);
    CHECK(ssec_derive(key, salt, k1) == 0, "derive");
    ssec_derive(key, salt, k2);
    CHECK(!memcmp(k1, k2, 32), "derive deterministic");
    /* Fixed vector (HKDF-SHA256, info "fs3-ssec-v1", L=32), cross-checked
     * with Python's hmac per RFC 5869: pins the on-disk format. */
    static const char want[] = "d32aab22b20432cb6b92b0c1e1d75340ea6356c1965913b50e95dd4fac29ead3";
    char hx[65];
    for (int i = 0; i < 32; i++) sprintf(hx + 2 * i, "%02x", k1[i]);
    CHECK(!strcmp(hx, want), "HKDF fixed vector");
    salt[0] ^= 1;
    ssec_derive(key, salt, k2);
    CHECK(memcmp(k1, k2, 32) != 0, "salt changes the key");
}

static void t_roundtrip_and_tamper(void) {
    uint8_t key[32], key2[32], k[32], k2[32];
    for (int i = 0; i < 32; i++) { key[i] = (uint8_t)(i * 7); key2[i] = (uint8_t)(i * 7 + 1); }
    ssec_info_t info, info2;
    CHECK(ssec_info_new(key, &info) == 0, "info");
    CHECK(ssec_key_matches(key, &info), "key check accepts the key");
    CHECK(!ssec_key_matches(key2, &info), "key check refuses another key");
    ssec_derive(key, info.salt, k);
    ssec_info_new(key, &info2);
    ssec_derive(key, info2.salt, k2);          /* same customer key, other object */
    const uint32_t seg = 4096;                  /* small segments for the test */
    size_t n = 3 * seg + 123;
    uint8_t *pt = malloc(n), *ct = malloc(n + 8 * SSEC_TAG), *back = malloc(n + 64);
    for (size_t i = 0; i < n; i++) pt[i] = (uint8_t)(i * 31 + 7);
    size_t cn = seal_obj(k, 0, BID, pt, n, ct, seg);
    CHECK(cn == ssec_cipher_len(n, seg), "cipher length");
    CHECK(ssec_plain_len(cn, seg) == n, "plain length inverse");
    CHECK(open_obj(k, 0, BID, ct, cn, back, seg) == (int)n && !memcmp(back, pt, n), "round trip");
    CHECK(memmem(ct, cn, pt, 64) == NULL, "ciphertext does not contain plaintext");
    /* flip one byte in each segment */
    for (size_t sgi = 0; sgi < 4; sgi++) {
        ct[sgi * (seg + SSEC_TAG) + 5] ^= 1;
        CHECK(open_obj(k, 0, BID, ct, cn, back, seg) < 0, "flip detected");
        ct[sgi * (seg + SSEC_TAG) + 5] ^= 1;
    }
    /* swap segments 0 and 1 */
    uint8_t *tmp = malloc(seg + SSEC_TAG);
    memcpy(tmp, ct, seg + SSEC_TAG);
    memcpy(ct, ct + seg + SSEC_TAG, seg + SSEC_TAG);
    memcpy(ct + seg + SSEC_TAG, tmp, seg + SSEC_TAG);
    CHECK(open_obj(k, 0, BID, ct, cn, back, seg) < 0, "segment swap detected");
    memcpy(ct + seg + SSEC_TAG, ct, seg + SSEC_TAG);
    memcpy(ct, tmp, seg + SSEC_TAG);
    CHECK(open_obj(k, 0, BID, ct, cn, back, seg) == (int)n, "restored");
    /* truncate at a segment boundary: the new last segment isn't "final" */
    CHECK(open_obj(k, 0, BID, ct, 2 * (seg + SSEC_TAG), back, seg) < 0, "truncation detected");
    /* splice a segment from another object (same customer key, other salt) */
    uint8_t *ct2 = malloc(n + 8 * SSEC_TAG);
    seal_obj(k2, 0, BID, pt, n, ct2, seg);
    memcpy(ct + (seg + SSEC_TAG), ct2 + (seg + SSEC_TAG), seg + SSEC_TAG);
    CHECK(open_obj(k, 0, BID, ct, cn, back, seg) < 0, "splice from another object detected");
    seal_obj(k, 0, BID, pt, n, ct, seg);
    /* other bucket, other part number */
    CHECK(open_obj(k, 0, BID2, ct, cn, back, seg) < 0, "moved to another bucket detected");
    CHECK(open_obj(k, 1, BID, ct, cn, back, seg) < 0, "wrong part number detected");
    /* empty object: one empty final segment */
    size_t en = seal_obj(k, 0, BID, pt, 0, ct, seg);
    CHECK(en == SSEC_TAG && open_obj(k, 0, BID, ct, en, back, seg) == 0, "empty object");
    /* exact multiple of the segment size */
    size_t mn = seal_obj(k, 0, BID, pt, 2 * seg, ct, seg);
    CHECK(mn == 2 * (seg + SSEC_TAG) && ssec_plain_len(mn, seg) == 2 * seg, "exact multiple");
    CHECK(open_obj(k, 0, BID, ct, mn, back, seg) == (int)(2 * seg), "exact multiple opens");
    free(pt); free(ct); free(back); free(tmp); free(ct2);
}

static void t_sizes(void) {
    for (uint64_t p = 0; p < 3 * SSEC_SEG + 5; p += 4093)
        if (ssec_plain_len(ssec_cipher_len(p, SSEC_SEG), SSEC_SEG) != p) { CHECK(0, "size algebra"); return; }
    CHECK(ssec_plain_len(ssec_cipher_len(SSEC_SEG, SSEC_SEG), SSEC_SEG) == SSEC_SEG, "size algebra");
}

static void t_tlv(void) {
    uint8_t key[32] = { 1 };
    ssec_info_t a, b;
    ssec_info_new(key, &a);
    uint8_t rec[6 + SSEC_TLV_PAYLOAD + 6 + 24];
    size_t n = ssec_tlv_encode(&a, rec);
    ssec_part_t parts[2] = { { 1, 5 << 20 }, { 2, 1234 } };
    n += ssec_parttable_encode(parts, 2, rec + n);
    CHECK(ssec_tlv_find(rec, n, &b) == 1 && !memcmp(&a, &b, sizeof(a)), "SSEC TLV round trip");
    ssec_part_t *pp; size_t pn;
    CHECK(ssec_parttable_find(rec, n, &pp, &pn) == 1 && pn == 2 && pp[1].plain == 1234, "PART_TABLE round trip");
    free(pp);
    CHECK(ssec_tlv_find(rec + 6 + SSEC_TLV_PAYLOAD, n - 6 - SSEC_TLV_PAYLOAD, &b) == 0, "absent");
}

static uint64_t rng = 0xdeadbeefcafef00dull;
static uint32_t rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (uint32_t)rng; }

static void fuzz(long iters) {
    uint8_t key[32] = { 9 };
    ssec_info_t a;
    ssec_info_new(key, &a);
    uint8_t seed[6 + SSEC_TLV_PAYLOAD + 6 + 36];
    size_t sn = ssec_tlv_encode(&a, seed);
    ssec_part_t parts[3] = { { 1, 10 }, { 2, 20 }, { 7, 0 } };
    sn += ssec_parttable_encode(parts, 3, seed + sn);
    uint8_t buf[256];
    for (long i = 0; i < iters; i++) {
        size_t n;
        if (rnd() & 1) {
            memcpy(buf, seed, sn); n = sn;
            for (int m = 0, k = 1 + (int)(rnd() % 4); m < k; m++) buf[rnd() % n] = (uint8_t)rnd();
            if (rnd() % 4 == 0) n = rnd() % (n + 1);
        } else {
            n = rnd() % sizeof(buf);
            for (size_t k = 0; k < n; k++) buf[k] = (uint8_t)rnd();
            if (n > 1) { buf[0] = (uint8_t)(5 + rnd() % 2); buf[1] = 0; }
        }
        uint8_t *h = malloc(n ? n : 1);
        memcpy(h, buf, n);
        ssec_info_t o;
        (void)ssec_tlv_find(h, n, &o);
        ssec_part_t *pp; size_t pn;
        if (ssec_parttable_find(h, n, &pp, &pn) == 1) free(pp);
        free(h);
    }
    pass++;
}

int main(int argc, char **argv) {
    t_derive_vector();
    t_roundtrip_and_tamper();
    t_sizes();
    t_tlv();
    fuzz(argc > 1 ? atol(argv[1]) : 2000);
    printf("%d passed, %d failed\n", pass, fail);
    if (fail) return 1;
    printf("ALL TESTS PASSED\n");
    return 0;
}
