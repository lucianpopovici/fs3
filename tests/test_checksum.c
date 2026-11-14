/* tests/test_checksum.c — checksum algorithms against published check
 * values, streaming == one-shot across split points, CRC32C hardware vs
 * portable path, and base64 strictness. */
#include "checksum.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int cksum_disable_hw;

static int pass, fail;
#define CHECK(c, m) do { if (c) pass++; else { fail++; \
    fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, m); } } while (0)

static void hex(const uint8_t *p, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) sprintf(out + 2 * i, "%02x", p[i]);
}

static void check_vec(int algo, const char *in, const char *want_hex) {
    uint8_t d[32]; size_t n; char h[65];
    CHECK(cksum_oneshot(algo, in, strlen(in), d, &n) == 0, "oneshot");
    hex(d, n, h);
    if (strcmp(h, want_hex) != 0)
        fprintf(stderr, "  algo %d: got %s want %s\n", algo, h, want_hex);
    CHECK(strcmp(h, want_hex) == 0, cksum_upper_name(algo));
}

int main(void) {
    const char *nine = "123456789";
    check_vec(S3_CKSUM_CRC32,     nine, "cbf43926");
    check_vec(S3_CKSUM_CRC32C,    nine, "e3069283");
    check_vec(S3_CKSUM_CRC64NVME, nine, "ae8b14860a799888");
    check_vec(S3_CKSUM_SHA1,      "abc", "a9993e364706816aba3e25717850c26c9cd0d89d");
    check_vec(S3_CKSUM_SHA256,    "abc",
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    check_vec(S3_CKSUM_CRC32, "", "00000000");
    cksum_disable_hw = 1;
    check_vec(S3_CKSUM_CRC32C, nine, "e3069283");
    cksum_disable_hw = 0;

    /* Streaming over every split point and misalignment equals one-shot;
     * hardware CRC32C equals portable. */
    uint8_t buf[1031];
    srand(7);
    for (size_t i = 0; i < sizeof(buf); i++) buf[i] = (uint8_t)rand();
    for (int algo = 1; algo < S3_CKSUM_MAX; algo++) {
        uint8_t want[32], got[32]; size_t wn, gn;
        cksum_oneshot(algo, buf + 3, 1000, want, &wn);
        int ok = 1;
        for (size_t split = 0; split <= 1000; split += 37) {
            cksum_ctx_t k;
            cksum_begin(&k, algo);
            cksum_update(&k, buf + 3, split);
            cksum_update(&k, buf + 3 + split, 1000 - split);
            cksum_final(&k, got, &gn);
            cksum_free(&k);
            if (gn != wn || memcmp(got, want, wn)) ok = 0;
        }
        CHECK(ok, "streaming == oneshot");
    }
    {
        uint8_t a[32], b[32]; size_t an, bn;
        int ok = 1;
        for (size_t off = 0; off < 9; off++) {
            for (size_t len = 0; len < 300; len += 7) {
                cksum_oneshot(S3_CKSUM_CRC32C, buf + off, len, a, &an);
                cksum_disable_hw = 1;
                cksum_oneshot(S3_CKSUM_CRC32C, buf + off, len, b, &bn);
                cksum_disable_hw = 0;
                if (memcmp(a, b, 4)) ok = 0;
            }
        }
        CHECK(ok, "crc32c hw == sw");
    }

    /* crc64nvme_combine(crc(A), crc(B), |B|) == crc(A‖B) for many splits. */
    {
        int ok = 1;
        for (size_t split = 0; split <= 1000 && ok; split += 13) {
            uint8_t a[32], b[32], w[32]; size_t n;
            cksum_oneshot(S3_CKSUM_CRC64NVME, buf, split, a, &n);
            cksum_oneshot(S3_CKSUM_CRC64NVME, buf + split, 1000 - split, b, &n);
            cksum_oneshot(S3_CKSUM_CRC64NVME, buf, 1000, w, &n);
            uint64_t c = crc64nvme_combine(crc64nvme_from_be(a), crc64nvme_from_be(b),
                                           1000 - split);
            if (c != crc64nvme_from_be(w)) ok = 0;
        }
        CHECK(ok, "crc64nvme_combine == one-shot");
        /* Check value: "12345" + "6789" → crc("123456789"). */
        uint8_t a[32], b[32]; size_t n;
        cksum_oneshot(S3_CKSUM_CRC64NVME, "12345", 5, a, &n);
        cksum_oneshot(S3_CKSUM_CRC64NVME, "6789", 4, b, &n);
        CHECK(crc64nvme_combine(crc64nvme_from_be(a), crc64nvme_from_be(b), 4)
              == 0xae8b14860a799888ull, "combine check value");
    }

    /* base64 */
    char e[64]; uint8_t d[64];
    base64_encode((const uint8_t *)"\xcb\xf4\x39\x26", 4, e);
    CHECK(strcmp(e, "y/Q5Jg==") == 0, "b64 encode");
    CHECK(base64_decode("y/Q5Jg==", 8, d, sizeof d) == 4
          && memcmp(d, "\xcb\xf4\x39\x26", 4) == 0, "b64 decode");
    CHECK(base64_decode("y/Q5Jg=", 7, d, sizeof d) < 0, "b64 bad length");
    CHECK(base64_decode("y/Q=Jg==", 8, d, sizeof d) < 0, "b64 mid padding");
    CHECK(base64_decode("y/Q5J!==", 8, d, sizeof d) < 0, "b64 bad char");
    CHECK(base64_decode("AAAAAAAA", 8, d, 3) < 0, "b64 overflow");

    /* names */
    CHECK(cksum_algo_from_name((s3_str_t){ "CRC32C", 6 }) == S3_CKSUM_CRC32C, "name");
    CHECK(cksum_algo_from_header((s3_str_t){ "x-amz-checksum-sha256", 21 })
          == S3_CKSUM_SHA256, "header name");
    CHECK(cksum_algo_from_header((s3_str_t){ "x-amz-checksum-mode", 19 }) == 0,
          "mode is not an algo");

    printf("===== checksum: %d passed, %d failed =====\n", pass, fail);
    return fail != 0;
}
