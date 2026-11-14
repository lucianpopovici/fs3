/* tests/test_config_fuzz.c — fuzz the bucket-config parsers (CORS,
 * lifecycle, website, bucket policy) with mutated valid documents and
 * random bytes. Must never crash; run under ASan/UBSan for memory
 * errors. Usage: test_config_fuzz [iterations]. */
#include "cors.h"
#include "fuzz_targets.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long long rng = 0x9E3779B97F4A7C15ull;
static unsigned rnd(void) {
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return (unsigned)rng;
}

static const char *SEEDS[] = {
    "<CORSConfiguration><CORSRule><AllowedOrigin>https://*.x.com</AllowedOrigin>"
    "<AllowedMethod>GET</AllowedMethod><AllowedHeader>*</AllowedHeader>"
    "<ExposeHeader>ETag</ExposeHeader><MaxAgeSeconds>60</MaxAgeSeconds>"
    "</CORSRule></CORSConfiguration>",
    FUZZ_EXTRA_SEEDS
};

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 50000;
    size_t n_seeds = sizeof(SEEDS) / sizeof(*SEEDS);
    static char buf[8192];
    long parsed = 0;
    for (long it = 0; it < iters; it++) {
        const char *seed = SEEDS[rnd() % n_seeds];
        size_t n = strlen(seed);
        if (n > sizeof(buf)) n = sizeof(buf);
        memcpy(buf, seed, n);
        if (it % 10 == 9) {                    /* pure noise */
            n = rnd() % 512;
            for (size_t i = 0; i < n; i++) buf[i] = (char)rnd();
        } else if (it % 10) {                  /* mutations */
            int m = 1 + (int)(rnd() % 6);
            for (int k = 0; k < m && n; k++) {
                size_t at = rnd() % n;
                switch (rnd() % 4) {
                case 0: buf[at] = (char)rnd(); break;
                case 1: buf[at] = "<>/*\":{}[],0"[rnd() % 12]; break;
                case 2: n = at; break;
                case 3:                         /* duplicate a span */
                    if (n * 2 < sizeof(buf)) {
                        size_t k2 = n - at;
                        memcpy(buf + n, buf + at, k2);
                        n += k2;
                    }
                    break;
                }
            }
        }
        s3_err_t e;
        cors_config_t *c = cors_parse(buf, n, &e);
        if (c) { parsed++; cors_free(c); }
        parsed += fuzz_extra(buf, n);
    }
    printf("===== config fuzz: %ld iterations, %ld accepted =====\n", iters, parsed);
    return 0;
}
