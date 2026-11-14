/* tests/test_chunk_fuzz.c — fuzz the aws-chunked decoder in all three
 * framing modes (signatures not verified, so mutations reach the deep
 * states: data, CRLFs, trailer lines). Each iteration builds a valid
 * stream, checks it decodes to the original body when unmutated, then
 * mutates bytes and feeds it at random split points. Must never crash;
 * run under ASan/UBSan for memory errors. Usage: test_chunk_fuzz [N]. */
#include "conn.h"
#include "sigv4.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long long rng = 88172645463325252ull;
static unsigned rnd(void) {
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return (unsigned)rng;
}

static char outbuf[1 << 16];
static size_t outlen;
static int sink(void *u, const char *d, size_t n) {
    (void)u;
    if (outlen + n > sizeof(outbuf)) return -1;
    memcpy(outbuf + outlen, d, n);
    outlen += n;
    return 0;
}

static size_t build(char *w, size_t cap, sigv4_stream_mode_t mode,
                    const char *body, size_t bn) {
    size_t o = 0;
    size_t pos = 0;
    static const char sig[] = ";chunk-signature="
        "0000000000000000000000000000000000000000000000000000000000000000";
    for (;;) {
        size_t cn = bn - pos, cap_n = 1 + rnd() % 64;
        if (cn > cap_n) cn = cap_n;
        if (pos >= bn) cn = 0;
        o += (size_t)snprintf(w + o, cap - o, "%zx%s\r\n", cn,
                              mode == SIGV4_STREAM_UNSIGNED_TRAILER ? "" : sig);
        if (cn) {
            memcpy(w + o, body + pos, cn); o += cn;
            memcpy(w + o, "\r\n", 2); o += 2;
            pos += cn;
            continue;
        }
        break;
    }
    if (mode == SIGV4_STREAM_SIGNED) {
        memcpy(w + o, "\r\n", 2); o += 2;
    } else {
        o += (size_t)snprintf(w + o, cap - o, "x-amz-checksum-crc32:AAAAAA==\r\n");
        if (mode == SIGV4_STREAM_SIGNED_TRAILER)
            o += (size_t)snprintf(w + o, cap - o, "x-amz-trailer-signature:%064d\r\n", 0);
        memcpy(w + o, "\r\n", 2); o += 2;
    }
    return o;
}

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 50000;
    conn_t *c = calloc(1, sizeof(*c));
    if (!c) return 1;
    c->req.headers[0].k = S3_STR_LIT("x-amz-trailer");
    c->req.headers[0].v = S3_STR_LIT("x-amz-checksum-crc32");
    c->req.n_headers = 1;

    static char body[2048], wire[1 << 18];
    long clean_ok = 0, clean_total = 0;
    for (long it = 0; it < iters; it++) {
        sigv4_stream_mode_t mode = (sigv4_stream_mode_t)(1 + rnd() % 3);
        size_t bn = rnd() % sizeof(body);
        for (size_t i = 0; i < bn; i++) body[i] = (char)rnd();
        size_t wn = build(wire, sizeof(wire), mode, body, bn);
        int mutate = (it % 4) != 0;
        if (mutate) {
            int nm = 1 + (int)(rnd() % 4);
            for (int m = 0; m < nm; m++) {
                size_t at = rnd() % wn;
                switch (rnd() % 3) {
                case 0: wire[at] = (char)rnd(); break;
                case 1: wire[at] = "\r\n;:0f"[rnd() % 6]; break;
                case 2: wn = at; break;                    /* truncate */
                }
                if (wn == 0) break;
            }
        }
        sigv4_chunk_decoder_t *d = sigv4_chunk_begin_mode(
            NULL, c, mode, 0, mutate ? 0 : bn, sink, NULL);
        if (!d) { fprintf(stderr, "begin failed\n"); return 1; }
        outlen = 0;
        size_t off = 0;
        int rc = 0;
        while (off < wn && rc == 0) {
            size_t take = 1 + rnd() % 97;
            if (take > wn - off) take = wn - off;
            rc = sigv4_chunk_feed(d, wire + off, take);
            off += take;
        }
        int fin = rc == 0 ? sigv4_chunk_finish(d) : -1;
        if (!mutate) {
            clean_total++;
            size_t tn = 0;
            const char *tv = sigv4_chunk_trailer(d, "x-amz-checksum-crc32", &tn);
            if (fin == 0 && outlen == bn && memcmp(outbuf, body, bn) == 0
                && (mode == SIGV4_STREAM_SIGNED || (tv && tn == 8)))
                clean_ok++;
            else fprintf(stderr, "clean stream failed: mode=%d bn=%zu fin=%d rc=%d\n",
                         mode, bn, fin, rc);
        }
        sigv4_chunk_free(d);
    }
    free(c);
    printf("===== chunk fuzz: %ld iterations, %ld/%ld clean streams decoded =====\n",
           iters, clean_ok, clean_total);
    return clean_ok == clean_total ? 0 : 1;
}
