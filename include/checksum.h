/* include/checksum.h — streaming x-amz-checksum-* algorithms
 *
 *   cksum_ctx_t k;
 *   cksum_begin(&k, S3_CKSUM_CRC32C);
 *   cksum_update(&k, buf, n);     ... any number of times
 *   cksum_final(&k, out, &len);   // raw digest, big-endian for CRCs
 *   cksum_free(&k);               // always; safe after final
 *
 * CRC32 / CRC32C / CRC64NVME are table-driven (slice-by-8) so the static
 * Synology build needs no zlib; CRC32C uses the SSE4.2 crc32 instruction
 * when the CPU has it (the DS1515+'s Atom C2538 does). SHA-1/SHA-256 use
 * OpenSSL EVP. The digest byte order matches what AWS base64-encodes in
 * the x-amz-checksum-* headers.
 */
#ifndef FS3_CHECKSUM_H
#define FS3_CHECKSUM_H

#include <stddef.h>
#include <stdint.h>

#include "s3.h"
#include "store.h"   /* s3_cksum_algo_t */

/* Not stored on disk: Content-MD5 verification reuses the same API. */
#define CKSUM_MD5 100

#define CKSUM_MAX_DIGEST 32

typedef struct {
    int       algo;      /* s3_cksum_algo_t or CKSUM_MD5; 0 = inactive */
    uint32_t  crc32;
    uint64_t  crc64;
    void     *md;        /* EVP_MD_CTX* for SHA-1/SHA-256/MD5 */
} cksum_ctx_t;

int  cksum_begin(cksum_ctx_t *k, int algo);         /* 0 ok, -1 bad/OOM */
void cksum_update(cksum_ctx_t *k, const void *p, size_t n);
int  cksum_final(cksum_ctx_t *k, uint8_t out[CKSUM_MAX_DIGEST], size_t *len);
void cksum_free(cksum_ctx_t *k);

/* Raw digest length for an algorithm (0 if unknown). */
size_t cksum_digest_len(int algo);

/* "crc32" / "CRC32" / "crc64nvme" … → algo, 0 if unknown. */
int cksum_algo_from_name(s3_str_t name);
/* "x-amz-checksum-crc32" → algo (case-insensitive), 0 if not a checksum
 * header name. */
int cksum_algo_from_header(s3_str_t hdr_name);
/* Lowercase header name, "x-amz-checksum-crc32". */
const char *cksum_header_name(int algo);
/* "CRC32", as in x-amz-checksum-algorithm and response headers. */
const char *cksum_upper_name(int algo);
/* XML element name, "ChecksumCRC32". */
const char *cksum_xml_name(int algo);

/* One-shot helpers. */
int  cksum_oneshot(int algo, const void *p, size_t n,
                   uint8_t out[CKSUM_MAX_DIGEST], size_t *len);

/* Standard base64 (with padding). base64_encode writes a NUL-terminated
 * string (out needs 4*ceil(n/3)+1 bytes) and returns its length.
 * base64_decode returns decoded length or -1 if invalid / too long. */
size_t base64_encode(const uint8_t *in, size_t n, char *out);
int    base64_decode(const char *in, size_t n, uint8_t *out, size_t cap);

#endif
