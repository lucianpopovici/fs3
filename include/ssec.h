/* include/ssec.h — SSE-C crypto (round 2, item 8): chunked AEAD.
 *
 *   k_obj  = HKDF-SHA256(ikm = customer key, salt, info = "fs3-ssec-v1")
 *   payload: 64 KiB plaintext segments, each AES-256-GCM sealed:
 *            nonce = part_number (4 B BE, 0 for a single PUT) ‖ segment index (8 B BE)
 *            AAD   = bucket id (32 hex chars) ‖ final-flag (1 B)
 *            on disk: ciphertext ‖ 16-byte tag
 *   check  = HMAC-SHA256(customer key, salt ‖ "check")  (wrong key → refused
 *            before any data is read; the bare key MD5 is never stored)
 *
 * The salt is random per object (per upload for multipart), so every
 * object has its own key: ciphertext moved between objects fails
 * authentication. The final flag stops truncation within a part.
 */
#ifndef FS3_SSEC_H
#define FS3_SSEC_H

#include <stddef.h>
#include <stdint.h>

#define SSEC_SEG  65536u
#define SSEC_TAG  16u
#define SSEC_TLV_PAYLOAD 53u     /* [u8 ver][u32 seg][16 salt][32 check] */

typedef struct {
    uint8_t  salt[16];
    uint32_t seg;
    uint8_t  check[32];
} ssec_info_t;

/* New per-object parameters for `key` (random salt). 0 ok. */
int  ssec_info_new(const uint8_t key[32], ssec_info_t *out);
/* 1 if `key` is the one the object was sealed with (constant time). */
int  ssec_key_matches(const uint8_t key[32], const ssec_info_t *i);
int  ssec_derive(const uint8_t key[32], const uint8_t salt[16], uint8_t kobj[32]);

/* Seal n plaintext bytes into out (n + 16). Open n ciphertext bytes
 * (including the tag) into pt (n - 16); -1 when authentication fails. */
int  ssec_seal(const uint8_t kobj[32], uint32_t part, uint64_t idx, int final,
               const char bucket_id[32], const uint8_t *pt, size_t n, uint8_t *out);
int  ssec_open(const uint8_t kobj[32], uint32_t part, uint64_t idx, int final,
               const char bucket_id[32], const uint8_t *ct, size_t n, uint8_t *pt);

/* Sizes: every part ends with a final (possibly short or empty) segment. */
uint64_t ssec_cipher_len(uint64_t plain, uint32_t seg);
uint64_t ssec_plain_len(uint64_t cipher, uint32_t seg);

/* TLV records (type S3_TLV_SSEC / S3_TLV_PART_TABLE, little endian).
 * Encode writes the whole record (6-byte head + payload) and returns its
 * length. Find returns 1 found, 0 absent, -1 malformed. */
size_t ssec_tlv_encode(const ssec_info_t *i, uint8_t out[6 + SSEC_TLV_PAYLOAD]);
int    ssec_tlv_find(const uint8_t *tlv, size_t n, ssec_info_t *out);

typedef struct { uint32_t part; uint64_t plain; } ssec_part_t;
/* out must hold 6 + 12 * n bytes. */
size_t ssec_parttable_encode(const ssec_part_t *p, size_t n, uint8_t *out);
/* *out malloc'd; parts strictly increasing, 1..10000. */
int    ssec_parttable_find(const uint8_t *tlv, size_t n, ssec_part_t **out, size_t *n_out);

#endif
