/* include/ssekeys.h — SSE-S3: server-managed encryption keys.
 *
 * SSE-S3 objects are sealed exactly like SSE-C objects (src/ssec.c:
 * per-object key = HKDF(key, random salt), AES-256-GCM segments), but
 * the 32-byte key comes from fs3's key ring instead of the client. The
 * object additionally carries a TLV (S3_TLV_SSE_S3) naming the key id,
 * so keys can be rotated: new objects use the first key in the file,
 * older objects keep using the key they were sealed with.
 *
 * Key file (--sse-key-file): one key per line, "<id> <64 hex digits>"
 * ('#' comments and blank lines ignored; id = [A-Za-z0-9._-]{1,32}).
 * The file must be a regular file owned by root or by fs3's user, with
 * no group/other permissions. Losing it makes every SSE-S3 object
 * unreadable: back it up apart from the data.
 */
#ifndef FS3_SSEKEYS_H
#define FS3_SSEKEYS_H

#include <stddef.h>
#include <stdint.h>

#define SSEKEYS_ID_MAX 32
#define SSEKEYS_TLV_MAX (6 + 2 + SSEKEYS_ID_MAX)

/* Load (or reload) the key ring. 0 ok; -1 with a message in err, in
 * which case the previous ring (if any) stays in force. */
int  ssekeys_load(const char *path, char *err, size_t errcap);
/* 1 when a key ring is loaded. */
int  ssekeys_enabled(void);
/* Current key for new objects; id copied to id_out. 0 ok, -1 none. */
int  ssekeys_current(uint8_t key[32], char id_out[SSEKEYS_ID_MAX + 1]);
/* Key by id. 0 ok, -1 unknown. */
int  ssekeys_find(const char *id, uint8_t key[32]);
/* Number of keys loaded (for logs and metrics). */
int  ssekeys_count(void);

/* The object marker: TLV [u16 type][u32 len][u8 version=1][u8 idlen][id].
 * Encode returns the record length. Find returns 1 found (id filled),
 * 0 absent, -1 malformed. */
size_t ssekeys_tlv_encode(const char *id, uint8_t out[SSEKEYS_TLV_MAX]);
int    ssekeys_tlv_find(const uint8_t *tlv, size_t n, char id_out[SSEKEYS_ID_MAX + 1]);

/* Parse one key file's text (exposed for tests). Returns the number of
 * keys (>= 1) or -1 with a message. ids/keys arrays hold up to max. */
int  ssekeys_parse(const char *text, size_t n, char ids[][SSEKEYS_ID_MAX + 1],
                   uint8_t keys[][32], int max, char *err, size_t errcap);

#endif
