/* include/objmeta.h — user metadata and standard object headers (round 2,
 * item 1e), stored as schema-4 TLV records:
 *
 *   S3_TLV_USER_META    repeated [u16 nlen][u16 vlen][name][value]
 *                       names lower-case, without "x-amz-meta-"
 *   S3_TLV_STD_HEADERS  repeated [u8 id][u16 len][value]
 *
 * All integers little-endian. Values become response headers, so this is
 * the response-splitting boundary: everything is validated when built
 * from a request AND again when walked from disk.
 */
#ifndef FS3_OBJMETA_H
#define FS3_OBJMETA_H

#include <stddef.h>
#include <stdint.h>

#include "s3.h"

#define OBJMETA_MAX_USER   2048   /* sum of name + value bytes, as AWS counts */
#define OBJMETA_MAX_STD    1024   /* per standard header value */

enum {
    OBJMETA_CACHE_CONTROL       = 1,
    OBJMETA_CONTENT_DISPOSITION = 2,
    OBJMETA_CONTENT_ENCODING    = 3,
    OBJMETA_CONTENT_LANGUAGE    = 4,
    OBJMETA_EXPIRES             = 5,
    OBJMETA_STD_MAX
};

/* Same layout as conn_header_t: lower-case name, raw value. */
typedef struct { s3_str_t k, v; } objmeta_hdr_t;

/* Build USER_META + STD_HEADERS records from request headers. *out is
 * malloc'd (NULL with *out_n 0 when there is nothing to store).
 * Duplicate x-amz-meta-* names are joined with ","; "aws-chunked" is
 * dropped from Content-Encoding. Errors: S3_ERR_METADATA_TOO_LARGE,
 * S3_ERR_INVALID_ARGUMENT (bad name/value). */
s3_err_t objmeta_from_headers(const objmeta_hdr_t *h, size_t n,
                              uint8_t **out, size_t *out_n);

/* Walk a TLV area and call cb(ctx, header_name, value) for each stored
 * header ("x-amz-meta-color", "Cache-Control", …); both NUL-terminated.
 * The whole area is validated first: a malformed area emits nothing and
 * returns -1. Unknown TLV types are skipped. std_only: only the standard
 * headers whose bit (1 << id) is set in std_mask, no user metadata.
 * A non-zero cb return stops the walk and is returned. */
typedef int (*objmeta_cb)(void *ctx, int std_id, const char *name, const char *value);
int objmeta_walk(const uint8_t *tlv, size_t n, int user_meta, unsigned std_mask,
                 objmeta_cb cb, void *ctx);

/* x-amz-metadata-directive: COPY. Keeps USER_META, STD_HEADERS and
 * unknown types; drops records that describe the source's stored bytes
 * (CONTENT_SHA256, PART_TABLE, SSEC, ZSTD_SEEK). -1 on malformed input. */
int objmeta_copy_filter(const uint8_t *tlv, size_t n, uint8_t **out, size_t *out_n);

/* Header value rule: no CR, LF, NUL, no bytes < 0x20 except HTAB, no
 * DEL, and bytes ≥ 0x80 must be valid UTF-8. */
int objmeta_valid_value(const char *p, size_t n);
/* RFC 9110 token. */
int objmeta_valid_token(const char *p, size_t n);

/* "Cache-Control" etc. for an id, NULL if unknown. */
const char *objmeta_std_name(int id);

#endif
