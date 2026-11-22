/* src/objmeta.c — user metadata / standard header TLVs (see objmeta.h). */
#include "objmeta.h"
#include "store.h"    /* S3_TLV_* */

#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const struct { const char *hdr; const char *name; } STD[OBJMETA_STD_MAX] = {
    [OBJMETA_CACHE_CONTROL]       = { "cache-control",       "Cache-Control" },
    [OBJMETA_CONTENT_DISPOSITION] = { "content-disposition", "Content-Disposition" },
    [OBJMETA_CONTENT_ENCODING]    = { "content-encoding",    "Content-Encoding" },
    [OBJMETA_CONTENT_LANGUAGE]    = { "content-language",    "Content-Language" },
    [OBJMETA_EXPIRES]             = { "expires",             "Expires" },
};

const char *objmeta_std_name(int id) {
    return id > 0 && id < OBJMETA_STD_MAX ? STD[id].name : NULL;
}

int objmeta_valid_token(const char *p, size_t n) {
    if (n == 0) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char ch = (unsigned char)p[i];
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'))
            continue;
        if (!strchr("!#$%&'*+-.^_`|~", ch) || ch == 0) return 0;
    }
    return 1;
}

int objmeta_valid_value(const char *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        unsigned char ch = (unsigned char)p[i];
        if (ch < 0x80) {
            if ((ch < 0x20 && ch != '\t') || ch == 0x7f) return 0;
            i++;
            continue;
        }
        size_t len; uint32_t cp, min;
        if      ((ch & 0xE0) == 0xC0) { len = 2; cp = ch & 0x1F; min = 0x80; }
        else if ((ch & 0xF0) == 0xE0) { len = 3; cp = ch & 0x0F; min = 0x800; }
        else if ((ch & 0xF8) == 0xF0) { len = 4; cp = ch & 0x07; min = 0x10000; }
        else return 0;
        if (n - i < len) return 0;
        for (size_t k = 1; k < len; k++) {
            unsigned char cc = (unsigned char)p[i + k];
            if ((cc & 0xC0) != 0x80) return 0;
            cp = cp << 6 | (cc & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
        i += len;
    }
    return 1;
}

/* ---- growable buffer ---- */
typedef struct { uint8_t *p; size_t n, cap; int oom; } buf_t;

static void put(buf_t *b, const void *d, size_t n) {
    if (b->oom) return;
    if (b->n + n > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 256;
        while (nc < b->n + n) nc *= 2;
        uint8_t *np = realloc(b->p, nc);
        if (!np) { b->oom = 1; return; }
        b->p = np; b->cap = nc;
    }
    memcpy(b->p + b->n, d, n);
    b->n += n;
}
static void put16(buf_t *b, unsigned v) { uint8_t x[2] = { (uint8_t)v, (uint8_t)(v >> 8) }; put(b, x, 2); }
static void put_tlv_head(buf_t *b, unsigned type, uint32_t len) {
    uint8_t x[6] = { (uint8_t)type, (uint8_t)(type >> 8), (uint8_t)len, (uint8_t)(len >> 8),
                     (uint8_t)(len >> 16), (uint8_t)(len >> 24) };
    put(b, x, 6);
}
static unsigned get16(const uint8_t *p) { return (unsigned)p[0] | (unsigned)p[1] << 8; }
static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

#define META_PREFIX "x-amz-meta-"
#define META_PREFIX_N (sizeof(META_PREFIX) - 1)

typedef struct { const char *name; size_t nn; char *val; size_t vn; int set; } um_t;

s3_err_t objmeta_from_headers(const objmeta_hdr_t *h, size_t n,
                              uint8_t **out, size_t *out_n) {
    *out = NULL; *out_n = 0;
    um_t *um = calloc(n ? n : 1, sizeof(*um));
    char *stdv[OBJMETA_STD_MAX] = { 0 };
    size_t stdn[OBJMETA_STD_MAX] = { 0 };
    size_t n_um = 0, total = 0;
    s3_err_t err = S3_OK;
    buf_t b = { 0 };
    if (!um) return S3_ERR_INTERNAL;

    for (size_t i = 0; i < n && err == S3_OK; i++) {
        s3_str_t k = h[i].k, v = h[i].v;
        if (k.n > META_PREFIX_N && strncasecmp(k.p, META_PREFIX, META_PREFIX_N) == 0) {
            const char *nm = k.p + META_PREFIX_N;
            size_t nn = k.n - META_PREFIX_N;
            if (!objmeta_valid_token(nm, nn) || !objmeta_valid_value(v.p, v.n)) {
                err = S3_ERR_INVALID_ARGUMENT; break;
            }
            size_t j;
            for (j = 0; j < n_um; j++)
                if (um[j].nn == nn && strncasecmp(um[j].name, nm, nn) == 0) break;
            if (j == n_um) {
                um[j].name = nm; um[j].nn = nn;
                total += nn;
                n_um++;
            } else {
                total += 1;                       /* the joining "," */
            }
            if (total + v.n > OBJMETA_MAX_USER) { err = S3_ERR_METADATA_TOO_LARGE; break; }
            char *nv = realloc(um[j].val, um[j].vn + v.n + 2);
            if (!nv) { err = S3_ERR_INTERNAL; break; }
            um[j].val = nv;
            if (um[j].set) nv[um[j].vn++] = ',';
            um[j].set = 1;
            memcpy(nv + um[j].vn, v.p, v.n);
            um[j].vn += v.n;
            total += v.n;
            continue;
        }
        for (int id = 1; id < OBJMETA_STD_MAX; id++) {
            if (k.n != strlen(STD[id].hdr) || strncasecmp(k.p, STD[id].hdr, k.n) != 0) continue;
            if (!objmeta_valid_value(v.p, v.n)) { err = S3_ERR_INVALID_ARGUMENT; break; }
            /* Content-Encoding: aws-chunked is transport framing. */
            char tmp[OBJMETA_MAX_STD + 1];
            size_t tn = 0;
            if (id == OBJMETA_CONTENT_ENCODING) {
                size_t s = 0;
                while (s < v.n) {
                    size_t e = s;
                    while (e < v.n && v.p[e] != ',') e++;
                    size_t a = s, z = e;
                    while (a < z && (v.p[a] == ' ' || v.p[a] == '\t')) a++;
                    while (z > a && (v.p[z-1] == ' ' || v.p[z-1] == '\t')) z--;
                    if (z > a && !(z - a == 11 && strncasecmp(v.p + a, "aws-chunked", 11) == 0)) {
                        if (tn + (tn ? 1 : 0) + (z - a) > OBJMETA_MAX_STD) { err = S3_ERR_INVALID_ARGUMENT; break; }
                        if (tn) tmp[tn++] = ',';
                        memcpy(tmp + tn, v.p + a, z - a);
                        tn += z - a;
                    }
                    s = e + 1;
                }
                if (err != S3_OK) break;
            } else {
                if (v.n > OBJMETA_MAX_STD) { err = S3_ERR_INVALID_ARGUMENT; break; }
                memcpy(tmp, v.p, v.n);
                tn = v.n;
            }
            if (tn == 0) break;
            /* A repeated standard header: join, as HTTP list semantics do. */
            size_t old = stdn[id];
            if (old + (old ? 1 : 0) + tn > OBJMETA_MAX_STD) { err = S3_ERR_INVALID_ARGUMENT; break; }
            char *nv = realloc(stdv[id], old + tn + 2);
            if (!nv) { err = S3_ERR_INTERNAL; break; }
            stdv[id] = nv;
            if (old) nv[stdn[id]++] = ',';
            memcpy(nv + stdn[id], tmp, tn);
            stdn[id] += tn;
            break;
        }
    }
    if (err != S3_OK) goto out;

    if (n_um) {
        size_t len = 0;
        for (size_t j = 0; j < n_um; j++) len += 4 + um[j].nn + um[j].vn;
        put_tlv_head(&b, S3_TLV_USER_META, (uint32_t)len);
        for (size_t j = 0; j < n_um; j++) {
            put16(&b, (unsigned)um[j].nn);
            put16(&b, (unsigned)um[j].vn);
            char lc[OBJMETA_MAX_USER];
            for (size_t q = 0; q < um[j].nn; q++) {
                char ch = um[j].name[q];
                lc[q] = (ch >= 'A' && ch <= 'Z') ? (char)(ch + 32) : ch;
            }
            put(&b, lc, um[j].nn);
            put(&b, um[j].val, um[j].vn);
        }
    }
    size_t slen = 0;
    for (int id = 1; id < OBJMETA_STD_MAX; id++) if (stdn[id]) slen += 3 + stdn[id];
    if (slen) {
        put_tlv_head(&b, S3_TLV_STD_HEADERS, (uint32_t)slen);
        for (int id = 1; id < OBJMETA_STD_MAX; id++) {
            if (!stdn[id]) continue;
            uint8_t x = (uint8_t)id;
            put(&b, &x, 1);
            put16(&b, (unsigned)stdn[id]);
            put(&b, stdv[id], stdn[id]);
        }
    }
    if (b.oom) { err = S3_ERR_INTERNAL; goto out; }
    *out = b.p; *out_n = b.n;
    b.p = NULL;
out:
    for (size_t j = 0; j < n_um; j++) free(um[j].val);
    free(um);
    for (int id = 0; id < OBJMETA_STD_MAX; id++) free(stdv[id]);
    free(b.p);
    return err;
}

/* Validate (emit == 0) or emit (emit == 1) one record's contents. */
static int walk_rec(unsigned type, const uint8_t *p, uint32_t len, int emit,
                    int user_meta, unsigned std_mask, objmeta_cb cb, void *ctx) {
    uint32_t o = 0;
    if (type == S3_TLV_USER_META) {
        size_t total = 0;
        while (o < len) {
            if (len - o < 4) return -1;
            unsigned nn = get16(p + o), vn = get16(p + o + 2);
            o += 4;
            if (nn > len - o || vn > len - o - nn) return -1;
            const char *nm = (const char *)p + o, *vv = nm + nn;
            total += nn + vn;
            if (total > OBJMETA_MAX_USER || !objmeta_valid_token(nm, nn)
                || !objmeta_valid_value(vv, vn) || memchr(vv, 0, vn))
                return -1;
            for (unsigned q = 0; q < nn; q++) if (nm[q] >= 'A' && nm[q] <= 'Z') return -1;
            if (emit && user_meta) {
                char name[META_PREFIX_N + OBJMETA_MAX_USER + 1], val[OBJMETA_MAX_USER + 1];
                memcpy(name, META_PREFIX, META_PREFIX_N);
                memcpy(name + META_PREFIX_N, nm, nn);
                name[META_PREFIX_N + nn] = '\0';
                memcpy(val, vv, vn);
                val[vn] = '\0';
                int r = cb(ctx, 0, name, val);
                if (r) return r;
            }
            o += nn + vn;
        }
    } else if (type == S3_TLV_STD_HEADERS) {
        while (o < len) {
            if (len - o < 3) return -1;
            unsigned id = p[o], vn = get16(p + o + 1);
            o += 3;
            if (vn > len - o || vn > OBJMETA_MAX_STD || id == 0 || id >= OBJMETA_STD_MAX)
                return -1;
            const char *vv = (const char *)p + o;
            if (!objmeta_valid_value(vv, vn)) return -1;
            if (emit && (std_mask & (1u << id))) {
                char val[OBJMETA_MAX_STD + 1];
                memcpy(val, vv, vn);
                val[vn] = '\0';
                int r = cb(ctx, (int)id, STD[id].name, val);
                if (r) return r;
            }
            o += vn;
        }
    }
    return 0;
}

static int walk(const uint8_t *t, size_t n, int emit, int user_meta, unsigned std_mask,
                objmeta_cb cb, void *ctx) {
    size_t o = 0;
    while (o < n) {
        if (n - o < 6) return -1;
        unsigned type = get16(t + o);
        uint32_t len = get32(t + o + 2);
        if (len > n - o - 6) return -1;
        int r = walk_rec(type, t + o + 6, len, emit, user_meta, std_mask, cb, ctx);
        if (r) return r;
        o += 6 + len;
    }
    return 0;
}

int objmeta_walk(const uint8_t *tlv, size_t n, int user_meta, unsigned std_mask,
                 objmeta_cb cb, void *ctx) {
    if (!tlv || n == 0) return 0;
    if (walk(tlv, n, 0, 0, 0, NULL, NULL) != 0) return -1;
    return walk(tlv, n, 1, user_meta, std_mask, cb, ctx);
}

int objmeta_copy_filter(const uint8_t *t, size_t n, uint8_t **out, size_t *out_n) {
    *out = NULL; *out_n = 0;
    if (!t || n == 0) return 0;
    if (walk(t, n, 0, 0, 0, NULL, NULL) != 0) return -1;
    buf_t b = { 0 };
    size_t o = 0;
    while (o < n) {
        unsigned type = get16(t + o);
        uint32_t len = get32(t + o + 2);
        int drop = type == S3_TLV_CONTENT_SHA256 || type == S3_TLV_PART_TABLE
                || type == S3_TLV_SSEC || type == S3_TLV_ZSTD_SEEK
                || type == S3_TLV_SSE_S3;
        if (!drop) put(&b, t + o, 6 + len);
        o += 6 + len;
    }
    if (b.oom) { free(b.p); return -1; }
    *out = b.p; *out_n = b.n;
    return 0;
}
