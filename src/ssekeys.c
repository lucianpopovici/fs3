/* src/ssekeys.c — SSE-S3 key ring. See include/ssekeys.h. */
#include "ssekeys.h"
#include "store.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_KEYS 64

typedef struct {
    int     n;
    char    ids[MAX_KEYS][SSEKEYS_ID_MAX + 1];
    uint8_t keys[MAX_KEYS][32];
} ring_t;

/* Swapped atomically on reload. Old rings are kept (never freed): a
 * reader may still be copying a key out of one, and reloads are rare. */
static ring_t *g_ring;

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int valid_id(const char *s, size_t n) {
    if (n == 0 || n > SSEKEYS_ID_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
              || c == '.' || c == '_' || c == '-'))
            return 0;
    }
    return 1;
}

int ssekeys_parse(const char *text, size_t n, char ids[][SSEKEYS_ID_MAX + 1],
                  uint8_t keys[][32], int max, char *err, size_t errcap) {
    int count = 0, lineno = 0;
    size_t pos = 0;
    while (pos < n) {
        size_t end = pos;
        while (end < n && text[end] != '\n') end++;
        lineno++;
        const char *l = text + pos;
        size_t ln = end - pos;
        pos = end + 1;
        while (ln && (l[ln - 1] == '\r' || l[ln - 1] == ' ' || l[ln - 1] == '\t')) ln--;
        while (ln && (*l == ' ' || *l == '\t')) { l++; ln--; }
        if (!ln || *l == '#') continue;
        const char *sp = memchr(l, ' ', ln);
        if (!sp) sp = memchr(l, '\t', ln);
        if (!sp) { snprintf(err, errcap, "line %d: expected \"<id> <64 hex digits>\"", lineno); return -1; }
        size_t idn = (size_t)(sp - l);
        const char *hx = sp;
        size_t hn = ln - idn;
        while (hn && (*hx == ' ' || *hx == '\t')) { hx++; hn--; }
        if (!valid_id(l, idn)) { snprintf(err, errcap, "line %d: key id must match [A-Za-z0-9._-]{1,32}", lineno); return -1; }
        if (hn != 64) { snprintf(err, errcap, "line %d: key must be 64 hex digits (32 bytes)", lineno); return -1; }
        if (count >= max) { snprintf(err, errcap, "more than %d keys", max); return -1; }
        uint8_t k[32];
        for (int i = 0; i < 32; i++) {
            int a = hexval(hx[2 * i]), b = hexval(hx[2 * i + 1]);
            if (a < 0 || b < 0) {
                OPENSSL_cleanse(k, sizeof(k));
                snprintf(err, errcap, "line %d: key is not hex", lineno);
                return -1;
            }
            k[i] = (uint8_t)(a << 4 | b);
        }
        static const uint8_t zero[32];
        if (!memcmp(k, zero, 32)) { snprintf(err, errcap, "line %d: all-zero key", lineno); return -1; }
        for (int j = 0; j < count; j++)
            if (strlen(ids[j]) == idn && !memcmp(ids[j], l, idn)) {
                OPENSSL_cleanse(k, sizeof(k));
                snprintf(err, errcap, "line %d: duplicate key id", lineno);
                return -1;
            }
        memcpy(ids[count], l, idn);
        ids[count][idn] = '\0';
        memcpy(keys[count], k, 32);
        OPENSSL_cleanse(k, sizeof(k));
        count++;
    }
    if (!count) { snprintf(err, errcap, "no keys in the file"); return -1; }
    return count;
}

int ssekeys_load(const char *path, char *err, size_t errcap) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { snprintf(err, errcap, "cannot open %s: %s", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
        close(fd); snprintf(err, errcap, "%s is not a regular file", path); return -1;
    }
    if (st.st_mode & 077) {
        close(fd); snprintf(err, errcap, "%s must not be readable by group or others (chmod 600)", path); return -1;
    }
    if (st.st_uid != 0 && st.st_uid != geteuid()) {
        close(fd); snprintf(err, errcap, "%s must be owned by root or by fs3's user", path); return -1;
    }
    if (st.st_size > 64 * 1024) { close(fd); snprintf(err, errcap, "%s is too large", path); return -1; }
    char *buf = malloc((size_t)st.st_size + 1);
    if (!buf) { close(fd); snprintf(err, errcap, "out of memory"); return -1; }
    ssize_t got = read(fd, buf, (size_t)st.st_size);
    close(fd);
    if (got != st.st_size) { free(buf); snprintf(err, errcap, "short read on %s", path); return -1; }
    ring_t *r = calloc(1, sizeof(*r));
    if (!r) { OPENSSL_cleanse(buf, (size_t)got); free(buf); snprintf(err, errcap, "out of memory"); return -1; }
    int n = ssekeys_parse(buf, (size_t)got, r->ids, r->keys, MAX_KEYS, err, errcap);
    OPENSSL_cleanse(buf, (size_t)got);
    free(buf);
    if (n < 0) { OPENSSL_cleanse(r, sizeof(*r)); free(r); return -1; }
    r->n = n;
    /* Keys already in use must keep their value: a reload that changed
     * the bytes behind an id would make those objects unreadable. */
    ring_t *old = __atomic_load_n(&g_ring, __ATOMIC_ACQUIRE);
    for (int i = 0; old && i < old->n; i++)
        for (int j = 0; j < r->n; j++)
            if (!strcmp(old->ids[i], r->ids[j]) && CRYPTO_memcmp(old->keys[i], r->keys[j], 32)) {
                snprintf(err, errcap, "key \"%s\" changed value; ids must never be reused", r->ids[j]);
                OPENSSL_cleanse(r, sizeof(*r));
                free(r);
                return -1;
            }
    for (int i = 0; old && i < old->n; i++) {
        int kept = 0;
        for (int j = 0; j < r->n; j++) if (!strcmp(old->ids[i], r->ids[j])) kept = 1;
        if (!kept) {
            snprintf(err, errcap, "key \"%s\" was removed; objects sealed with it would become unreadable",
                     old->ids[i]);
            OPENSSL_cleanse(r, sizeof(*r));
            free(r);
            return -1;
        }
    }
    __atomic_store_n(&g_ring, r, __ATOMIC_RELEASE);
    return 0;
}

int ssekeys_enabled(void) { return __atomic_load_n(&g_ring, __ATOMIC_ACQUIRE) != NULL; }

int ssekeys_count(void) {
    ring_t *r = __atomic_load_n(&g_ring, __ATOMIC_ACQUIRE);
    return r ? r->n : 0;
}

int ssekeys_current(uint8_t key[32], char id_out[SSEKEYS_ID_MAX + 1]) {
    ring_t *r = __atomic_load_n(&g_ring, __ATOMIC_ACQUIRE);
    if (!r || r->n < 1) return -1;
    memcpy(key, r->keys[0], 32);
    memcpy(id_out, r->ids[0], SSEKEYS_ID_MAX + 1);
    return 0;
}

int ssekeys_find(const char *id, uint8_t key[32]) {
    ring_t *r = __atomic_load_n(&g_ring, __ATOMIC_ACQUIRE);
    for (int i = 0; r && i < r->n; i++)
        if (!strcmp(r->ids[i], id)) { memcpy(key, r->keys[i], 32); return 0; }
    return -1;
}

size_t ssekeys_tlv_encode(const char *id, uint8_t out[SSEKEYS_TLV_MAX]) {
    size_t n = strlen(id);
    if (n > SSEKEYS_ID_MAX) n = SSEKEYS_ID_MAX;
    uint32_t len = (uint32_t)(2 + n);
    out[0] = S3_TLV_SSE_S3 & 0xff; out[1] = S3_TLV_SSE_S3 >> 8;
    out[2] = (uint8_t)len; out[3] = (uint8_t)(len >> 8); out[4] = 0; out[5] = 0;
    out[6] = 1;
    out[7] = (uint8_t)n;
    memcpy(out + 8, id, n);
    return 6 + len;
}

int ssekeys_tlv_find(const uint8_t *t, size_t n, char id_out[SSEKEYS_ID_MAX + 1]) {
    size_t o = 0;
    int found = 0;
    while (t && o < n) {
        if (n - o < 6) return -1;
        unsigned type = t[o] | (unsigned)t[o + 1] << 8;
        uint32_t len = t[o + 2] | (uint32_t)t[o + 3] << 8 | (uint32_t)t[o + 4] << 16 | (uint32_t)t[o + 5] << 24;
        if (len > n - o - 6) return -1;
        if (type == S3_TLV_SSE_S3) {
            const uint8_t *p = t + o + 6;
            if (found || len < 3 || p[0] != 1 || p[1] != len - 2 || !valid_id((const char *)p + 2, p[1]))
                return -1;
            memcpy(id_out, p + 2, p[1]);
            id_out[p[1]] = '\0';
            found = 1;
        }
        o += 6 + len;
    }
    return found;
}
