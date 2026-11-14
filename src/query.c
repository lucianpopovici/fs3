/* src/query.c — query-string parsing for conn_t (split out of conn.c so
 * the SigV4 unit tests can link it without the whole connection layer). */

#include "conn.h"

#include <string.h>

/* ------------------------------------------------------------------------- */
/* Query parsing                                                             */
/* ------------------------------------------------------------------------- */

static int hexval(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* Percent-decode src[0..n) into dst; returns bytes written. */
static size_t qdecode(const char *src, size_t n, char *dst) {
    size_t w = 0;
    for (size_t r = 0; r < n; r++) {
        int hi, lo;
        if (src[r] == '%' && r + 2 < n
            && (hi = hexval(src[r+1])) >= 0 && (lo = hexval(src[r+2])) >= 0) {
            dst[w++] = (char)((hi << 4) | lo);
            r += 2;
        } else {
            dst[w++] = src[r];
        }
    }
    return w;
}

int conn_parse_query(conn_t *c) {
    c->req.n_qp = 0;
    s3_str_t q = c->req.query;
    if (q.n == 0) return 0;
    if (q.n > sizeof(c->qbuf)) return -1;
    size_t used = 0, i = 0;
    while (i < q.n) {
        size_t s = i;
        while (i < q.n && q.p[i] != '&') i++;
        size_t e = i;
        if (i < q.n) i++;
        if (e == s) continue;
        if (c->req.n_qp >= CONN_MAX_QPARAMS) return -1;
        size_t eq = s;
        while (eq < e && q.p[eq] != '=') eq++;
        conn_qparam_t *p = &c->req.qp[c->req.n_qp++];
        size_t kn = qdecode(q.p + s, eq - s, c->qbuf + used);
        p->k = (s3_str_t){ c->qbuf + used, kn };
        used += kn;
        p->has_eq = eq < e;
        size_t vn = p->has_eq ? qdecode(q.p + eq + 1, e - eq - 1,
                                         c->qbuf + used) : 0;
        p->v = (s3_str_t){ c->qbuf + used, vn };
        used += vn;
    }
    return 0;
}

const conn_qparam_t *conn_query_get(const conn_t *c, const char *name) {
    for (size_t i = 0; i < c->req.n_qp; i++)
        if (s3_str_eq_lit(c->req.qp[i].k, name)) return &c->req.qp[i];
    return NULL;
}

int conn_query_count(const conn_t *c, const char *name) {
    int n = 0;
    for (size_t i = 0; i < c->req.n_qp; i++)
        if (s3_str_eq_lit(c->req.qp[i].k, name)) n++;
    return n;
}

