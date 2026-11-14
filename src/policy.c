/* src/policy.c — bucket policy compiler + evaluator (item 9). */

#include "policy.h"
#include "action.h"
#include "json.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_STATEMENTS 64
#define MAX_LIST       64
#define MAX_STARS      4

enum { COND_STR_EQ, COND_STR_NE, COND_STR_LIKE, COND_IP, COND_NOT_IP, COND_BOOL };
enum { KEY_SOURCE_IP, KEY_SECURE, KEY_PREFIX, KEY_USERNAME };

typedef struct { int op, key; char **vals; size_t n; } cond_t;
typedef struct { char *bucket; char *key_pat; } res_t;   /* key_pat NULL = bucket ARN */

typedef struct {
    int     deny;
    int     any_principal;
    char  **users;   size_t n_users;
    char  **actions; size_t n_actions;
    int     not_action;
    res_t  *res;     size_t n_res;
    cond_t *conds;   size_t n_conds;
} stmt_t;

struct policy {
    stmt_t *st;
    size_t  n;
};

static void free_strs(char **v, size_t n) {
    for (size_t i = 0; i < n; i++) free(v[i]);
    free(v);
}

void policy_free(policy_t *p) {
    if (!p) return;
    for (size_t i = 0; i < p->n; i++) {
        stmt_t *s = &p->st[i];
        free_strs(s->users, s->n_users);
        free_strs(s->actions, s->n_actions);
        for (size_t j = 0; j < s->n_res; j++) { free(s->res[j].bucket); free(s->res[j].key_pat); }
        free(s->res);
        for (size_t j = 0; j < s->n_conds; j++) free_strs(s->conds[j].vals, s->conds[j].n);
        free(s->conds);
    }
    free(p->st);
    free(p);
}
void policy_free_cb(void *p) { policy_free(p); }

/* ---- Matching -------------------------------------------------------- */

int policy_glob(const char *pat, s3_str_t s) {
    /* Two-pointer wildcard match with single backtrack point: O(n*m)
     * worst case but patterns are short and stars are capped. */
    size_t pn = strlen(pat), pi = 0, si = 0, star = (size_t)-1, mark = 0;
    while (si < s.n) {
        if (pi < pn && (pat[pi] == '?' || pat[pi] == s.p[si])) { pi++; si++; }
        else if (pi < pn && pat[pi] == '*') { star = pi++; mark = si; }
        else if (star != (size_t)-1) { pi = star + 1; si = ++mark; }
        else return 0;
    }
    while (pi < pn && pat[pi] == '*') pi++;
    return pi == pn;
}

static int parse_ip(const char *s, uint8_t out[16], int *is4) {
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, s, &a4) == 1) {
        memset(out, 0, 16);
        memcpy(out + 12, &a4, 4);
        *is4 = 1;
        return 0;
    }
    if (inet_pton(AF_INET6, s, &a6) == 1) {
        memcpy(out, &a6, 16);
        static const uint8_t mapped[12] = { 0,0,0,0,0,0,0,0,0,0,0xff,0xff };
        *is4 = memcmp(out, mapped, 12) == 0;     /* ::ffff:a.b.c.d → IPv4 */
        return 0;
    }
    return -1;
}

int policy_ip_in(const char *ip, const char *cidr) {
    if (!ip || !cidr) return 0;
    char net[64];
    const char *sl = strchr(cidr, '/');
    size_t nn = sl ? (size_t)(sl - cidr) : strlen(cidr);
    if (nn >= sizeof(net)) return 0;
    memcpy(net, cidr, nn);
    net[nn] = '\0';
    uint8_t a[16], b[16];
    int a4, b4;
    if (parse_ip(ip, a, &a4) < 0 || parse_ip(net, b, &b4) < 0 || a4 != b4) return 0;
    int maxbits = b4 ? 32 : 128;
    int bits = maxbits;
    if (sl) {
        char *end;
        long v = strtol(sl + 1, &end, 10);
        if (*end || v < 0 || v > maxbits) return 0;
        bits = (int)v;
    }
    int off = b4 ? 12 : 0;
    for (int i = 0; i < bits; i++) {
        int byte = off + i / 8, bit = 7 - i % 8;
        if (((a[byte] >> bit) & 1) != ((b[byte] >> bit) & 1)) return 0;
    }
    return 1;
}

static int valid_cidr(const char *s) {
    char net[64];
    const char *sl = strchr(s, '/');
    size_t nn = sl ? (size_t)(sl - s) : strlen(s);
    if (nn >= sizeof(net)) return 0;
    memcpy(net, s, nn);
    net[nn] = '\0';
    uint8_t a[16];
    int is4;
    if (parse_ip(net, a, &is4) < 0) return 0;
    if (sl) {
        char *end;
        long v = strtol(sl + 1, &end, 10);
        if (*end || sl[1] == '\0' || v < 0 || v > (is4 ? 32 : 128)) return 0;
    }
    return 1;
}

/* ---- Compiler -------------------------------------------------------- */

static int count_stars(const char *s) {
    int n = 0;
    for (; *s; s++) if (*s == '*') n++;
    return n;
}

/* String or array of strings → owned list. */
static int str_list(const json_t *j, char ***out, size_t *n) {
    *out = NULL; *n = 0;
    if (!j) return -1;
    if (j->type == JSON_STR) {
        *out = malloc(sizeof(char *));
        if (!*out || !((*out)[0] = strdup(j->str))) { free(*out); *out = NULL; return -1; }
        *n = 1;
        return 0;
    }
    if (j->type != JSON_ARR || j->n_children == 0 || j->n_children > MAX_LIST) return -1;
    *out = calloc(j->n_children, sizeof(char *));
    if (!*out) return -1;
    for (const json_t *c = j->child; c; c = c->next) {
        if (c->type != JSON_STR || !((*out)[*n] = strdup(c->str))) {
            free_strs(*out, *n); *out = NULL; *n = 0; return -1;
        }
        (*n)++;
    }
    return 0;
}

static int action_writes(const char *pat) {
    for (int a = ACT_NONE + 1; a < ACT_MAX; a++) {
        const s3_action_info_t *ai = action_info((s3_action_t)a);
        if (ai && ai->perm != PERM_R
            && policy_glob(pat, (s3_str_t){ ai->iam_name, strlen(ai->iam_name) }))
            return 1;
    }
    return 0;
}

#define BAD(m) do { if (chk) chk->msg = (m); goto bad; } while (0)

static int compile_stmt(const json_t *j, stmt_t *s, s3_str_t bucket, int check_bucket,
                        policy_check_t *chk) {
    if (j->type != JSON_OBJ) BAD("Statement must be an object");
    for (const json_t *m = j->child; m; m = m->next) {
        if (strcmp(m->key, "Sid") && strcmp(m->key, "Effect") && strcmp(m->key, "Principal")
            && strcmp(m->key, "Action") && strcmp(m->key, "NotAction")
            && strcmp(m->key, "Resource") && strcmp(m->key, "Condition"))
            BAD("unsupported statement element");
    }
    const json_t *sid = json_get(j, "Sid");
    if (sid && (sid->type != JSON_STR || sid->str_n > 256)) BAD("bad Sid");
    const char *eff = json_str(json_get(j, "Effect"));
    if (!eff || (strcmp(eff, "Allow") && strcmp(eff, "Deny"))) BAD("Effect must be Allow or Deny");
    s->deny = !strcmp(eff, "Deny");

    const json_t *pr = json_get(j, "Principal");
    if (!pr) BAD("Principal required");
    if (pr->type == JSON_STR) {
        if (strcmp(pr->str, "*")) BAD("Principal string must be \"*\"");
        s->any_principal = 1;
    } else if (pr->type == JSON_OBJ && pr->n_children == 1 && json_get(pr, "AWS")) {
        char **u; size_t nu;
        if (str_list(json_get(pr, "AWS"), &u, &nu) < 0) BAD("bad Principal.AWS");
        for (size_t i = 0; i < nu; i++) {
            const char *v = u[i];
            if (!strcmp(v, "*")) { s->any_principal = 1; continue; }
            if (!strncmp(v, "arn:aws:iam:::user/", 19)) memmove(u[i], v + 19, strlen(v + 19) + 1);
            if (!s3_valid_ident_strict(u[i])) { free_strs(u, nu); BAD("bad principal user"); }
        }
        s->users = u; s->n_users = nu;
    } else {
        BAD("unsupported Principal");
    }

    const json_t *ac = json_get(j, "Action"), *nac = json_get(j, "NotAction");
    if (!!ac == !!nac) BAD("exactly one of Action / NotAction");
    s->not_action = nac != NULL;
    if (str_list(ac ? ac : nac, &s->actions, &s->n_actions) < 0) BAD("bad Action");
    for (size_t i = 0; i < s->n_actions; i++) {
        const char *a = s->actions[i];
        if (strcmp(a, "*") && (strncmp(a, "s3:", 3) || strlen(a) > 64))
            BAD("actions must be s3:*");
        if (count_stars(a) > MAX_STARS) BAD("too many wildcards");
    }

    char **rs; size_t nr;
    if (str_list(json_get(j, "Resource"), &rs, &nr) < 0) BAD("Resource required");
    s->res = calloc(nr, sizeof(*s->res));
    if (!s->res) { free_strs(rs, nr); BAD("oom"); }
    for (size_t i = 0; i < nr; i++) {
        const char *r = rs[i];
        if (strncmp(r, "arn:aws:s3:::", 13)) { free_strs(rs, nr); BAD("Resource must be an S3 ARN"); }
        const char *b = r + 13, *sl = strchr(b, '/');
        size_t bn = sl ? (size_t)(sl - b) : strlen(b);
        /* S6: a policy may only name its own bucket (no bucket wildcards). */
        if (bn == 0 || bn > 63 || memchr(b, '*', bn) || memchr(b, '?', bn)
            || (check_bucket && (bn != bucket.n || memcmp(b, bucket.p, bn)))) {
            free_strs(rs, nr); BAD("Resource must name this bucket");
        }
        s->res[i].bucket = strndup(b, bn);
        if (sl) {
            s->res[i].key_pat = strdup(sl + 1);
            if (count_stars(sl + 1) > MAX_STARS) { s->n_res = i + 1; free_strs(rs, nr); BAD("too many wildcards"); }
        }
        s->n_res = i + 1;
    }
    free_strs(rs, nr);

    const json_t *co = json_get(j, "Condition");
    if (co) {
        if (co->type != JSON_OBJ) BAD("Condition must be an object");
        for (const json_t *op = co->child; op; op = op->next) {
            int o;
            if (!strcmp(op->key, "StringEquals")) o = COND_STR_EQ;
            else if (!strcmp(op->key, "StringNotEquals")) o = COND_STR_NE;
            else if (!strcmp(op->key, "StringLike")) o = COND_STR_LIKE;
            else if (!strcmp(op->key, "IpAddress")) o = COND_IP;
            else if (!strcmp(op->key, "NotIpAddress")) o = COND_NOT_IP;
            else if (!strcmp(op->key, "Bool")) o = COND_BOOL;
            else BAD("unsupported condition operator");
            if (op->type != JSON_OBJ || op->n_children == 0) BAD("bad condition block");
            for (const json_t *k = op->child; k; k = k->next) {
                int key;
                if (!strcmp(k->key, "aws:SourceIp")) key = KEY_SOURCE_IP;
                else if (!strcmp(k->key, "aws:SecureTransport")) key = KEY_SECURE;
                else if (!strcmp(k->key, "s3:prefix")) key = KEY_PREFIX;
                else if (!strcmp(k->key, "aws:username")) key = KEY_USERNAME;
                else BAD("unsupported condition key");
                int ipop = o == COND_IP || o == COND_NOT_IP;
                if ((key == KEY_SOURCE_IP) != ipop || (key == KEY_SECURE) != (o == COND_BOOL))
                    BAD("condition operator does not fit key");
                cond_t c = { o, key, NULL, 0 };
                if (str_list(k, &c.vals, &c.n) < 0) BAD("bad condition value");
                for (size_t i = 0; i < c.n; i++) {
                    if ((ipop && !valid_cidr(c.vals[i]))
                        || (o == COND_BOOL && strcmp(c.vals[i], "true") && strcmp(c.vals[i], "false"))
                        || (o == COND_STR_LIKE && count_stars(c.vals[i]) > MAX_STARS)) {
                        free_strs(c.vals, c.n); BAD("bad condition value");
                    }
                }
                cond_t *nc = realloc(s->conds, (s->n_conds + 1) * sizeof(*nc));
                if (!nc) { free_strs(c.vals, c.n); BAD("oom"); }
                s->conds = nc;
                s->conds[s->n_conds++] = c;
            }
        }
    }

    if (chk && !s->deny && s->any_principal) {
        chk->public_read = 1;
        for (size_t i = 0; i < s->n_actions; i++)
            if (s->not_action || action_writes(s->actions[i])) chk->public_write = 1;
    }
    return 0;
bad:
    return -1;
}

static policy_t *compile(const char *src, size_t n, s3_str_t bucket, int check_bucket,
                         policy_check_t *chk) {
    if (chk) { memset(chk, 0, sizeof(*chk)); chk->err = S3_ERR_MALFORMED_POLICY; }
    policy_t *p = NULL;
    json_t *j = NULL;
    if (n == 0 || n > POLICY_MAX_BYTES) BAD("policy size must be 1..20480 bytes");
    j = json_parse(src, n, 8, 4096);
    if (!j || j->type != JSON_OBJ) BAD("invalid JSON");
    for (const json_t *m = j->child; m; m = m->next)
        if (strcmp(m->key, "Version") && strcmp(m->key, "Id") && strcmp(m->key, "Statement"))
            BAD("unsupported top-level element");
    const char *ver = json_str(json_get(j, "Version"));
    if (!ver || strcmp(ver, "2012-10-17")) BAD("Version must be 2012-10-17");
    const json_t *st = json_get(j, "Statement");
    if (!st) BAD("Statement required");
    size_t ns = st->type == JSON_ARR ? st->n_children : 1;
    if (ns == 0 || ns > MAX_STATEMENTS) BAD("1..64 statements");
    p = calloc(1, sizeof(*p));
    if (!p || !(p->st = calloc(ns, sizeof(*p->st)))) BAD("oom");
    const json_t *e = st->type == JSON_ARR ? st->child : st;
    for (size_t i = 0; i < ns; i++, e = e->next) {
        p->n = i + 1;
        if (compile_stmt(e, &p->st[i], bucket, check_bucket, chk) < 0) goto bad;
    }
    json_free(j);
    if (chk) chk->err = S3_OK;
    return p;
bad:
    json_free(j);
    policy_free(p);
    return NULL;
}

policy_t *policy_compile(const char *json, size_t n, s3_str_t bucket,
                         policy_check_t *chk) {
    return compile(json, n, bucket, 1, chk);
}

void *policy_parse_cb(const char *json, size_t n) {
    return compile(json, n, S3_STR_NULL, 0, NULL);
}

/* ---- Evaluation ------------------------------------------------------ */

static int cond_holds(const cond_t *c, const policy_req_t *r) {
    const char *v = NULL;
    s3_str_t sv = S3_STR_NULL;
    switch (c->key) {
    case KEY_SOURCE_IP: v = r->source_ip; break;
    case KEY_SECURE:    v = r->secure ? "true" : "false"; break;
    case KEY_PREFIX:    if (!r->has_prefix) return c->op == COND_STR_NE; sv = r->prefix; break;
    case KEY_USERNAME:  v = r->user; break;
    }
    if (v) sv = (s3_str_t){ v, strlen(v) };
    int any = 0;
    for (size_t i = 0; i < c->n && !any; i++) {
        switch (c->op) {
        case COND_STR_EQ: case COND_STR_NE: case COND_BOOL:
            any = s3_str_eq_lit(sv, c->vals[i]); break;
        case COND_STR_LIKE:
            any = policy_glob(c->vals[i], sv); break;
        case COND_IP: case COND_NOT_IP:
            any = v && policy_ip_in(v, c->vals[i]); break;
        }
    }
    if (c->op == COND_STR_NE || c->op == COND_NOT_IP) {
        /* Missing source IP never satisfies NotIpAddress (fail closed for
         * Allow; a Deny then doesn't fire — conservative either way is
         * documented: aws:SourceIp is advisory behind a proxy). */
        if (c->op == COND_NOT_IP && !v) return 0;
        return !any;
    }
    return any;
}

static int stmt_matches(const stmt_t *s, const policy_req_t *r) {
    int pm = s->any_principal;
    for (size_t i = 0; !pm && i < s->n_users; i++)
        pm = r->user[0] && !strcmp(s->users[i], r->user);
    if (!pm) return 0;
    s3_str_t act = { r->action, strlen(r->action) };
    int am = 0;
    for (size_t i = 0; !am && i < s->n_actions; i++) am = policy_glob(s->actions[i], act);
    if (s->not_action) am = !am;
    if (!am) return 0;
    int rm = 0;
    for (size_t i = 0; !rm && i < s->n_res; i++) {
        const res_t *x = &s->res[i];
        if (strlen(x->bucket) != r->bucket.n || memcmp(x->bucket, r->bucket.p, r->bucket.n)) continue;
        if (r->key.n == 0) rm = x->key_pat == NULL;
        else rm = x->key_pat && policy_glob(x->key_pat, r->key);
    }
    if (!rm) return 0;
    for (size_t i = 0; i < s->n_conds; i++)
        if (!cond_holds(&s->conds[i], r)) return 0;
    return 1;
}

policy_effect_t policy_eval(const policy_t *p, const policy_req_t *r) {
    if (!p) return POLICY_NONE;
    int allow = 0;
    for (size_t i = 0; i < p->n; i++) {
        if (!stmt_matches(&p->st[i], r)) continue;
        if (p->st[i].deny) return POLICY_DENY;
        allow = 1;
    }
    return allow ? POLICY_ALLOW : POLICY_NONE;
}
