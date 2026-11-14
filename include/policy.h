/* include/policy.h — bucket policies, a strict IAM JSON subset (item 9)
 *
 * Enough for public-read buckets, cross-user sharing with prefix limits,
 * IP allowlists and "deny non-TLS". Anything outside the grammar is
 * MalformedPolicy (fail closed):
 *
 *   Version     "2012-10-17"
 *   Statement   object or array (≤ 64), each with
 *     Sid        string (optional)
 *     Effect     "Allow" | "Deny"
 *     Principal  "*" | {"AWS": "*" | "<user>" | "arn:aws:iam:::user/<user>" | [...]}
 *     Action | NotAction   "s3:<Name>" patterns, '*' wildcards (≤ 4 per pattern)
 *     Resource   "arn:aws:s3:::<this-bucket>" | "arn:aws:s3:::<this-bucket>/<pattern>"
 *     Condition  {StringEquals|StringNotEquals|StringLike|IpAddress|
 *                 NotIpAddress|Bool: {key: value | [values]}}
 *                keys: aws:SourceIp, aws:SecureTransport, s3:prefix, aws:username
 *
 * NotPrincipal, NotResource, unknown operators/keys, other buckets in
 * Resource, duplicate JSON keys and nesting deeper than 8 are refused.
 * Glob matching is linear-time-bounded (two-pointer, capped stars).
 */
#ifndef FS3_POLICY_H
#define FS3_POLICY_H

#include <stddef.h>
#include "s3.h"

#define POLICY_MAX_BYTES (20 * 1024)

typedef struct policy policy_t;

typedef struct {
    s3_err_t    err;              /* S3_OK or S3_ERR_MALFORMED_POLICY */
    int         public_read;      /* an Allow names Principal "*" */
    int         public_write;     /* ... for an action that can write */
    const char *msg;              /* reason, for logs */
} policy_check_t;

/* Compile; NULL on error (details in *chk if non-NULL). `bucket` is the
 * bucket the policy is attached to (Resource must name it). */
policy_t *policy_compile(const char *json, size_t n, s3_str_t bucket,
                         policy_check_t *chk);
void      policy_free(policy_t *p);

/* Request context for evaluation. */
typedef struct {
    const char *user;             /* "" = anonymous */
    const char *action;           /* "s3:GetObject" */
    s3_str_t    bucket, key;      /* key empty for bucket-level actions */
    const char *source_ip;        /* textual IPv4/IPv6, may be NULL */
    int         secure;           /* aws:SecureTransport */
    s3_str_t    prefix;           /* s3:prefix (ListBucket ?prefix=) */
    int         has_prefix;
} policy_req_t;

typedef enum { POLICY_NONE = 0, POLICY_ALLOW, POLICY_DENY } policy_effect_t;

/* Explicit Deny anywhere → DENY; else any matching Allow → ALLOW; else
 * NONE (the caller's other rules decide). */
policy_effect_t policy_eval(const policy_t *p, const policy_req_t *r);

/* Glob with '*' (any run) and '?' (one char); linear-time bounded. */
int policy_glob(const char *pat, s3_str_t s);

/* IPv4/IPv6 address in CIDR ("10.0.0.0/8", "2001:db8::/32", bare IP).
 * IPv4-mapped IPv6 addresses compare as IPv4. */
int policy_ip_in(const char *ip, const char *cidr);

/* store_sidecar_get adapters; the bucket name is not known there, so the
 * cached form is compiled without the Resource-bucket check (it was
 * checked when the policy was stored). */
void *policy_parse_cb(const char *json, size_t n);
void  policy_free_cb(void *p);

#endif
