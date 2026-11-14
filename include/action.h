/* include/action.h — S3 operations and authorization classes
 *
 * Every request the router accepts is classified into exactly one
 * s3_action_t *from the S3 operation*, not the HTTP method: GET ?acl is
 * ACT_GET_OBJECT_ACL, not ACT_GET_OBJECT. Authorization (route.c
 * authz()) and policy evaluation key off the action, and logs print its
 * S3 IAM name.
 *
 * The table in action.c is exhaustive: action_selfcheck() fails if any
 * action lacks an entry, and the server refuses to start in that case
 * (default deny — a handler without a mapping can never be reached).
 */
#ifndef FS3_ACTION_H
#define FS3_ACTION_H

typedef enum {
    ACT_NONE = 0,               /* unclassified: always denied */

    /* Service */
    ACT_LIST_BUCKETS,

    /* Bucket */
    ACT_CREATE_BUCKET,
    ACT_DELETE_BUCKET,
    ACT_HEAD_BUCKET,
    ACT_LIST_OBJECTS,
    ACT_LIST_OBJECT_VERSIONS,
    ACT_LIST_MPU_UPLOADS,
    ACT_DELETE_OBJECTS,         /* POST ?delete — each key still needs w */
    ACT_GET_BUCKET_LOCATION,
    ACT_GET_BUCKET_VERSIONING,
    ACT_PUT_BUCKET_VERSIONING,
    ACT_GET_BUCKET_ACL,
    ACT_PUT_BUCKET_ACL,
    ACT_GET_BUCKET_CORS,
    ACT_PUT_BUCKET_CORS,
    ACT_DELETE_BUCKET_CORS,
    ACT_GET_BUCKET_LIFECYCLE,
    ACT_PUT_BUCKET_LIFECYCLE,
    ACT_DELETE_BUCKET_LIFECYCLE,
    ACT_GET_BUCKET_WEBSITE,
    ACT_PUT_BUCKET_WEBSITE,
    ACT_DELETE_BUCKET_WEBSITE,
    ACT_GET_BUCKET_POLICY,
    ACT_PUT_BUCKET_POLICY,
    ACT_DELETE_BUCKET_POLICY,
    ACT_GET_BUCKET_OBJECT_LOCK,
    ACT_PUT_BUCKET_OBJECT_LOCK,

    /* Object */
    ACT_GET_OBJECT,
    ACT_HEAD_OBJECT,
    ACT_PUT_OBJECT,
    ACT_COPY_OBJECT,            /* destination side; source needs GET */
    ACT_DELETE_OBJECT,
    ACT_GET_OBJECT_ACL,
    ACT_PUT_OBJECT_ACL,
    ACT_GET_OBJECT_RETENTION,
    ACT_PUT_OBJECT_RETENTION,
    ACT_GET_OBJECT_LEGAL_HOLD,
    ACT_PUT_OBJECT_LEGAL_HOLD,

    /* Multipart */
    ACT_MPU_CREATE,
    ACT_MPU_UPLOAD_PART,
    ACT_MPU_COMPLETE,
    ACT_MPU_ABORT,
    ACT_MPU_LIST_PARTS,

    ACT_MAX
} s3_action_t;

/* Permission class an action needs under per-user grants (item 3):
 * 'r' read, 'w' write, 'o' owner (config). */
typedef enum { PERM_R = 1, PERM_W = 2, PERM_O = 4 } s3_perm_t;

typedef struct {
    const char *iam_name;       /* "s3:GetObject" */
    s3_perm_t   perm;
    int         bucket_level;   /* resource is the bucket, not an object */
} s3_action_info_t;

/* NULL for ACT_NONE / out of range. */
const s3_action_info_t *action_info(s3_action_t a);
const char *action_name(s3_action_t a);

/* 0 if every action in (ACT_NONE, ACT_MAX) has a table entry. */
int action_selfcheck(void);

#endif
