/* src/action.c — the exhaustive S3 action table (see include/action.h). */

#include "action.h"

#include <stddef.h>

#define B 1   /* bucket-level resource */
#define O 0   /* object-level resource */

static const s3_action_info_t TABLE[ACT_MAX] = {
    [ACT_LIST_BUCKETS]            = { "s3:ListAllMyBuckets",               PERM_R, B },

    [ACT_CREATE_BUCKET]           = { "s3:CreateBucket",                   PERM_O, B },
    [ACT_DELETE_BUCKET]           = { "s3:DeleteBucket",                   PERM_O, B },
    [ACT_HEAD_BUCKET]             = { "s3:ListBucket",                     PERM_R, B },
    [ACT_LIST_OBJECTS]            = { "s3:ListBucket",                     PERM_R, B },
    [ACT_LIST_OBJECT_VERSIONS]    = { "s3:ListBucketVersions",             PERM_R, B },
    [ACT_LIST_MPU_UPLOADS]        = { "s3:ListBucketMultipartUploads",     PERM_R, B },
    [ACT_DELETE_OBJECTS]          = { "s3:DeleteObject",                   PERM_W, B },
    [ACT_GET_BUCKET_LOCATION]     = { "s3:GetBucketLocation",              PERM_R, B },
    [ACT_GET_BUCKET_VERSIONING]   = { "s3:GetBucketVersioning",            PERM_O, B },
    [ACT_PUT_BUCKET_VERSIONING]   = { "s3:PutBucketVersioning",            PERM_O, B },
    [ACT_GET_BUCKET_ACL]          = { "s3:GetBucketAcl",                   PERM_O, B },
    [ACT_PUT_BUCKET_ACL]          = { "s3:PutBucketAcl",                   PERM_O, B },
    [ACT_GET_BUCKET_CORS]         = { "s3:GetBucketCORS",                  PERM_O, B },
    [ACT_PUT_BUCKET_CORS]         = { "s3:PutBucketCORS",                  PERM_O, B },
    [ACT_DELETE_BUCKET_CORS]      = { "s3:PutBucketCORS",                  PERM_O, B },
    [ACT_GET_BUCKET_LIFECYCLE]    = { "s3:GetLifecycleConfiguration",      PERM_O, B },
    [ACT_PUT_BUCKET_LIFECYCLE]    = { "s3:PutLifecycleConfiguration",      PERM_O, B },
    [ACT_DELETE_BUCKET_LIFECYCLE] = { "s3:PutLifecycleConfiguration",      PERM_O, B },
    [ACT_GET_BUCKET_WEBSITE]      = { "s3:GetBucketWebsite",               PERM_O, B },
    [ACT_PUT_BUCKET_WEBSITE]      = { "s3:PutBucketWebsite",               PERM_O, B },
    [ACT_DELETE_BUCKET_WEBSITE]   = { "s3:DeleteBucketWebsite",            PERM_O, B },
    [ACT_GET_BUCKET_POLICY]       = { "s3:GetBucketPolicy",                PERM_O, B },
    [ACT_PUT_BUCKET_POLICY]       = { "s3:PutBucketPolicy",                PERM_O, B },
    [ACT_DELETE_BUCKET_POLICY]    = { "s3:DeleteBucketPolicy",             PERM_O, B },
    [ACT_GET_BUCKET_OBJECT_LOCK]  = { "s3:GetBucketObjectLockConfiguration", PERM_O, B },
    [ACT_PUT_BUCKET_OBJECT_LOCK]  = { "s3:PutBucketObjectLockConfiguration", PERM_O, B },

    [ACT_GET_OBJECT]              = { "s3:GetObject",                      PERM_R, O },
    [ACT_HEAD_OBJECT]             = { "s3:GetObject",                      PERM_R, O },
    [ACT_PUT_OBJECT]              = { "s3:PutObject",                      PERM_W, O },
    [ACT_COPY_OBJECT]             = { "s3:PutObject",                      PERM_W, O },
    [ACT_DELETE_OBJECT]           = { "s3:DeleteObject",                   PERM_W, O },
    [ACT_GET_OBJECT_ACL]          = { "s3:GetObjectAcl",                   PERM_O, O },
    [ACT_PUT_OBJECT_ACL]          = { "s3:PutObjectAcl",                   PERM_O, O },
    [ACT_GET_OBJECT_RETENTION]    = { "s3:GetObjectRetention",             PERM_R, O },
    [ACT_PUT_OBJECT_RETENTION]    = { "s3:PutObjectRetention",             PERM_O, O },
    [ACT_GET_OBJECT_LEGAL_HOLD]   = { "s3:GetObjectLegalHold",             PERM_R, O },
    [ACT_PUT_OBJECT_LEGAL_HOLD]   = { "s3:PutObjectLegalHold",             PERM_O, O },

    [ACT_MPU_CREATE]              = { "s3:PutObject",                      PERM_W, O },
    [ACT_MPU_UPLOAD_PART]         = { "s3:PutObject",                      PERM_W, O },
    [ACT_MPU_COMPLETE]            = { "s3:PutObject",                      PERM_W, O },
    [ACT_MPU_ABORT]               = { "s3:AbortMultipartUpload",           PERM_W, O },
    [ACT_MPU_LIST_PARTS]          = { "s3:ListMultipartUploadParts",       PERM_R, O },
};

#undef B
#undef O

const s3_action_info_t *action_info(s3_action_t a) {
    if (a <= ACT_NONE || a >= ACT_MAX) return NULL;
    if (!TABLE[a].iam_name) return NULL;
    return &TABLE[a];
}

const char *action_name(s3_action_t a) {
    const s3_action_info_t *i = action_info(a);
    return i ? i->iam_name : "-";
}

int action_selfcheck(void) {
    for (int a = ACT_NONE + 1; a < ACT_MAX; a++)
        if (!TABLE[a].iam_name || !TABLE[a].perm) return -1;
    return 0;
}
