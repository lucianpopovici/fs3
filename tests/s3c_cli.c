/* tests/s3c_cli.c — test driver for src/s3client.c.
 *
 *   s3c_cli [--ca FILE] [--insecure] [--vhost] ENDPOINT AK SK REGION CMD ARGS...
 *
 *   put BUCKET KEY FILE [content-type] [hdr=value ...]
 *   get BUCKET KEY OUTFILE [max-bytes]
 *   head BUCKET KEY
 *   delete BUCKET KEY
 *   mpu BUCKET KEY FILE PARTSIZE        (create, upload parts, complete)
 *   mpu-abort BUCKET KEY FILE PARTSIZE  (create, upload part 1, abort)
 *   multi BUCKET KEY FILE N             (N PUTs on one connection)
 *
 * Prints "status=<n> etag=<e> code=<c> version=<v>" for the final
 * response, or "error: <msg>" and exits 2 on a transport error.
 */
#include "s3client.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static s3c_t *g_c;
static void show(const s3c_resp_t *r) {
    printf("status=%d etag=%s code=%s version=%s len=%llu connects=%u\n", r->status, r->etag,
           r->code, r->version_id, (unsigned long long)r->content_length, s3c_connects(g_c));
}

static int fail(s3c_t *c) {
    printf("error: %s\n", s3c_err(c));
    return 2;
}

int main(int argc, char **argv) {
    s3c_endpoint_t ep;
    memset(&ep, 0, sizeof(ep));
    ep.verify_tls = 1;
    ep.timeout_s = 10;
    int i = 1;
    for (; i < argc && !strncmp(argv[i], "--", 2); i++) {
        if (!strcmp(argv[i], "--ca") && i + 1 < argc)
            snprintf(ep.ca_file, sizeof(ep.ca_file), "%s", argv[++i]);
        else if (!strcmp(argv[i], "--insecure")) ep.verify_tls = 0;
        else if (!strcmp(argv[i], "--vhost")) ep.virtual_host = 1;
        else { fprintf(stderr, "unknown option %s\n", argv[i]); return 64; }
    }
    if (argc - i < 6) { fprintf(stderr, "usage: see source\n"); return 64; }
    char err[128];
    if (s3c_parse_endpoint(argv[i], &ep, err, sizeof(err)) < 0) { printf("bad endpoint: %s\n", err); return 3; }
    snprintf(ep.access_key, sizeof(ep.access_key), "%s", argv[i + 1]);
    snprintf(ep.secret_key, sizeof(ep.secret_key), "%s", argv[i + 2]);
    snprintf(ep.region, sizeof(ep.region), "%s", argv[i + 3]);
    const char *cmd = argv[i + 4];
    const char *bucket = argv[i + 5];
    const char *key = argc - i > 6 ? argv[i + 6] : NULL;
    char **rest = argv + i + 7;
    int nrest = argc - i - 7;
    if (nrest < 0) nrest = 0;

    s3c_t *c = s3c_new(&ep);
    g_c = c;
    s3c_resp_t r;
    int rc = 0;

    if (!strcmp(cmd, "put") || !strcmp(cmd, "multi")) {
        if (nrest < 1) return 64;
        int fd = open(rest[0], O_RDONLY);
        if (fd < 0) { perror(rest[0]); return 1; }
        struct stat st;
        fstat(fd, &st);
        s3c_put_opts_t o = { 0 };
        s3c_hdr_t h[16];
        int reps = 1;
        if (!strcmp(cmd, "multi")) reps = nrest > 1 ? atoi(rest[1]) : 2;
        else {
            if (nrest > 1) o.content_type = rest[1];
            for (int k = 2; k < nrest && o.n_headers < 16; k++) {
                char *eq = strchr(rest[k], '=');
                if (!eq) continue;
                *eq = 0;
                h[o.n_headers].name = rest[k];
                h[o.n_headers].value = eq + 1;
                o.n_headers++;
            }
            o.headers = h;
        }
        for (int k = 0; k < reps; k++) {
            char kk[1024];
            if (reps > 1) snprintf(kk, sizeof(kk), "%s.%d", key, k); else snprintf(kk, sizeof(kk), "%s", key);
            rc = s3c_put_object(c, bucket, kk, fd, 0, (uint64_t)st.st_size, &o, &r);
            if (rc < 0) { close(fd); return fail(c); }
            if (r.status != 200) break;
        }
        close(fd);
    } else if (!strcmp(cmd, "get")) {
        if (nrest < 1) return 64;
        int fd = open(rest[0], O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) { perror(rest[0]); return 1; }
        uint64_t max = nrest > 1 ? strtoull(rest[1], NULL, 10) : 0;
        rc = s3c_get_object(c, bucket, key, fd, max, &r);
        close(fd);
        if (rc < 0) return fail(c);
    } else if (!strcmp(cmd, "head")) {
        if (s3c_head_object(c, bucket, key, &r) < 0) return fail(c);
    } else if (!strcmp(cmd, "delete")) {
        if (s3c_delete_object(c, bucket, key, &r) < 0) return fail(c);
    } else if (!strcmp(cmd, "mpu") || !strcmp(cmd, "mpu-abort")) {
        if (nrest < 2) return 64;
        int fd = open(rest[0], O_RDONLY);
        if (fd < 0) { perror(rest[0]); return 1; }
        struct stat st;
        fstat(fd, &st);
        uint64_t ps = strtoull(rest[1], NULL, 10);
        if (s3c_mpu_create(c, bucket, key, NULL, &r) < 0) return fail(c);
        if (r.status != 200) { show(&r); return 0; }
        char uid[256];
        snprintf(uid, sizeof(uid), "%s", r.upload_id);
        int np = (int)((st.st_size + ps - 1) / ps);
        if (np < 1) np = 1;
        char (*etags)[80] = calloc((size_t)np, 80);
        int abort_after = !strcmp(cmd, "mpu-abort");
        for (int p = 0; p < np; p++) {
            uint64_t off = (uint64_t)p * ps, len = (uint64_t)st.st_size - off;
            if (len > ps) len = ps;
            if (s3c_mpu_upload_part(c, bucket, key, uid, p + 1, fd, (off_t)off, len, &r) < 0) return fail(c);
            if (r.status != 200) { show(&r); return 0; }
            snprintf(etags[p], 80, "%s", r.etag);
            if (abort_after) break;
        }
        if (abort_after) rc = s3c_mpu_abort(c, bucket, key, uid, &r);
        else rc = s3c_mpu_complete(c, bucket, key, uid, etags, np, &r);
        free(etags);
        close(fd);
        if (rc < 0) return fail(c);
    } else {
        fprintf(stderr, "unknown command %s\n", cmd);
        return 64;
    }
    show(&r);
    s3c_free(c);
    return 0;
}
