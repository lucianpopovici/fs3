/* tests/fuzz_targets.h — extra config parsers for test_config_fuzz.c. */
#ifndef FS3_FUZZ_TARGETS_H
#define FS3_FUZZ_TARGETS_H
#include <stddef.h>
#include "lifecycle.h"

#define FUZZ_EXTRA_SEEDS \
    "<LifecycleConfiguration><Rule><ID>a</ID><Status>Enabled</Status>" \
    "<Filter><And><Prefix>tmp/</Prefix></And></Filter><Expiration><Days>3</Days>" \
    "</Expiration><AbortIncompleteMultipartUpload><DaysAfterInitiation>2" \
    "</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>" \
    "<Rule><Status>Disabled</Status><Prefix>x</Prefix><Expiration>" \
    "<Date>2030-01-01T00:00:00.000Z</Date></Expiration></Rule></LifecycleConfiguration>"

static inline long fuzz_extra(const char *buf, size_t n) {
    long ok = 0;
    s3_err_t e;
    lc_config_t *lc = lc_parse(buf, n, &e);
    if (lc) {
        ok++;
        lc_expiry_ms(lc, (s3_str_t){ "tmp/x", 5 }, 0);
        lc_free(lc);
    }
    return ok;
}
#endif
