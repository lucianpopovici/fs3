/* tests/fuzz_targets.h — extra config parsers for test_config_fuzz.c.
 * Each later parser (lifecycle, website, policy) adds a seed and a call. */
#ifndef FS3_FUZZ_TARGETS_H
#define FS3_FUZZ_TARGETS_H
#include <stddef.h>
#define FUZZ_EXTRA_SEEDS "<CORSConfiguration/>"
static inline long fuzz_extra(const char *buf, size_t n) { (void)buf; (void)n; return 0; }
#endif
