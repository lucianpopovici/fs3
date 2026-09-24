/* tests/test_credfile.c — unit tests for the credentials-file v2 parser
 *
 * main.c is the security boundary for identity mode (brief 12a), so its
 * line/field parsing gets a dedicated harness here rather than only
 * end-to-end coverage. Compiled with -DFS3_MAIN_TESTING, which excludes
 * main()/on_signal/g_server from src/main.c (see the test-hook section
 * at the bottom of that file) so this binary can supply its own main()
 * without pulling in the server's dependency chain.
 */

#include "sigv4.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Test hooks declared in main.c under FS3_MAIN_TESTING, mirroring
 * sigv4.c's SIGV4_TESTING seam. */
int main_test_parse_and_add_cred(sigv4_verifier_t *v, const char *spec);
int main_test_parse_cred_v2_line(sigv4_verifier_t *v, char *line);
int main_test_load_credentials_file(sigv4_verifier_t *v, const char *path);

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) do {                                       \
    if (cond) { g_pass++; }                                         \
    else { fprintf(stderr, "FAIL: %s (%s:%d)\n",                    \
                   msg, __FILE__, __LINE__); g_fail++; }             \
} while (0)

/* ---------------------------------------------------------------- */
/* parse_cred_v2_line — line-level                                  */
/* ---------------------------------------------------------------- */

static void t_v2_line_valid(void) {
    sigv4_verifier_t *v = sigv4_create();
    char line[256];
    strcpy(line, "AKIAALICE0000000001\talice\t1700000000000\tlaptop\tsecretvalue");
    CHECK(main_test_parse_cred_v2_line(v, line) == 0, "valid v2 line accepted");
    sigv4_destroy(v);
}

static void t_v2_line_admin_empty_owner(void) {
    sigv4_verifier_t *v = sigv4_create();
    char line[256];
    strcpy(line, "AKIAADMIN000000000A\t\t1700000000000\tinstall\tsecretvalue");
    CHECK(main_test_parse_cred_v2_line(v, line) == 0, "empty-owner v2 line accepted");
    sigv4_destroy(v);
}

static void t_v2_line_secret_with_colon_preserved(void) {
    /* ':' is not a safe separator for v2 (that's why it's tab-separated
     * with the secret last) — a colon in the secret must parse fine. */
    sigv4_verifier_t *v = sigv4_create();
    char line[256];
    strcpy(line, "AKIAALICE0000000001\talice\t1700000000000\tlaptop\tsecret:with:colons");
    CHECK(main_test_parse_cred_v2_line(v, line) == 0,
          "secret containing ':' accepted");
    sigv4_destroy(v);
}

static void t_v2_line_too_few_tabs_rejected(void) {
    sigv4_verifier_t *v = sigv4_create();
    char line[256];
    strcpy(line, "AKIAALICE0000000001\talice\t1700000000000\tlaptop");
    CHECK(main_test_parse_cred_v2_line(v, line) == -1,
          "line with only 3 tabs (missing secret) rejected");
    sigv4_destroy(v);
}

static void t_v2_line_bad_access_key_charset_rejected(void) {
    sigv4_verifier_t *v = sigv4_create();
    char line[256];
    strcpy(line, "akia-lowercase-and-dash\talice\t1700000000000\tlaptop\tsecretvalue");
    CHECK(main_test_parse_cred_v2_line(v, line) == -1,
          "lowercase/dash access key rejected");
    sigv4_destroy(v);
}

static void t_v2_line_empty_secret_rejected(void) {
    sigv4_verifier_t *v = sigv4_create();
    char line[256];
    strcpy(line, "AKIAALICE0000000001\talice\t1700000000000\tlaptop\t");
    CHECK(main_test_parse_cred_v2_line(v, line) == -1, "empty secret rejected");
    sigv4_destroy(v);
}

static void t_v2_line_non_numeric_created_ms_rejected(void) {
    sigv4_verifier_t *v = sigv4_create();
    char line[256];
    strcpy(line, "AKIAALICE0000000001\talice\tnot-a-number\tlaptop\tsecretvalue");
    CHECK(main_test_parse_cred_v2_line(v, line) == -1,
          "non-numeric created_ms rejected");
    sigv4_destroy(v);
}

static void t_v2_line_tab_in_owner_naturally_rejected(void) {
    /* A stray TAB meant to be part of "owner" instead splits the line
     * one field early: what was meant as the rest of the owner lands in
     * created_ms, which then fails its digits-only check. There is no
     * way to escape a TAB in v2 — this is the expected failure mode. */
    sigv4_verifier_t *v = sigv4_create();
    char line[256];
    strcpy(line, "AKIAALICE0000000001\towner\twith\ttab\t1700000000000\tlabel\tsecretvalue");
    CHECK(main_test_parse_cred_v2_line(v, line) == -1,
          "stray TAB in intended owner field rejected");
    sigv4_destroy(v);
}

/* ---------------------------------------------------------------- */
/* load_credentials_file — file-level, magic detection + fallback   */
/* ---------------------------------------------------------------- */

static char g_path[256];

static void write_file(const char *content) {
    snprintf(g_path, sizeof(g_path), "/tmp/fs3-credfile-test.XXXXXX");
    int fd = mkstemp(g_path);
    CHECK(fd >= 0, "mkstemp");
    ssize_t n = write(fd, content, strlen(content));
    CHECK(n == (ssize_t)strlen(content), "write temp credentials file");
    close(fd);
}

static void cleanup_file(void) { unlink(g_path); }

static void t_v1_line_still_works(void) {
    write_file("# comment\nAKIALEGACY00000001:secretvalue\n");
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_load_credentials_file(v, g_path) == 0,
          "v1 file (no v2 magic) still loads");
    sigv4_destroy(v);
    cleanup_file();
}

static void t_v2_magic_detected_and_parsed(void) {
    write_file(
        "#fs3-credentials v2\n"
        "AKIAALICE0000000001\talice\t1700000000000\tlaptop\tsecretalice\n"
        "AKIABOB000000000001\tbob\t1700000000001\tbackup\tsecretbob\n"
        "AKIAADMIN000000000A\t\t1700000000002\tinstall\tsecretadmin\n");
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_load_credentials_file(v, g_path) == 0,
          "v2 file with 3 valid lines loads");
    sigv4_destroy(v);
    cleanup_file();
}

static void t_v2_file_with_invalid_line_fails_closed(void) {
    write_file(
        "#fs3-credentials v2\n"
        "AKIAALICE0000000001\talice\t1700000000000\tlaptop\tsecretalice\n"
        "not-a-valid-v2-line\n");
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_load_credentials_file(v, g_path) != 0,
          "v2 file with one malformed line fails the whole load");
    sigv4_destroy(v);
    cleanup_file();
}

static void t_near_miss_magic_falls_back_to_v1(void) {
    /* Not an exact match for "#fs3-credentials v2" (trailing space) —
     * must NOT be treated as v2. Since it starts with '#', v1 parsing
     * treats it as a comment and moves on; the tab-shaped second line
     * has no ':' for v1 to split on and so is rejected as v1, which is
     * the correct fail-closed outcome for content that looks v2-ish but
     * didn't hit the exact magic. */
    write_file(
        "#fs3-credentials v2 \n"
        "AKIAALICE0000000001\talice\t1700000000000\tlaptop\tsecretalice\n");
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_load_credentials_file(v, g_path) != 0,
          "near-miss magic line falls back to v1 and rejects the tab-shaped line");
    sigv4_destroy(v);
    cleanup_file();
}

int main(void) {
    t_v2_line_valid();
    t_v2_line_admin_empty_owner();
    t_v2_line_secret_with_colon_preserved();
    t_v2_line_too_few_tabs_rejected();
    t_v2_line_bad_access_key_charset_rejected();
    t_v2_line_empty_secret_rejected();
    t_v2_line_non_numeric_created_ms_rejected();
    t_v2_line_tab_in_owner_naturally_rejected();
    t_v1_line_still_works();
    t_v2_magic_detected_and_parsed();
    t_v2_file_with_invalid_line_fails_closed();
    t_near_miss_magic_falls_back_to_v1();

    fprintf(stderr, "===== %d passed, %d failed =====\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
