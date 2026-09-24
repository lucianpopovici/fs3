/* tests/test_credfile.c — unit tests for the credentials-file parser
 *
 * main.c is the security boundary for per-user bucket isolation, so its
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
int main_test_load_credentials_file(sigv4_verifier_t *v, const char *path);
int main_test_valid_identity(const char *u);

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) do {                                       \
    if (cond) { g_pass++; }                                         \
    else { fprintf(stderr, "FAIL: %s (%s:%d)\n",                    \
                   msg, __FILE__, __LINE__); g_fail++; }             \
} while (0)

/* ---------------------------------------------------------------- */
/* parse_and_add_cred — "access_key:secret_key[:user]"              */
/* ---------------------------------------------------------------- */

static void t_cred_no_user_defaults_to_access_key(void) {
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_parse_and_add_cred(v, "AKIAALICE0000000001:secretvalue") == 0,
          "ak:sk with no user accepted");
    sigv4_destroy(v);
}

static void t_cred_with_explicit_user(void) {
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_parse_and_add_cred(v, "AKIAALICE0000000001:secretvalue:alice") == 0,
          "ak:sk:user accepted");
    sigv4_destroy(v);
}

static void t_cred_no_colon_rejected(void) {
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_parse_and_add_cred(v, "AKIANOOCLON") == -1,
          "spec with no colon rejected");
    sigv4_destroy(v);
}

static void t_cred_empty_secret_rejected(void) {
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_parse_and_add_cred(v, "AKIAALICE0000000001:") == -1,
          "empty secret rejected");
    sigv4_destroy(v);
}

static void t_cred_empty_access_key_rejected(void) {
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_parse_and_add_cred(v, ":secretvalue") == -1,
          "empty access key rejected");
    sigv4_destroy(v);
}

static void t_cred_empty_user_field_rejected(void) {
    /* "ak:sk:" — a trailing colon with nothing after it is a malformed
     * (not merely ownerless) user field. */
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_parse_and_add_cred(v, "AKIAALICE0000000001:secretvalue:") == -1,
          "empty user after second colon rejected");
    sigv4_destroy(v);
}

static void t_cred_duplicate_access_key_rejected(void) {
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_parse_and_add_cred(v, "AKIAALICE0000000001:secretvalue") == 0,
          "first add succeeds");
    CHECK(main_test_parse_and_add_cred(v, "AKIAALICE0000000001:othersecret") == -1,
          "duplicate access key rejected");
    sigv4_destroy(v);
}

/* Known format limitation, documented rather than silently assumed: a
 * secret containing a literal ':' is split at the second colon, so any
 * remainder after it is misparsed as a user rather than kept as part of
 * the secret. This still returns 0 (a user field IS present, from the
 * parser's point of view) — it is a behavior to be aware of when
 * choosing secrets, not a parser bug to fix here. */
static void t_cred_secret_with_colon_reinterprets_remainder_as_user(void) {
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_parse_and_add_cred(v, "AKIAALICE0000000001:sec:ret") == 0,
          "secret containing ':' parses (remainder becomes the user field)");
    sigv4_destroy(v);
}

/* ---------------------------------------------------------------- */
/* valid_identity                                                   */
/* ---------------------------------------------------------------- */

static void t_identity_valid(void) {
    CHECK(main_test_valid_identity("alice") == 1, "plain name accepted");
    CHECK(main_test_valid_identity("AKIAALICE0000000001") == 1,
          "access-key-shaped name accepted");
}

static void t_identity_empty_rejected(void) {
    CHECK(main_test_valid_identity("") == 0, "empty identity rejected");
}

static void t_identity_with_space_rejected(void) {
    CHECK(main_test_valid_identity("alice smith") == 0,
          "identity with space rejected");
}

static void t_identity_with_colon_rejected(void) {
    CHECK(main_test_valid_identity("alice:smith") == 0,
          "identity with ':' rejected (it's the credential-line separator)");
}

static void t_identity_too_long_rejected(void) {
    char buf[300];
    memset(buf, 'a', sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    CHECK(main_test_valid_identity(buf) == 0,
          "identity longer than SIGV4_USER_MAX rejected");
}

/* ---------------------------------------------------------------- */
/* load_credentials_file                                            */
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

static void t_load_file_basic(void) {
    write_file(
        "# comment\n"
        "AKIAALICE0000000001:secretalice:alice\n"
        "AKIABOB000000000001:secretbob\n"
        "\n"
        "AKIAADMIN000000000A:secretadmin:root\n");
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_load_credentials_file(v, g_path) == 0,
          "file with 3 valid lines loads");
    sigv4_destroy(v);
    cleanup_file();
}

static void t_load_file_with_bad_line_fails_closed(void) {
    write_file(
        "AKIAALICE0000000001:secretalice:alice\n"
        "not-a-valid-line\n");
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_load_credentials_file(v, g_path) != 0,
          "file with one malformed line fails the whole load");
    sigv4_destroy(v);
    cleanup_file();
}

static void t_load_file_empty_fails(void) {
    write_file("# only comments\n\n");
    sigv4_verifier_t *v = sigv4_create();
    CHECK(main_test_load_credentials_file(v, g_path) != 0,
          "file with no credential lines fails");
    sigv4_destroy(v);
    cleanup_file();
}

int main(void) {
    t_cred_no_user_defaults_to_access_key();
    t_cred_with_explicit_user();
    t_cred_no_colon_rejected();
    t_cred_empty_secret_rejected();
    t_cred_empty_access_key_rejected();
    t_cred_empty_user_field_rejected();
    t_cred_duplicate_access_key_rejected();
    t_cred_secret_with_colon_reinterprets_remainder_as_user();
    t_identity_valid();
    t_identity_empty_rejected();
    t_identity_with_space_rejected();
    t_identity_with_colon_rejected();
    t_identity_too_long_rejected();
    t_load_file_basic();
    t_load_file_with_bad_line_fails_closed();
    t_load_file_empty_fails();

    fprintf(stderr, "===== %d passed, %d failed =====\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
