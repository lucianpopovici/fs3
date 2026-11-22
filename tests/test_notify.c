/* tests/test_notify.c — webhook rule parser and URL splitter: valid and
 * invalid rules, secret retention, endpoint policy (plain http only to
 * private hosts, verify_tls off only for private hosts, https needs TLS),
 * then a fuzz loop over both. Usage: test_notify [iterations]. */
#include "notify.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* notify.o audits drops; the audit module drags in the whole server. */
void audit_event(const char *who, const char *what);
void audit_event(const char *who, const char *what) { (void)who; (void)what; }

static int pass, fail;
#define CHECK(name, cond) do { if (cond) pass++; else { fail++; printf("FAIL: %s (line %d)\n", name, __LINE__); } } while (0)
static unsigned long long rng = 88172645463325252ull;
static unsigned rnd(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return (unsigned)rng; }

static notify_rule_t R;
static char E[300];
static int P(const char *j, int tls) { return notify_rule_parse(j, strlen(j), NULL, tls, &R, E, sizeof(E)); }

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 1000;
    char base[300], target[1024];

    CHECK("split", notify_split_url("https://h.example:8443/a/b?x=1", base, sizeof(base), target, sizeof(target)) == 0
          && !strcmp(base, "https://h.example:8443") && !strcmp(target, "/a/b?x=1"));
    CHECK("split no path", notify_split_url("http://h", base, sizeof(base), target, sizeof(target)) == 0
          && !strcmp(base, "http://h") && !strcmp(target, "/"));
    CHECK("split bad scheme", notify_split_url("ftp://h/x", base, sizeof(base), target, sizeof(target)) < 0);
    CHECK("split space", notify_split_url("http://h/a b", base, sizeof(base), target, sizeof(target)) < 0);
    CHECK("split fragment", notify_split_url("http://h/a#b", base, sizeof(base), target, sizeof(target)) < 0);
    CHECK("split ctrl", notify_split_url("http://h/a\x01", base, sizeof(base), target, sizeof(target)) < 0);

    CHECK("minimal https", P("{\"endpoint\":\"https://hooks.example.com/x\"}", 1) == 0);
    CHECK("defaults: created+removed", R.events == (NOTIFY_EV_CREATED_PUT | NOTIFY_EV_CREATED_COPY | NOTIFY_EV_CREATED_MPU
                                                    | NOTIFY_EV_REMOVED_DELETE | NOTIFY_EV_REMOVED_MARKER));
    CHECK("defaults: verify, 24h", R.verify_tls == 1 && R.max_age_hours == 24 && !R.allow_plain_http);
    CHECK("https without TLS build", P("{\"endpoint\":\"https://hooks.example.com/x\"}", 0) < 0);
    CHECK("plain http public", P("{\"endpoint\":\"http://8.8.8.8/x\",\"allow_plain_http\":true}", 1) < 0);
    CHECK("plain http private needs flag", P("{\"endpoint\":\"http://10.1.2.3/x\"}", 1) < 0);
    CHECK("plain http 10/8", P("{\"endpoint\":\"http://10.1.2.3/x\",\"allow_plain_http\":true}", 0) == 0);
    CHECK("plain http 172.16/12", P("{\"endpoint\":\"http://172.20.0.1/x\",\"allow_plain_http\":true}", 0) == 0);
    CHECK("plain http 172.32 public", P("{\"endpoint\":\"http://172.32.0.1/x\",\"allow_plain_http\":true}", 0) < 0);
    CHECK("plain http 192.168", P("{\"endpoint\":\"http://192.168.1.5:9000/x\",\"allow_plain_http\":true}", 0) == 0);
    CHECK("plain http localhost", P("{\"endpoint\":\"http://localhost:1/\",\"allow_plain_http\":true}", 0) == 0);
    CHECK("plain http [::1]", P("{\"endpoint\":\"http://[::1]:8080/h\",\"allow_plain_http\":true}", 0) == 0);
    CHECK("plain http DNS name", P("{\"endpoint\":\"http://hooks.lan/x\",\"allow_plain_http\":true}", 0) < 0);
    CHECK("verify off public", P("{\"endpoint\":\"https://hooks.example.com/x\",\"verify_tls\":false}", 1) < 0);
    CHECK("verify off private", P("{\"endpoint\":\"https://192.168.1.2/x\",\"verify_tls\":false}", 1) == 0);
    CHECK("events list", P("{\"endpoint\":\"https://h.example/x\",\"events\":[\"s3:ObjectCreated:Put\",\"s3:LifecycleExpiration:*\"]}", 1) == 0
          && R.events == (NOTIFY_EV_CREATED_PUT | NOTIFY_EV_LIFECYCLE_DELETE | NOTIFY_EV_LIFECYCLE_MARKER));
    CHECK("unknown event", P("{\"endpoint\":\"https://h.example/x\",\"events\":[\"s3:Nope\"]}", 1) < 0);
    CHECK("empty events", P("{\"endpoint\":\"https://h.example/x\",\"events\":[]}", 1) < 0);
    CHECK("events not array", P("{\"endpoint\":\"https://h.example/x\",\"events\":\"s3:ObjectCreated:*\"}", 1) < 0);
    CHECK("event not string", P("{\"endpoint\":\"https://h.example/x\",\"events\":[1]}", 1) < 0);
    CHECK("unknown field", P("{\"endpoint\":\"https://h.example/x\",\"zzz\":1}", 1) < 0 && strstr(E, "zzz"));
    CHECK("secret_set ignored", P("{\"endpoint\":\"https://h.example/x\",\"secret_set\":true}", 1) == 0);
    CHECK("no endpoint", P("{}", 1) < 0);
    CHECK("not object", P("[1]", 1) < 0);
    CHECK("garbage", P("{", 1) < 0);
    CHECK("bool type", P("{\"endpoint\":\"https://h.example/x\",\"verify_tls\":1}", 1) < 0);
    CHECK("max_age range", P("{\"endpoint\":\"https://h.example/x\",\"max_age_hours\":721}", 1) < 0);
    CHECK("max_age float", P("{\"endpoint\":\"https://h.example/x\",\"max_age_hours\":1.5}", 1) < 0);
    CHECK("max_age ok", P("{\"endpoint\":\"https://h.example/x\",\"max_age_hours\":720}", 1) == 0 && R.max_age_hours == 720);
    CHECK("prefix/suffix", P("{\"endpoint\":\"https://h.example/x\",\"prefix\":\"a/\",\"suffix\":\".jpg\"}", 1) == 0
          && !strcmp(R.prefix, "a/") && !strcmp(R.suffix, ".jpg"));
    CHECK("prefix control char", P("{\"endpoint\":\"https://h.example/x\",\"prefix\":\"a\\n\"}", 1) < 0);
    CHECK("secret control char", P("{\"endpoint\":\"https://h.example/x\",\"secret\":\"a\\u0001\"}", 1) < 0);
    CHECK("NUL in string", P("{\"endpoint\":\"https://h.example/x\",\"prefix\":\"a\\u0000b\"}", 1) < 0);
    CHECK("userinfo refused", P("{\"endpoint\":\"https://u:p@h.example/x\"}", 1) < 0);
    {
        notify_rule_t old;
        const char *a = "{\"endpoint\":\"https://h.example/x\",\"secret\":\"s3cr3t\"}";
        CHECK("with secret", notify_rule_parse(a, strlen(a), NULL, 1, &old, E, sizeof(E)) == 0 && !strcmp(old.secret, "s3cr3t"));
        const char *b = "{\"endpoint\":\"https://h.example/y\"}";
        CHECK("secret kept", notify_rule_parse(b, strlen(b), &old, 1, &R, E, sizeof(E)) == 0 && !strcmp(R.secret, "s3cr3t"));
        const char *c = "{\"endpoint\":\"https://h.example/y\",\"secret\":\"new\"}";
        CHECK("secret replaced", notify_rule_parse(c, strlen(c), &old, 1, &R, E, sizeof(E)) == 0 && !strcmp(R.secret, "new"));
    }

    /* Fuzz: mutate valid rules and random bytes; must not crash and must
     * NUL-terminate everything on success. */
    static const char *seeds[] = {
        "{\"endpoint\":\"https://h.example:443/a?b=c\",\"events\":[\"s3:ObjectCreated:*\"],\"prefix\":\"p\",\"suffix\":\"s\",\"secret\":\"x\",\"verify_tls\":true,\"max_age_hours\":5}",
        "{\"endpoint\":\"http://127.0.0.1:1/\",\"allow_plain_http\":true,\"events\":[\"s3:ObjectRemoved:DeleteMarkerCreated\"]}",
    };
    char buf[1024];
    for (long i = 0; i < iters; i++) {
        const char *s = seeds[rnd() % 2];
        size_t n = strlen(s);
        memcpy(buf, s, n);
        int muts = 1 + (int)(rnd() % 6);
        for (int m = 0; m < muts; m++) {
            size_t at = rnd() % n;
            switch (rnd() % 4) {
            case 0: buf[at] = (char)rnd(); break;
            case 1: if (n > 1) { memmove(buf + at, buf + at + 1, n - at - 1); n--; } break;
            case 2: if (n < sizeof(buf) - 1) { memmove(buf + at + 1, buf + at, n - at); buf[at] = "{}[]\":,\\0a"[rnd() % 10]; n++; } break;
            case 3: n = at + 1; break;
            }
        }
        if (P(buf, rnd() & 1) == 0)
            CHECK("fuzz: terminated", memchr(R.url, 0, sizeof(R.url)) && memchr(R.prefix, 0, sizeof(R.prefix))
                  && memchr(R.secret, 0, sizeof(R.secret)) && R.events);
        buf[n < sizeof(buf) ? n : sizeof(buf) - 1] = 0;
        notify_split_url(buf, base, sizeof(base), target, sizeof(target));
    }
    printf("test_notify: %d passed, %d failed\n", pass, fail);
    return fail != 0;
}
