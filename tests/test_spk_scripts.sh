#!/usr/bin/env bash
#
# tests/test_spk_scripts.sh — the Synology package's start-stop-status:
# fs3.conf → command line (via lib/fs3-conf.sh), validation of hand-edited
# values, authentication wiring, and the watchdog (restart to apply new
# settings without backoff, respawn after an unexpected exit, stop).
# fs3 is replaced by a stub that records its arguments.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
T=/tmp/fs3-spk-$$
PKG=$T/pkg
VAR=$T/var
SSS="$ROOT/packaging/synology/scripts/start-stop-status"

cleanup() {
    SYNOPKG_PKGDEST="$PKG" SYNOPKG_PKGVAR="$VAR" sh "$SSS" stop >/dev/null 2>&1 || true
    rm -rf "$T"
}
trap cleanup EXIT

mkdir -p "$PKG/bin" "$PKG/lib" "$VAR"
cp "$ROOT/packaging/synology/lib/fs3-conf.sh" "$PKG/lib/"
cat > "$PKG/bin/fs3" <<'STUB'
#!/bin/sh
# Stub fs3: record the arguments (one per line), then idle until TERM.
out="$(dirname "$0")/../args"
printf '%s\n' "$@" > "$out.tmp.$$" && mv "$out.tmp.$$" "$out"
trap 'exit 0' TERM
while :; do sleep 0.1; done
STUB
chmod +x "$PKG/bin/fs3"
ARGS="$PKG/args"
CONF="$VAR/fs3.conf"

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}
has_arg() {  # $1=desc $2... = consecutive lines expected in the args file
    local desc="$1"; shift
    local want; want=$(printf '%s\n' "$@")
    if awk -v w="$want" 'BEGIN { n = split(w, a, "\n") }
         { l[NR] = $0 } END { for (i = 1; i <= NR - n + 1; i++) { ok = 1
             for (j = 1; j <= n; j++) if (l[i + j - 1] != a[j]) { ok = 0; break }
             if (ok) exit 0 } exit 1 }' "$ARGS"; then
        PASS=$((PASS+1)); printf '.'
    else
        FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  missing: %s\n  args: %s\n' "$desc" "$*" "$(tr '\n' ' ' < "$ARGS")"
    fi
}
lacks_arg() {
    if grep -qxF -- "$2" "$ARGS"; then
        FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  unexpected: %s\n' "$1" "$2"
    else PASS=$((PASS+1)); printf '.'; fi
}
sss() { SYNOPKG_PKGDEST="$PKG" SYNOPKG_PKGVAR="$VAR" SYNOPKG_TEMP_LOGFILE="$T/dsm-msg" sh "$SSS" "$@"; }
wait_args() {  # wait until the stub (re)wrote its args after $1
    for _ in $(seq 1 50); do
        [ -f "$ARGS" ] && [ "$ARGS" -nt "$1" ] && return 0
        sleep 0.1
    done
    return 1
}
mark() { touch "$T/mark"; sleep 1.1; }   # mtime granularity

# 1. Defaults: no conf at all.
mark
sss start
wait_args "$T/mark" || echo "stub never started" >&2
has_arg "default bind"           -a 127.0.0.1
has_arg "default port"           -p 9000
has_arg "default data folder"    -d "$VAR/data"
has_arg "trusted proxy on by default" --trusted-proxy 127.0.0.1
has_arg "admin listener"         --metrics-port 9101
has_arg "fs3 writes its own rotated log" --log-file "$VAR/fs3.log"
lacks_arg "default rotation not passed" --log-max-size
lacks_arg "no dedup by default"  --dedup
has_arg "admin socket on by default" --admin-socket "$VAR/admin.sock"
lacks_arg "default replication threads not passed" --repl-workers
lacks_arg "no CA bundle without repl-ca.pem" --repl-ca-file
lacks_arg "no SSE key file by default" --sse-key-file
check_eq "no SSE key file created by default" "$([ -e "$VAR/sse.keys" ] && echo yes || echo no)" "no"
lacks_arg "no auth without credentials" --require-auth
sss status && st=0 || st=$?
check_eq "status running" "$st" "0"

# 2. New settings are applied by a restart request, without backoff.
cat > "$CONF" <<EOF
FS3_DATA=$VAR/my data
FS3_DEDUP=owner
FS3_AUDIT_LOG=1
FS3_WEB_PORT=9080
FS3_WEB_ROOT_DOMAIN=web.lan
FS3_TRUSTED_PROXY=127.0.0.1,10.0.0.2
FS3_MAX_BODY_SIZE=1G
FS3_ALLOW_PUBLIC=1
FS3_SECCOMP=log
FS3_LOG_MAX_SIZE=2M
FS3_LOG_KEEP=7
FS3_REPL_WORKERS=4
FS3_REPL_RATE=5M
FS3_REPL_TIMEOUT=60
FS3_ADMIN_SOCKET=0
FS3_SSE_S3=1
EOF
mkdir -p "$VAR/my data"
: > "$VAR/repl-ca.pem"
mark
: > "$VAR/fs3.restart"
kill "$(cat "$VAR/fs3.child.pid")"
wait_args "$T/mark" || echo "no respawn after restart request" >&2
has_arg "path with a space is one argument" -d "$VAR/my data"
has_arg "dedup passed"           --dedup owner
has_arg "audit log in package folder" --audit-log "$VAR/audit.jsonl"
has_arg "website port and address" --web-port 9080 --web-addr 127.0.0.1
has_arg "website root domain"    --web-root-domain web.lan
has_arg "second trusted proxy"   --trusted-proxy 10.0.0.2
has_arg "body size"              --max-body-size 1G
has_arg "public allowed"         --allow-public
has_arg "seccomp mode"           --seccomp log
has_arg "log rotation size"      --log-max-size 2M
has_arg "log rotation count"     --log-keep 7
has_arg "replication threads"    --repl-workers 4
has_arg "replication rate"       --repl-rate 5M
has_arg "replication timeout"    --repl-timeout 60
has_arg "fixed CA bundle file"   --repl-ca-file "$VAR/repl-ca.pem"
lacks_arg "admin socket can be turned off" --admin-socket
has_arg "SSE key file passed"    --sse-key-file "$VAR/sse.keys"
check_eq "SSE key file mode 600" "$(stat -c %a "$VAR/sse.keys")" "600"
check_eq "SSE key file holds one valid key" \
    "$(grep -cE '^k1 [0-9a-f]{64}$' "$VAR/sse.keys")" "1"
check_eq "SSE key creation logged" "$(grep -c 'created a new SSE-S3 key file' "$VAR/fs3.start.log" || true)" "1"
SSE_BEFORE=$(cat "$VAR/sse.keys")
check_eq "restart request consumed" "$([ -f "$VAR/fs3.restart" ] && echo yes || echo no)" "no"
check_eq "restart logged, no backoff" "$(grep -c 'restarting to apply new settings' "$VAR/fs3.start.log" || true)" "1"

# 3. Hand-edited invalid values fall back to the default and are logged;
#    nothing in the conf is executed.
cat > "$CONF" <<EOF
FS3_PORT=abc
FS3_ADMIN=\$(touch $T/pwned)
FS3_DEDUP=everything
FS3_REQUIRE_AUTH=0
FS3_EXTRA=--allow-public-write
EOF
mark
: > "$VAR/fs3.restart"
kill "$(cat "$VAR/fs3.child.pid")"
wait_args "$T/mark" || echo "no respawn" >&2
has_arg "invalid port → default" -p 9000
lacks_arg "invalid enum → default" --dedup
lacks_arg "unknown key ignored"  --allow-public-write
check_eq "invalid value logged" "$(grep -c 'ignoring invalid value for FS3_PORT' "$VAR/fs3.start.log" || true)" "1"
check_eq "conf never executed" "$([ -e "$T/pwned" ] && echo yes || echo no)" "no"
# SSE-S3 off again (FS3_SSE_S3 not set): the existing key file is still
# passed, unchanged, so sealed objects stay readable.
has_arg "SSE key file kept after the setting is turned off" --sse-key-file "$VAR/sse.keys"
check_eq "SSE key file not regenerated" "$(cat "$VAR/sse.keys")" "$SSE_BEFORE"

# 4. An unexpected exit is respawned (after the 1 s backoff) and logged;
#    an oversized fs3.start.log is trimmed at the respawn.
head -c 600000 /dev/zero | tr '\0' 'x' >> "$VAR/fs3.start.log"
mark
kill "$(cat "$VAR/fs3.child.pid")"
wait_args "$T/mark" || echo "no respawn after crash" >&2
check_eq "unexpected exit logged" "$(grep -c 'exited unexpectedly' "$VAR/fs3.start.log" || true)" "1"
check_eq "start log trimmed" "$([ "$(wc -c < "$VAR/fs3.start.log")" -le 262144 ] && echo yes || echo no)" "yes"
check_eq "nothing but the stub writes fs3.log" "$([ -e "$VAR/fs3.log" ] && echo yes || echo no)" "no"

# 5. Authentication.
sss stop
sss status && st=0 || st=$?
check_eq "status stopped after stop" "$st" "3"
printf 'FS3_REQUIRE_AUTH=1\n' > "$CONF"
sss start && rc=0 || rc=$?
check_eq "auth without credentials refuses to start" "$rc" "1"
check_eq "DSM sees why" "$(grep -c 'credentials' "$T/dsm-msg" 2>/dev/null || true)" "1"
printf 'AKIAEXAMPLE:secretsecret:alice\n' > "$VAR/credentials"
printf 'FS3_REQUIRE_AUTH=1\nFS3_ADMIN=bob\n' > "$CONF"
mark
sss start
wait_args "$T/mark" || echo "stub never started" >&2
has_arg "credentials file"       --credentials-file "$VAR/credentials" --require-auth
has_arg "legacy owner = first user" --legacy-owner alice
has_arg "admin user"             --admin bob
check_eq "credentials file is 0600" "$(stat -c %a "$VAR/credentials")" "600"
sss stop
check_eq "child gone after stop" "$([ -f "$VAR/fs3.child.pid" ] && echo yes || echo no)" "no"

printf '\n===== spk scripts: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
