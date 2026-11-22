#!/usr/bin/env bash
#
# tests/test_e2e_logs.sh — --log-file / --log-max-size / --log-keep against
# a running server: the server log and the audit log rotate by size, keep
# the configured number of files, never tear a line under concurrent
# requests, and re-open on SIGHUP. Also the option validation.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 28400 + RANDOM % 300 ))}
T=/tmp/fs3-logs-e2e-$$
DATA=$T/data
LOGD=$T/logs
URL="http://127.0.0.1:$PORT"

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; [ $? -ne 159 ] || echo "FAIL: server died with SIGSYS (seccomp blocked a syscall; see --seccomp=log)" >&2; } || true
    [ -n "${KEEP:-}" ] || rm -rf "$T"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)
mkdir -p "$LOGD"

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}
yesno() { if "$@"; then echo yes; else echo no; fi; }

# Option validation.
"$ROOT/fs3" --log-keep 0 >/dev/null 2>&1 && rc=0 || rc=$?
check_eq "--log-keep 0 refused" "$rc" "2"
"$ROOT/fs3" --log-max-size 100 >/dev/null 2>&1 && rc=0 || rc=$?
check_eq "--log-max-size below 4K refused" "$rc" "2"
"$ROOT/fs3" -p "$PORT" -d "$DATA" --log-file /nonexistent-dir/fs3.log >/dev/null 2>"$T.err" && rc=0 || rc=$?
check_eq "unopenable --log-file refused" "$rc" "2"
check_eq "error names the file" "$(grep -c 'cannot open' "$T.err" || true)" "1"

${FS3_WRAP:-} "$ROOT/fs3" -p "$PORT" -d "$DATA" -v \
    --log-file "$LOGD/fs3.log" --audit-log "$LOGD/audit.jsonl" \
    --log-max-size 4K --log-keep 3 >"$T.stderr" 2>&1 &
SP=$!
for _ in $(seq 50); do curl -s -o /dev/null "$URL/_health" && break; sleep 0.1; done
kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$T.stderr" >&2; exit 1; }

check_eq "server log goes to the file, not stderr" "$(grep -c '\[INF\]' "$T.stderr" || true)" "0"
check_eq "log file mode 0640"   "$(stat -c %a "$LOGD/fs3.log")" "640"
check_eq "audit log mode 0600"  "$(stat -c %a "$LOGD/audit.jsonl")" "600"

curl -sS -o /dev/null -X PUT "$URL/logbkt"
head -c 2000 /dev/urandom > "$T.obj"
# Concurrent traffic: 8 clients x 60 requests (PUT + GET + a 404).
seq 1 8 | xargs -P 8 -I{} sh -c '
    for i in $(seq 1 20); do
        curl -s -o /dev/null -X PUT --data-binary @'"$T.obj"' '"$URL"'/logbkt/k{}-$i
        curl -s -o /dev/null '"$URL"'/logbkt/k{}-$i
        curl -s -o /dev/null '"$URL"'/logbkt/missing-{}-$i
    done'

for f in fs3.log audit.jsonl; do
    check_eq "$f rotated: .1 exists"   "$(yesno test -f "$LOGD/$f.1")" "yes"
    check_eq "$f rotated: .3 exists"   "$(yesno test -f "$LOGD/$f.3")" "yes"
    check_eq "$f keeps 3: no .4"       "$(yesno test -f "$LOGD/$f.4")" "no"
    big=0
    for g in "$LOGD/$f" "$LOGD/$f".[123]; do
        [ "$(stat -c %s "$g")" -le 4096 ] || big=1
    done
    check_eq "$f: every file within --log-max-size" "$big" "0"
done
check_eq "rotated audit log keeps mode 0600" "$(stat -c %a "$LOGD/audit.jsonl.1")" "600"

# No torn or interleaved lines: every server-log line starts with a
# timestamp, every audit line is one JSON object.
bad=$(cat "$LOGD"/fs3.log "$LOGD"/fs3.log.[123] | grep -cvE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+ \[(DBG|INF|WRN|ERR)\] ' || true)
check_eq "server log: no torn lines" "$bad" "0"
bad=$(cat "$LOGD"/audit.jsonl "$LOGD"/audit.jsonl.[123] | python3 -c '
import json, sys
bad = 0
for line in sys.stdin:
    try:
        json.loads(line)
    except Exception:
        bad += 1
print(bad)')
check_eq "audit log: every line is JSON" "$bad" "0"
check_eq "newest requests are in the current audit file" \
    "$(tail -n 1 "$LOGD/audit.jsonl" | grep -c '"ts"' || true)" "1"

# External rotation + SIGHUP: both files are re-opened at the same path.
mv "$LOGD/fs3.log" "$T.moved.log"
mv "$LOGD/audit.jsonl" "$T.moved.audit"
kill -HUP "$SP"
# SIGHUP is acted on at the server's next 1 s tick.
for _ in $(seq 1 30); do
    curl -s -o /dev/null "$URL/logbkt/k1-1"
    [ -s "$LOGD/fs3.log" ] && [ -s "$LOGD/audit.jsonl" ] && break
    sleep 0.1
done
check_eq "SIGHUP re-creates the log file"   "$(yesno test -s "$LOGD/fs3.log")" "yes"
check_eq "SIGHUP re-creates the audit log"  "$(yesno test -s "$LOGD/audit.jsonl")" "yes"
check_eq "server still serving" "$(curl -s -o /dev/null -w '%{http_code}' "$URL/_health")" "200"

# --log-max-size 0: never rotate.
kill "$SP"; wait "$SP" 2>/dev/null || true; SP=
rm -rf "$LOGD"; mkdir -p "$LOGD"
${FS3_WRAP:-} "$ROOT/fs3" -p "$PORT" -d "$DATA" -v --log-file "$LOGD/fs3.log" \
    --log-max-size 0 >"$T.stderr" 2>&1 &
SP=$!
for _ in $(seq 50); do curl -s -o /dev/null "$URL/_health" && break; sleep 0.1; done
for i in $(seq 1 60); do curl -s -o /dev/null "$URL/logbkt/k1-1"; done
check_eq "max-size 0: no rotation" "$(yesno test -f "$LOGD/fs3.log.1")" "no"
check_eq "max-size 0: still logging" "$([ "$(stat -c %s "$LOGD/fs3.log")" -gt 4096 ] && echo yes || echo no)" "yes"

echo
echo "===== logs e2e: $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
