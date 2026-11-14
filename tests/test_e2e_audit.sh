#!/usr/bin/env bash
#
# tests/test_e2e_audit.sh — audit log (one JSON line per request, no
# query strings/signatures, SIGHUP reopen) and auth-failure throttling
# (per client IP via a trusted proxy's X-Forwarded-For).
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 25300 + RANDOM % 300 ))}
DATA=/tmp/fs3-aud-e2e-$$
LOG=/tmp/fs3-aud-e2e-$$.log
AUD=/tmp/fs3-aud-e2e-$$.audit
URL="http://127.0.0.1:$PORT"
AK=AKIAAUDITTEST001
SK=auditTestSecret01234567890123456789012345

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; [ $? -ne 159 ] || echo "FAIL: server died with SIGSYS (seccomp blocked a syscall; see --seccomp=log)" >&2; } || true
    rm -rf "$DATA" "$LOG" "$AUD" "$AUD".1
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

${FS3_WRAP:-} "$ROOT/fs3" -p "$PORT" -d "$DATA" --auth "$AK:$SK:alice" --audit-log "$AUD" \
    --auth-fail-limit 3 --trusted-proxy 127.0.0.1 >"$LOG" 2>&1 &
SP=$!
sleep 0.4
kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}
code() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }

export FS3_URL="$URL" FS3_AK="$AK" FS3_SK="$SK"
python3 - <<PY
import boto3
s3 = boto3.client("s3", endpoint_url="$URL", aws_access_key_id="$AK",
                  aws_secret_access_key="$SK", region_name="us-east-1")
s3.create_bucket(Bucket="audb"); s3.put_object(Bucket="audb", Key="k", Body=b"v")
PY
u=$(python3 "$ROOT/tests/presign.py" get audb k)
check_eq "presigned GET" "$(code "$u")" "200"
check_eq "audit file mode 0600" "$(stat -c %a "$AUD")" "600"
check_eq "audit lines are JSON" \
    "$(python3 -c "import json,sys; [json.loads(l) for l in open('$AUD')]; print('ok')")" "ok"
check_eq "PutObject audited with identity" \
    "$(python3 -c "
import json
for l in open('$AUD'):
    d=json.loads(l)
    if d['action']=='s3:PutObject': print(d['user'], d['access_key'], d['status'], d['path'])")" \
    "alice $AK 200 /audb/k"
check_eq "presigned request audited as presigned" \
    "$(grep -c '"presigned":true' "$AUD" || true)" "1"
check_eq "no signatures or credentials in the audit log" \
    "$(grep -c -E 'X-Amz-Signature|X-Amz-Credential|$SK' "$AUD" || true)" "0"

# Throttling: 3 bad signatures from 10.9.9.9 (via the trusted proxy).
bad="AWS4-HMAC-SHA256 Credential=$AK/20260101/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=$(printf '0%.0s' $(seq 64))"
for i in 1 2 3; do
    code -H "X-Forwarded-For: 10.9.9.9" -H "Authorization: $bad" -H "x-amz-date: 20260101T000000Z" "$URL/audb/k" >/dev/null
done
check_eq "blocked after limit → 503" \
    "$(code -H 'X-Forwarded-For: 10.9.9.9' -H "Authorization: $bad" -H 'x-amz-date: 20260101T000000Z' "$URL/audb/k")" "503"
check_eq "other client unaffected" \
    "$(FS3_AK=$AK FS3_SK=$SK python3 "$ROOT/tests/sign_request.py" --method GET --url "$URL/audb/k" --header "X-Forwarded-For:10.1.1.1" 2>&1 | head -1)" "STATUS=200"
sleep 2.2
check_eq "block expires" \
    "$(FS3_AK=$AK FS3_SK=$SK python3 "$ROOT/tests/sign_request.py" --method GET --url "$URL/audb/k" --header "X-Forwarded-For:10.9.9.9" 2>&1 | head -1)" "STATUS=200"

# SIGHUP reopens the audit log (rotation).
mv "$AUD" "$AUD.1"
kill -HUP "$SP"; sleep 1.5
code "$u" >/dev/null
check_eq "new audit file after SIGHUP" "$( [ -s "$AUD" ] && echo yes || echo no)" "yes"

echo
echo "===== audit e2e: $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
