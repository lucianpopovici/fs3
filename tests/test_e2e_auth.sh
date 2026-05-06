#!/usr/bin/env bash
#
# tests/test_e2e_auth.sh — end-to-end SigV4 auth tests.
#
# Starts ./fs3 with --auth and --require-auth, then exercises happy and
# unhappy paths via tests/sign_request.py (which uses botocore for
# signing). Verifies that the wire-level S3 error responses are correct.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-19199}
DATA=/tmp/fs3-auth-e2e-$$
LOG=/tmp/fs3-auth-e2e-$$.log
URL="http://127.0.0.1:$PORT"

AK=AKIATESTAUTH123
SK=secretValue1234567890123456789012345678901

cleanup() {
    [ -n "${SP:-}" ] && kill "$SP" 2>/dev/null || true
    rm -rf "$DATA"
    rm -f /tmp/fs3-auth-body.$$ /tmp/fs3-auth-out.$$
}
trap cleanup EXIT

# Build if needed
BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1) || {
    echo "build failed" >&2
    (cd "$ROOT" && make $BUILD_FLAGS fs3 2>&1 | tail -10) >&2
    exit 1
}

# Start with --auth and --require-auth
"$ROOT/fs3" -p "$PORT" -d "$DATA" \
    --auth "$AK:$SK" \
    --require-auth \
    >"$LOG" 2>&1 &
SP=$!
sleep 0.4
if ! kill -0 "$SP" 2>/dev/null; then
    echo "server did not start" >&2
    cat "$LOG" >&2
    exit 1
fi

# Helper to invoke the signer with the right env
sign() {
    FS3_AK="$AK" FS3_SK="$SK" \
        python3 "$ROOT/tests/sign_request.py" "$@"
}

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then
        PASS=$((PASS+1))
        printf '.'
    else
        FAIL=$((FAIL+1))
        printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"
    fi
}

# --- t1: valid signed bucket create ---
out=$(sign --method PUT --url "$URL/authbucket" 2>&1)
status=$(echo "$out" | head -1)
check_eq "valid PUT bucket" "$status" "STATUS=200"

# --- t2: valid signed object PUT ---
out=$(sign --method PUT --url "$URL/authbucket/k1" --body "world" \
      --header "Content-Type:text/plain" 2>&1)
status=$(echo "$out" | head -1)
check_eq "valid PUT object" "$status" "STATUS=200"

# --- t3: valid signed GET ---
out=$(sign --method GET --url "$URL/authbucket/k1" 2>&1)
status=$(echo "$out" | head -1)
body=$(echo "$out" | tail -c +9)  # strip "STATUS=200\n"
check_eq "valid GET status" "$status" "STATUS=200"
# body check: just look for "world" anywhere in the output
if echo "$out" | grep -q "world"; then
    PASS=$((PASS+1))
    printf '.'
else
    FAIL=$((FAIL+1))
    printf '\nFAIL: GET body contains world\n'
fi

# --- t4: unauthenticated request rejected ---
out=$(curl -sS -m 5 -X PUT -o /tmp/fs3-auth-body.$$ -w "%{http_code}" "$URL/foo")
check_eq "no auth → 403" "$out" "403"
if grep -q "AccessDenied" /tmp/fs3-auth-body.$$; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: AccessDenied in body\n'
    cat /tmp/fs3-auth-body.$$
fi

# --- t5: tampered signature ---
# Sign normally, then mangle the last char of the signature.
FS3_AK="$AK" FS3_SK="$SK" python3 - <<EOF > /tmp/fs3-auth-out.$$ 2>&1
import os, urllib.request, urllib.error
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
creds = Credentials("$AK", "$SK")
req = AWSRequest(method="GET", url="$URL/authbucket/k1")
S3SigV4Auth(creds, "s3", "us-east-1").add_auth(req)
auth = req.headers["Authorization"]
# flip last hex digit of signature
auth = auth[:-1] + ("0" if auth[-1] != "0" else "1")
ur = urllib.request.Request(req.url, method="GET")
for k, v in req.headers.items():
    if k.lower() == "authorization":
        ur.add_header(k, auth)
    else:
        ur.add_header(k, v)
try:
    with urllib.request.urlopen(ur) as r:
        print(f"STATUS={r.status}")
        print(r.read().decode())
except urllib.error.HTTPError as e:
    print(f"STATUS={e.code}")
    print(e.read().decode())
EOF
status=$(head -1 /tmp/fs3-auth-out.$$)
check_eq "tampered sig → 403" "$status" "STATUS=403"
if grep -q "SignatureDoesNotMatch" /tmp/fs3-auth-out.$$; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: SignatureDoesNotMatch in body\n'
    cat /tmp/fs3-auth-out.$$
fi

# --- t6: unknown access key ---
FS3_AK="AKIANOTREAL" FS3_SK="$SK" \
    python3 "$ROOT/tests/sign_request.py" \
    --method GET --url "$URL/authbucket/k1" \
    > /tmp/fs3-auth-out.$$ 2>&1 || true
status=$(head -1 /tmp/fs3-auth-out.$$)
check_eq "unknown access key → 403" "$status" "STATUS=403"
if grep -q "AccessDenied" /tmp/fs3-auth-out.$$; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: AccessDenied in body for unknown key\n'
fi

# --- t7: skewed clock (>15min off) ---
FS3_AK="$AK" FS3_SK="$SK" \
    python3 "$ROOT/tests/sign_request.py" \
    --method GET --url "$URL/authbucket/k1" --skew 1800 \
    > /tmp/fs3-auth-out.$$ 2>&1 || true
status=$(head -1 /tmp/fs3-auth-out.$$)
check_eq "skewed time → 403" "$status" "STATUS=403"
if grep -q "RequestTimeTooSkewed" /tmp/fs3-auth-out.$$; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: RequestTimeTooSkewed in body\n'
    cat /tmp/fs3-auth-out.$$
fi

# --- t8: malformed Authorization header ---
out=$(curl -sS -m 5 -X GET \
    -H "Authorization: Bearer xxx" \
    -H "x-amz-date: 20240115T120000Z" \
    -o /tmp/fs3-auth-body.$$ -w "%{http_code}" \
    "$URL/authbucket/k1")
check_eq "malformed auth → 403" "$out" "403"
if grep -q "AccessDenied" /tmp/fs3-auth-body.$$; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: malformed-auth body\n'
fi

# --- t9: honest body hash (PUT with correct x-amz-content-sha256) ---
# This is implicitly already covered by t2, but we verify the object
# is actually on disk afterwards as a sanity check.
out=$(sign --method PUT --url "$URL/authbucket/honest" \
    --body "honest-body" --header "Content-Type:text/plain" 2>&1)
status=$(echo "$out" | head -1)
check_eq "honest body PUT" "$status" "STATUS=200"
out=$(sign --method GET --url "$URL/authbucket/honest" 2>&1)
if echo "$out" | grep -q "honest-body"; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: honest body GET\n'
fi

# --- t10: lying body hash (declared SHA-256 ≠ actual body bytes) ---
# Sign the request claiming the body is "first-payload" but actually
# send "second-payload". Server must reject with XAmzContentSHA256Mismatch
# and the object must NOT be in the bucket afterwards.
FS3_AK="$AK" FS3_SK="$SK" python3 - <<EOF > /tmp/fs3-auth-out.$$ 2>&1
import urllib.request, urllib.error
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

creds = Credentials("$AK", "$SK")
# Sign the request as if the body were "first-payload"
req = AWSRequest(method="PUT", url="$URL/authbucket/liar",
                 headers={"Content-Type": "text/plain"},
                 data=b"first-payload")
S3SigV4Auth(creds, "s3", "us-east-1").add_auth(req)
# Now send "second-payload" instead. The Authorization header (and
# the x-amz-content-sha256) describe "first-payload".
ur = urllib.request.Request(req.url, method="PUT", data=b"second-payload")
for k, v in req.headers.items():
    ur.add_header(k, v)
# Override Content-Length to match the actual body we'll send.
# urllib computes this from data automatically; explicit override below.
try:
    with urllib.request.urlopen(ur) as r:
        print(f"STATUS={r.status}")
        print(r.read().decode())
except urllib.error.HTTPError as e:
    print(f"STATUS={e.code}")
    print(e.read().decode())
EOF
status=$(head -1 /tmp/fs3-auth-out.$$)
check_eq "lying body → 400" "$status" "STATUS=400"
if grep -q "XAmzContentSHA256Mismatch" /tmp/fs3-auth-out.$$; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: XAmzContentSHA256Mismatch in body\n'
    cat /tmp/fs3-auth-out.$$
fi

# --- t11: lying body did NOT create the object ---
out=$(sign --method GET --url "$URL/authbucket/liar" 2>&1)
status=$(echo "$out" | head -1)
check_eq "lying body left no object" "$status" "STATUS=404"

# --- t12: UNSIGNED-PAYLOAD with mismatched body still works ---
# When the client says UNSIGNED-PAYLOAD, we must NOT body-verify.
# Sign claiming UNSIGNED-PAYLOAD, send arbitrary bytes, expect 200.
FS3_AK="$AK" FS3_SK="$SK" python3 - <<EOF > /tmp/fs3-auth-out.$$ 2>&1
import urllib.request, urllib.error
from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials

creds = Credentials("$AK", "$SK")
req = AWSRequest(method="PUT", url="$URL/authbucket/unsigned",
                 headers={
                     "Content-Type": "text/plain",
                     "x-amz-content-sha256": "UNSIGNED-PAYLOAD",
                 },
                 data=b"any-body-at-all")
S3SigV4Auth(creds, "s3", "us-east-1").add_auth(req)
ur = urllib.request.Request(req.url, method="PUT", data=b"any-body-at-all")
for k, v in req.headers.items():
    ur.add_header(k, v)
try:
    with urllib.request.urlopen(ur) as r:
        print(f"STATUS={r.status}")
except urllib.error.HTTPError as e:
    print(f"STATUS={e.code}")
    print(e.read().decode())
EOF
status=$(head -1 /tmp/fs3-auth-out.$$)
check_eq "UNSIGNED-PAYLOAD accepts any body" "$status" "STATUS=200"

# --- t13–t18: streaming chunked SigV4 ---

# happy path: small body, multiple chunks
out=$(FS3_AK="$AK" FS3_SK="$SK" python3 "$ROOT/tests/sign_chunked.py" \
        --url "$URL/authbucket/chunked-ok" \
        --body "Hello, streaming chunked SigV4 world!" \
        --chunk-size 8 2>&1)
status=$(echo "$out" | head -1)
check_eq "chunked PUT happy path" "$status" "STATUS=200"

# Verify body landed correctly
out=$(sign --method GET --url "$URL/authbucket/chunked-ok" 2>&1)
if echo "$out" | grep -q "Hello, streaming chunked SigV4 world"; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: chunked GET body mismatch\n'
    echo "$out"
fi

# mangled chunk signature
out=$(FS3_AK="$AK" FS3_SK="$SK" python3 "$ROOT/tests/sign_chunked.py" \
        --url "$URL/authbucket/chunked-bad-sig" \
        --body "tampered" --chunk-size 3 --malform chunk-sig 2>&1)
status=$(echo "$out" | head -1)
check_eq "chunked bad chunk-sig → 403" "$status" "STATUS=403"
if echo "$out" | grep -q "SignatureDoesNotMatch"; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: chunked bad sig body\n'
fi

# data doesn't match declared chunk hash
out=$(FS3_AK="$AK" FS3_SK="$SK" python3 "$ROOT/tests/sign_chunked.py" \
        --url "$URL/authbucket/chunked-bad-data" \
        --body "honest data here" --chunk-size 4 --malform data-mismatch 2>&1)
status=$(echo "$out" | head -1)
check_eq "chunked data-mismatch → 403" "$status" "STATUS=403"

# Body never arrived → object must not exist
out=$(sign --method GET --url "$URL/authbucket/chunked-bad-data" 2>&1)
status=$(echo "$out" | head -1)
check_eq "chunked bad data left no object" "$status" "STATUS=404"

# missing terminator chunk
out=$(FS3_AK="$AK" FS3_SK="$SK" python3 "$ROOT/tests/sign_chunked.py" \
        --url "$URL/authbucket/chunked-no-term" \
        --body "incomplete" --chunk-size 4 --malform no-terminator 2>&1)
status=$(echo "$out" | head -1)
check_eq "chunked no terminator → 403" "$status" "STATUS=403"

# wrong x-amz-decoded-content-length
out=$(FS3_AK="$AK" FS3_SK="$SK" python3 "$ROOT/tests/sign_chunked.py" \
        --url "$URL/authbucket/chunked-bad-len" \
        --body "lying length" --chunk-size 4 --malform wrong-decoded-len 2>&1)
status=$(echo "$out" | head -1)
check_eq "chunked wrong decoded-len → 403" "$status" "STATUS=403"

# --- trailer-form chunked SigV4 ---

# happy path: trailer-form PUT with x-amz-checksum-sha256 trailer
out=$(FS3_AK="$AK" FS3_SK="$SK" python3 "$ROOT/tests/sign_chunked.py" \
        --url "$URL/authbucket/trailer-ok" \
        --body "Hello, trailer-form streaming SigV4!" \
        --chunk-size 8 --trailer 2>&1)
status=$(echo "$out" | head -1)
check_eq "trailer-form PUT happy path" "$status" "STATUS=200"

# Verify body landed correctly via signed GET
out=$(sign --method GET --url "$URL/authbucket/trailer-ok" 2>&1)
if echo "$out" | grep -q "Hello, trailer-form streaming SigV4"; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: trailer-form GET body mismatch\n'
    echo "$out"
fi

# tampered x-amz-trailer-signature
out=$(FS3_AK="$AK" FS3_SK="$SK" python3 "$ROOT/tests/sign_chunked.py" \
        --url "$URL/authbucket/trailer-bad-sig" \
        --body "tampered" --chunk-size 4 --trailer --malform trailer-sig 2>&1)
status=$(echo "$out" | head -1)
check_eq "trailer-form bad trailer-sig → 403" "$status" "STATUS=403"
if echo "$out" | grep -q "SignatureDoesNotMatch"; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: trailer-form bad sig body\n'
fi

# Object must not exist after a failed trailer signature
out=$(sign --method GET --url "$URL/authbucket/trailer-bad-sig" 2>&1)
status=$(echo "$out" | head -1)
check_eq "trailer-form bad sig left no object" "$status" "STATUS=404"

# missing x-amz-trailer-signature line
out=$(FS3_AK="$AK" FS3_SK="$SK" python3 "$ROOT/tests/sign_chunked.py" \
        --url "$URL/authbucket/trailer-no-sig" \
        --body "no sig here" --chunk-size 4 --trailer --malform no-trailer-sig 2>&1)
status=$(echo "$out" | head -1)
check_eq "trailer-form missing trailer-sig → 403" "$status" "STATUS=403"

# tampered trailer header value (sig was computed over original)
out=$(FS3_AK="$AK" FS3_SK="$SK" python3 "$ROOT/tests/sign_chunked.py" \
        --url "$URL/authbucket/trailer-bad-line" \
        --body "tampered line" --chunk-size 4 --trailer --malform trailer-line 2>&1)
status=$(echo "$out" | head -1)
check_eq "trailer-form tampered trailer value → 403" "$status" "STATUS=403"

echo
echo "===== auth e2e: $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
