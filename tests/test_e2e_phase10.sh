#!/usr/bin/env bash
#
# tests/test_e2e_phase10.sh — Phase 10 feature tests:
#   1. Server-side object copy (x-amz-copy-source)
#   2. ?acl stub (bucket and object level)
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 19800 + RANDOM % 200 ))}
DATA=/tmp/fs3-p10-e2e-$$
LOG=/tmp/fs3-p10-e2e-$$.log
URL="http://127.0.0.1:$PORT"

cleanup() {
    [ -n "${SP:-}" ] && kill "$SP" 2>/dev/null || true
    rm -rf "$DATA"
    rm -f /tmp/fs3-p10-$$.*
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

"$ROOT/fs3" -p "$PORT" -d "$DATA" >"$LOG" 2>&1 &
SP=$!
sleep 0.4
if ! kill -0 "$SP" 2>/dev/null; then
    echo "server did not start" >&2; cat "$LOG" >&2; exit 1
fi

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then
        PASS=$((PASS+1)); printf '.'
    else
        FAIL=$((FAIL+1))
        printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"
    fi
}

# ---------- Setup -----------------------------------------------------------
# Two source buckets and one destination bucket
curl -sS -X PUT "$URL/src" -o /dev/null
curl -sS -X PUT "$URL/dst" -o /dev/null
curl -sS -X PUT "$URL/bkt" -o /dev/null

# Upload source objects
printf 'Hello, World!' | curl -sS -X PUT "$URL/src/hello" \
    -H "Content-Type: text/plain" --data-binary @- -o /dev/null
printf '%0.s-' {1..1000} | curl -sS -X PUT "$URL/src/big" \
    -H "Content-Type: application/octet-stream" --data-binary @- -o /dev/null

# ---------- Basic copy: same-bucket ------------------------------------------
code=$(curl -sS -X PUT "$URL/src/hello-copy" \
       -H "x-amz-copy-source: /src/hello" -o /dev/null -w "%{http_code}")
check_eq "copy same-bucket → 200" "$code" "200"

# Verify body of copy matches source
body=$(curl -sS "$URL/src/hello-copy")
check_eq "copy body matches source" "$body" "Hello, World!"

# ---------- Cross-bucket copy ------------------------------------------------
code=$(curl -sS -X PUT "$URL/dst/hello" \
       -H "x-amz-copy-source: /src/hello" -o /dev/null -w "%{http_code}")
check_eq "copy cross-bucket → 200" "$code" "200"

body=$(curl -sS "$URL/dst/hello")
check_eq "cross-bucket copy body" "$body" "Hello, World!"

# ---------- Copy without leading slash in source header ----------------------
code=$(curl -sS -X PUT "$URL/dst/hello2" \
       -H "x-amz-copy-source: src/hello" -o /dev/null -w "%{http_code}")
check_eq "copy no-slash source → 200" "$code" "200"

body=$(curl -sS "$URL/dst/hello2")
check_eq "no-slash copy body" "$body" "Hello, World!"

# ---------- Copy preserves Content-Type --------------------------------------
ct=$(curl -sS "$URL/src/hello-copy" -D - -o /dev/null \
     | grep -i '^content-type:' | tr -d '\r' | awk '{print $2}')
check_eq "copy preserves content-type" "$ct" "text/plain"

# ---------- CopyObjectResult XML contains ETag and LastModified --------------
xml=$(curl -sS -X PUT "$URL/dst/xmlcheck" \
      -H "x-amz-copy-source: /src/hello")
echo "$xml" | grep -q 'ETag' && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: CopyObjectResult missing ETag\n'; }
printf '.'
echo "$xml" | grep -q 'LastModified' && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: CopyObjectResult missing LastModified\n'; }
printf '.'

# ---------- Copy large object (1000 bytes) -----------------------------------
code=$(curl -sS -X PUT "$URL/dst/big" \
       -H "x-amz-copy-source: /src/big" -o /dev/null -w "%{http_code}")
check_eq "copy large object → 200" "$code" "200"

src_body=$(curl -sS "$URL/src/big")
dst_body=$(curl -sS "$URL/dst/big")
check_eq "large copy body matches" "$dst_body" "$src_body"

# ---------- Copy: source key not found → 404 ---------------------------------
code=$(curl -sS -X PUT "$URL/dst/nope" \
       -H "x-amz-copy-source: /src/nosuchkey" -o /dev/null -w "%{http_code}")
check_eq "copy missing source key → 404" "$code" "404"

# ---------- Copy: source bucket not found → 404 ------------------------------
code=$(curl -sS -X PUT "$URL/dst/nope" \
       -H "x-amz-copy-source: /nosuchbucket/key" -o /dev/null -w "%{http_code}")
check_eq "copy missing source bucket → 404" "$code" "404"

# ---------- Copy: dest bucket not found → 404 --------------------------------
code=$(curl -sS -X PUT "$URL/nosuchbucket/key" \
       -H "x-amz-copy-source: /src/hello" -o /dev/null -w "%{http_code}")
check_eq "copy missing dest bucket → 404" "$code" "404"

# ---------- Self-copy (same bucket, same key) --------------------------------
code=$(curl -sS -X PUT "$URL/src/hello" \
       -H "x-amz-copy-source: /src/hello" -o /dev/null -w "%{http_code}")
check_eq "self-copy → 200" "$code" "200"

body=$(curl -sS "$URL/src/hello")
check_eq "self-copy body unchanged" "$body" "Hello, World!"

# ---------- Copy with URL-encoded key ----------------------------------------
printf 'encoded key content' | curl -sS -X PUT "$URL/src/key%20with%20spaces" \
    --data-binary @- -o /dev/null -w "%{http_code}" | grep -q 200 && true || true

# PUT target with URL-encoded copy source
code=$(curl -sS -X PUT "$URL/dst/spaces-copy" \
       -H "x-amz-copy-source: /src/key%20with%20spaces" \
       -o /dev/null -w "%{http_code}")
check_eq "copy URL-encoded key → 200" "$code" "200"

body=$(curl -sS "$URL/dst/spaces-copy")
check_eq "URL-encoded key copy body" "$body" "encoded key content"

# ---------- Bucket ?acl: GET -------------------------------------------------
code=$(curl -sS "$URL/bkt?acl" -o /tmp/fs3-p10-$$.bacl -w "%{http_code}")
check_eq "GET bucket ?acl → 200" "$code" "200"

body=$(cat /tmp/fs3-p10-$$.bacl)
echo "$body" | grep -q 'AccessControlPolicy' && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: bucket ACL missing AccessControlPolicy\n'; }
printf '.'
echo "$body" | grep -q 'FULL_CONTROL' && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: bucket ACL missing FULL_CONTROL\n'; }
printf '.'

# ---------- Bucket ?acl: PUT (discard body, return 200) ----------------------
code=$(curl -sS -X PUT "$URL/bkt?acl" \
       -H "Content-Type: application/xml" \
       --data-binary '<AccessControlPolicy/>' \
       -o /dev/null -w "%{http_code}")
check_eq "PUT bucket ?acl → 200" "$code" "200"

# ---------- Bucket ?acl on missing bucket → 404 ------------------------------
code=$(curl -sS "$URL/nosuchbucket?acl" -o /dev/null -w "%{http_code}")
check_eq "GET ?acl no-such-bucket → 404" "$code" "404"

# ---------- Object ?acl: GET -------------------------------------------------
code=$(curl -sS "$URL/src/hello?acl" -o /tmp/fs3-p10-$$.oacl -w "%{http_code}")
check_eq "GET object ?acl → 200" "$code" "200"

body=$(cat /tmp/fs3-p10-$$.oacl)
echo "$body" | grep -q 'AccessControlPolicy' && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: object ACL missing AccessControlPolicy\n'; }
printf '.'

# ---------- Object ?acl: PUT (discard body, return 200) ----------------------
code=$(curl -sS -X PUT "$URL/src/hello?acl" \
       -H "Content-Type: application/xml" \
       --data-binary '<AccessControlPolicy/>' \
       -o /dev/null -w "%{http_code}")
check_eq "PUT object ?acl → 200" "$code" "200"

# ---------- Object ?acl on missing key → 404 ---------------------------------
code=$(curl -sS "$URL/src/nosuchkey?acl" -o /dev/null -w "%{http_code}")
check_eq "GET object ?acl no-such-key → 404" "$code" "404"

# ---------- Final report ------------------------------------------------------
printf '\n===== phase10 e2e: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
