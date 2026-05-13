#!/usr/bin/env bash
#
# tests/test_e2e_mpu.sh — multipart-upload e2e tests, no auth.
#
# Exercises the full lifecycle: initiate, upload parts, complete, abort.
# Plus failure paths: bad upload ID, missing parts, bad XML.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-19299}
DATA=/tmp/fs3-mpu-e2e-$$
LOG=/tmp/fs3-mpu-e2e-$$.log
URL="http://127.0.0.1:$PORT"

cleanup() {
    [ -n "${SP:-}" ] && kill "$SP" 2>/dev/null || true
    rm -rf "$DATA"
    rm -f /tmp/fs3-mpu-*.$$
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

"$ROOT/fs3" -p "$PORT" -d "$DATA" >"$LOG" 2>&1 &
SP=$!
sleep 0.4
if ! kill -0 "$SP" 2>/dev/null; then
    echo "server did not start" >&2
    cat "$LOG" >&2
    exit 1
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

# --- create bucket ---
out=$(curl -sS -X PUT "$URL/mpb" -o /dev/null -w "%{http_code}")
check_eq "bucket create" "$out" "200"

# --- t1: full lifecycle (initiate, parts, complete) ---
RESP=$(curl -sS -X POST "$URL/mpb/full.bin?uploads")
UPID=$(echo "$RESP" | grep -oP '<UploadId>\K[^<]+')
[ -n "$UPID" ] && PASS=$((PASS+1)) || FAIL=$((FAIL+1))
printf '.'

# Two 5-byte parts so we can do byte-exact verification
echo -n "first" > /tmp/fs3-mpu-p1.$$
echo -n "secnd" > /tmp/fs3-mpu-p2.$$

E1=$(curl -sS -X PUT "$URL/mpb/full.bin?partNumber=1&uploadId=$UPID" \
    --data-binary @/tmp/fs3-mpu-p1.$$ -D - -o /dev/null \
    | grep -i '^etag:' | tr -d '\r"' | awk '{print $2}')
E2=$(curl -sS -X PUT "$URL/mpb/full.bin?partNumber=2&uploadId=$UPID" \
    --data-binary @/tmp/fs3-mpu-p2.$$ -D - -o /dev/null \
    | grep -i '^etag:' | tr -d '\r"' | awk '{print $2}')

# md5("first") = 8b04d5e3775d298e78455efc5ca404d5
check_eq "part1 etag = md5(first)" "$E1" "8b04d5e3775d298e78455efc5ca404d5"
# md5("secnd") = 17ca7b8d3d4a4b3c8e2c7a8e9d3f4a3b — let me compute
E2_WANT=$(python3 -c 'import hashlib; print(hashlib.md5(b"secnd").hexdigest())')
check_eq "part2 etag matches md5" "$E2" "$E2_WANT"

# Complete
COMPLETE_BODY="<CompleteMultipartUpload>
  <Part><PartNumber>1</PartNumber><ETag>\"$E1\"</ETag></Part>
  <Part><PartNumber>2</PartNumber><ETag>\"$E2\"</ETag></Part>
</CompleteMultipartUpload>"
RESP=$(curl -sS -X POST "$URL/mpb/full.bin?uploadId=$UPID" \
    -H "Content-Type: application/xml" \
    --data-binary "$COMPLETE_BODY")
if echo "$RESP" | grep -q "CompleteMultipartUploadResult"; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: complete body\n%s\n' "$RESP"
fi

# Verify final object
out=$(curl -sS "$URL/mpb/full.bin")
check_eq "GET multipart object" "$out" "firstsecnd"

# Verify ETag has multipart-style suffix
ETAG=$(curl -sS -I "$URL/mpb/full.bin" | grep -i '^etag:' | tr -d '\r"' | awk '{print $2}')
if echo "$ETAG" | grep -qE -- '-2$'; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: multipart ETag (got %s)\n' "$ETAG"
fi

# --- t2: abort ---
RESP=$(curl -sS -X POST "$URL/mpb/abrt.bin?uploads")
UPID=$(echo "$RESP" | grep -oP '<UploadId>\K[^<]+')

# Upload one part
echo -n "wasted" > /tmp/fs3-mpu-w.$$
curl -sS -X PUT "$URL/mpb/abrt.bin?partNumber=1&uploadId=$UPID" \
    --data-binary @/tmp/fs3-mpu-w.$$ -o /dev/null

# Abort
out=$(curl -sS -X DELETE "$URL/mpb/abrt.bin?uploadId=$UPID" -o /dev/null -w "%{http_code}")
check_eq "abort returns 204" "$out" "204"

# Object should not exist
out=$(curl -sS "$URL/mpb/abrt.bin" -o /dev/null -w "%{http_code}")
check_eq "aborted upload left no object" "$out" "404"

# Second abort — NoSuchUpload
out=$(curl -sS -X DELETE "$URL/mpb/abrt.bin?uploadId=$UPID" -w "%{http_code}" -o /tmp/fs3-mpu-err.$$)
check_eq "double-abort = 404" "$out" "404"
if grep -q "NoSuchUpload" /tmp/fs3-mpu-err.$$; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: NoSuchUpload code\n'
fi

# --- t3: complete with missing part ---
RESP=$(curl -sS -X POST "$URL/mpb/missing.bin?uploads")
UPID=$(echo "$RESP" | grep -oP '<UploadId>\K[^<]+')
echo -n "x" > /tmp/fs3-mpu-x.$$
E=$(curl -sS -X PUT "$URL/mpb/missing.bin?partNumber=1&uploadId=$UPID" \
    --data-binary @/tmp/fs3-mpu-x.$$ -D - -o /dev/null \
    | grep -i '^etag:' | tr -d '\r"' | awk '{print $2}')
# Try complete claiming part 1 AND a non-existent part 2
BAD_BODY="<CompleteMultipartUpload>
  <Part><PartNumber>1</PartNumber><ETag>\"$E\"</ETag></Part>
  <Part><PartNumber>2</PartNumber><ETag>\"00000000000000000000000000000000\"</ETag></Part>
</CompleteMultipartUpload>"
out=$(curl -sS -X POST "$URL/mpb/missing.bin?uploadId=$UPID" \
    -H "Content-Type: application/xml" \
    --data-binary "$BAD_BODY" -w "%{http_code}" -o /tmp/fs3-mpu-err.$$)
check_eq "missing part = 400" "$out" "400"
if grep -q "InvalidPart" /tmp/fs3-mpu-err.$$; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: InvalidPart code\n'
fi
# Cleanup the still-active upload
curl -sS -X DELETE "$URL/mpb/missing.bin?uploadId=$UPID" -o /dev/null

# --- t4: complete with malformed XML ---
RESP=$(curl -sS -X POST "$URL/mpb/badxml.bin?uploads")
UPID=$(echo "$RESP" | grep -oP '<UploadId>\K[^<]+')
out=$(curl -sS -X POST "$URL/mpb/badxml.bin?uploadId=$UPID" \
    -H "Content-Type: application/xml" \
    --data-binary "<CompleteMultipartUpload></CompleteMultipartUpload>" \
    -w "%{http_code}" -o /tmp/fs3-mpu-err.$$)
check_eq "empty parts list = 400" "$out" "400"
curl -sS -X DELETE "$URL/mpb/badxml.bin?uploadId=$UPID" -o /dev/null

# --- t5: bad upload ID ---
out=$(curl -sS -X PUT "$URL/mpb/whatever?partNumber=1&uploadId=ffffffffffffffffffffffffffffffff" \
    --data-binary "data" -w "%{http_code}" -o /tmp/fs3-mpu-err.$$)
check_eq "unknown uploadId for part = 404" "$out" "404"
if grep -q "NoSuchUpload" /tmp/fs3-mpu-err.$$; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: NoSuchUpload code on bad id\n'
fi

# --- t6: malformed uploadId (not 32 hex) ---
out=$(curl -sS -X PUT "$URL/mpb/x?partNumber=1&uploadId=tooshort" \
    --data-binary "data" -w "%{http_code}" -o /dev/null)
check_eq "short uploadId = 404" "$out" "404"

# --- t7: large multipart (5 MB part + 1 MB part) ---
RESP=$(curl -sS -X POST "$URL/mpb/large.bin?uploads")
UPID=$(echo "$RESP" | grep -oP '<UploadId>\K[^<]+')
head -c 5242880 /dev/urandom > /tmp/fs3-mpu-big1.$$
head -c 1048576 /dev/urandom > /tmp/fs3-mpu-big2.$$
E1=$(curl -sS -X PUT "$URL/mpb/large.bin?partNumber=1&uploadId=$UPID" \
    --data-binary @/tmp/fs3-mpu-big1.$$ -D - -o /dev/null \
    | grep -i '^etag:' | tr -d '\r"' | awk '{print $2}')
E2=$(curl -sS -X PUT "$URL/mpb/large.bin?partNumber=2&uploadId=$UPID" \
    --data-binary @/tmp/fs3-mpu-big2.$$ -D - -o /dev/null \
    | grep -i '^etag:' | tr -d '\r"' | awk '{print $2}')
COMPLETE_BODY="<CompleteMultipartUpload>
  <Part><PartNumber>1</PartNumber><ETag>\"$E1\"</ETag></Part>
  <Part><PartNumber>2</PartNumber><ETag>\"$E2\"</ETag></Part>
</CompleteMultipartUpload>"
out=$(curl -sS -X POST "$URL/mpb/large.bin?uploadId=$UPID" \
    -H "Content-Type: application/xml" \
    --data-binary "$COMPLETE_BODY" \
    -w "%{http_code}" -o /dev/null)
check_eq "large multipart complete = 200" "$out" "200"

# Verify byte-for-byte
cat /tmp/fs3-mpu-big1.$$ /tmp/fs3-mpu-big2.$$ > /tmp/fs3-mpu-want.$$
curl -sS "$URL/mpb/large.bin" -o /tmp/fs3-mpu-got.$$
if cmp -s /tmp/fs3-mpu-want.$$ /tmp/fs3-mpu-got.$$; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: large multipart byte mismatch\n'
fi

# --- t8: ListMultipartUploads ---
# Initiate three uploads, then list and verify the response.
UP1=$(curl -sS -X POST "$URL/mpb/lmu/a.txt?uploads" | grep -oP '<UploadId>\K[^<]+')
UP2=$(curl -sS -X POST "$URL/mpb/lmu/b.txt?uploads" | grep -oP '<UploadId>\K[^<]+')
UP3=$(curl -sS -X POST "$URL/mpb/other/c.txt?uploads" | grep -oP '<UploadId>\K[^<]+')

body=$(curl -sS "$URL/mpb?uploads")
case "$body" in
    *"<ListMultipartUploadsResult"*) PASS=$((PASS+1)); printf '.';;
    *) FAIL=$((FAIL+1)); printf '\nFAIL: ListMultipartUploadsResult root\n%s\n' "$body";;
esac

# Should see all three uploads (we listed bucket mpb, all three are on mpb).
count_uploads=$(echo "$body" | grep -c "<Upload>" || true)
check_eq "three in-flight uploads listed" "$count_uploads" "3"

# Filter by prefix
body=$(curl -sS "$URL/mpb?uploads&prefix=lmu/")
count_uploads=$(echo "$body" | grep -c "<Upload>" || true)
check_eq "prefix filter narrows to 2" "$count_uploads" "2"

if echo "$body" | grep -q "<Prefix>lmu/</Prefix>"; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: <Prefix>lmu/</Prefix> echoed\n'
fi

# Cleanup uploads we just created
curl -sS -X DELETE "$URL/mpb/lmu/a.txt?uploadId=$UP1" -o /dev/null
curl -sS -X DELETE "$URL/mpb/lmu/b.txt?uploadId=$UP2" -o /dev/null
curl -sS -X DELETE "$URL/mpb/other/c.txt?uploadId=$UP3" -o /dev/null

# After abort, listing should be empty (well, no <Upload> entries)
body=$(curl -sS "$URL/mpb?uploads")
count_uploads=$(echo "$body" | grep -c "<Upload>" || true)
check_eq "after abort, no uploads listed" "$count_uploads" "0"

# --- t9: missing bucket → 404 ---
out=$(curl -sS -w "%{http_code}" -o /tmp/fs3-mpu-err.$$ "$URL/nobucket?uploads")
check_eq "list MPUs on missing bucket = 404" "$out" "404"
if grep -q "NoSuchBucket" /tmp/fs3-mpu-err.$$; then
    PASS=$((PASS+1)); printf '.'
else
    FAIL=$((FAIL+1)); printf '\nFAIL: NoSuchBucket in body\n'
fi

echo
echo "===== mpu e2e: $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
