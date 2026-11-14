#!/usr/bin/env bash
#
# tests/test_e2e_subresources.sh — S0 regression: an S3 subresource the
# server does not implement must answer 501 NotImplemented and never reach
# the store. Before the fix, "PUT /b/k?tagging" overwrote the object with
# the XML body and "DELETE /b/k?versionId=x" deleted it.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 20800 + RANDOM % 400 ))}
DATA=/tmp/fs3-sub-e2e-$$
LOG=/tmp/fs3-sub-e2e-$$.log
URL="http://127.0.0.1:$PORT"

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; } || true
    rm -rf "$DATA" "$LOG"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

"$ROOT/fs3" -p "$PORT" -d "$DATA" >"$LOG" 2>&1 &
SP=$!
sleep 0.4
kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}
code() { curl -sS -o /dev/null -w "%{http_code}" "$@"; }

check_eq "create bucket" "$(code -X PUT "$URL/subb")" "200"
check_eq "put object" "$(code -X PUT --data-binary 'original' "$URL/subb/k")" "200"

body_is_original() {
    check_eq "$1: object unchanged" "$(curl -sS "$URL/subb/k")" "original"
}

for sub in tagging torrent restore select attributes \
           versions policy cors lifecycle website object-lock encryption \
           replication notification logging; do
    check_eq "PUT ?$sub → 501" \
        "$(code -X PUT --data-binary '<Tagging/>' "$URL/subb/k?$sub")" "501"
    body_is_original "PUT ?$sub"
    check_eq "DELETE ?$sub → 501" "$(code -X DELETE "$URL/subb/k?$sub")" "501"
    body_is_original "DELETE ?$sub"
    check_eq "GET ?$sub → 501" "$(code "$URL/subb/k?$sub")" "501"
done

# Object-lock subresources on a bucket without object lock: refused,
# object untouched.
for sub in retention legal-hold; do
    check_eq "PUT ?$sub (no lock) → 400" \
        "$(code -X PUT --data-binary '<Retention/>' "$URL/subb/k?$sub")" "400"
    body_is_original "PUT ?$sub"
done

# A malformed versionId is refused before any path is built (S5) and
# never touches the current object.
for m in PUT DELETE GET; do
    check_eq "$m ?versionId=../x → 400" \
        "$(code -X $m --data-binary 'x' "$URL/subb/k?versionId=../../etc")" "400"
    body_is_original "$m ?versionId"
done

# POST ?restore / ?select must not be treated as anything else.
check_eq "POST ?restore → 501" "$(code -X POST --data-binary x "$URL/subb/k?restore")" "501"
body_is_original "POST ?restore"

# Bucket level: DELETE ?cors must not delete the bucket; PUT ?versioning
# must not try to create it.
for sub in tagging encryption \
           replication publicAccessBlock; do
    check_eq "bucket DELETE ?$sub → 501" "$(code -X DELETE "$URL/subb?$sub")" "501"
    check_eq "bucket PUT ?$sub → 501" \
        "$(code -X PUT --data-binary '<x/>' "$URL/subb?$sub")" "501"
    check_eq "bucket GET ?$sub → 501" "$(code "$URL/subb?$sub")" "501"
done
check_eq "bucket PUT ?versioning malformed → 400" "$(code -X PUT --data-binary '<x/>' "$URL/subb?versioning")" "400"
check_eq "bucket survives" "$(code -I "$URL/subb")" "200"
body_is_original "bucket-level probes"

# GET ?uploadId is ListParts and must not return the object.
check_eq "GET ?uploadId (unknown) → 404 NoSuchUpload" "$(code "$URL/subb/k?uploadId=0123456789abcdef0123456789abcdef")" "404"
# GetObject ?partNumber=2 would be wrong bytes; =1 is the whole object.
check_eq "GET ?partNumber=2 → 501" "$(code "$URL/subb/k?partNumber=2")" "501"
check_eq "GET ?partNumber=1 → 200" "$(code "$URL/subb/k?partNumber=1")" "200"

# Modifiers do not change the operation.
check_eq "GET with response-* modifier" \
    "$(curl -sS "$URL/subb/k?response-content-type=text/plain")" "original"
check_eq "GET with x-id modifier" "$(curl -sS "$URL/subb/k?x-id=GetObject")" "original"
check_eq "unknown non-S3 param ignored" "$(curl -sS "$URL/subb/k?cachebust=123")" "original"

# Implemented subresources still work.
check_eq "GET ?acl" "$(code "$URL/subb/k?acl")" "200"
check_eq "bucket GET ?location" "$(code "$URL/subb?location")" "200"

# Too many query parameters → 400, not a crash or truncation.
q=$(for i in $(seq 1 60); do printf 'p%d=1&' "$i"; done)
check_eq "60 params → 400" "$(code "$URL/subb/k?$q")" "400"

echo
echo "===== subresources e2e: $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
