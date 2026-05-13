#!/usr/bin/env bash
#
# tests/test_e2e_phase9.sh — Phase 9 feature tests:
#   1. HTTP Range requests (206 Partial Content / 416 Range Not Satisfiable)
#   2. POST /<bucket>?delete (bulk delete)
#   3. GET /<bucket>?location and GET /<bucket>?versioning (stubs)
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 19400 + RANDOM % 400 ))}
DATA=/tmp/fs3-p9-e2e-$$
LOG=/tmp/fs3-p9-e2e-$$.log
URL="http://127.0.0.1:$PORT"

cleanup() {
    [ -n "${SP:-}" ] && kill "$SP" 2>/dev/null || true
    rm -rf "$DATA"
    rm -f /tmp/fs3-p9-$$.*
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
out=$(curl -sS -X PUT "$URL/p9b" -o /dev/null -w "%{http_code}")
check_eq "bucket create" "$out" "200"

# Upload a 20-byte object: "ABCDEFGHIJKLMNOPQRST"
printf 'ABCDEFGHIJKLMNOPQRST' > /tmp/fs3-p9-$$.obj
out=$(curl -sS -X PUT "$URL/p9b/obj" --data-binary @/tmp/fs3-p9-$$.obj -o /dev/null -w "%{http_code}")
check_eq "PUT 20-byte object" "$out" "200"

# Upload a 1-byte object
printf 'X' > /tmp/fs3-p9-$$.one
out=$(curl -sS -X PUT "$URL/p9b/one" --data-binary @/tmp/fs3-p9-$$.one -o /dev/null -w "%{http_code}")
check_eq "PUT 1-byte object" "$out" "200"

# ---------- Range: bytes=A-B ------------------------------------------------
# bytes=0-9 → first 10 bytes = "ABCDEFGHIJ"
out=$(curl -sS -H "Range: bytes=0-9" "$URL/p9b/obj" -w "\n%{http_code}")
body=$(echo "$out" | head -1)
code=$(echo "$out" | tail -1)
check_eq "range 0-9 status" "$code" "206"
check_eq "range 0-9 body" "$body" "ABCDEFGHIJ"

# bytes=10-19 → last 10 bytes = "KLMNOPQRST"
out=$(curl -sS -H "Range: bytes=10-19" "$URL/p9b/obj" -w "\n%{http_code}")
body=$(echo "$out" | head -1)
code=$(echo "$out" | tail -1)
check_eq "range 10-19 status" "$code" "206"
check_eq "range 10-19 body" "$body" "KLMNOPQRST"

# bytes=5-5 → single byte = "F"
out=$(curl -sS -H "Range: bytes=5-5" "$URL/p9b/obj" -w "\n%{http_code}")
body=$(echo "$out" | head -1)
code=$(echo "$out" | tail -1)
check_eq "range 5-5 status" "$code" "206"
check_eq "range 5-5 body" "$body" "F"

# ---------- Range: bytes=A- (open end) -------------------------------------
# bytes=15- → bytes 15..19 = "PQRST"
out=$(curl -sS -H "Range: bytes=15-" "$URL/p9b/obj" -w "\n%{http_code}")
body=$(echo "$out" | head -1)
code=$(echo "$out" | tail -1)
check_eq "range 15- status" "$code" "206"
check_eq "range 15- body" "$body" "PQRST"

# bytes=0- → full object (still 206)
out=$(curl -sS -H "Range: bytes=0-" "$URL/p9b/obj" -w "\n%{http_code}")
body=$(echo "$out" | head -1)
code=$(echo "$out" | tail -1)
check_eq "range 0- status" "$code" "206"
check_eq "range 0- body" "$body" "ABCDEFGHIJKLMNOPQRST"

# ---------- Range: bytes=-N (suffix) ----------------------------------------
# bytes=-5 → last 5 bytes = "PQRST"
out=$(curl -sS -H "Range: bytes=-5" "$URL/p9b/obj" -w "\n%{http_code}")
body=$(echo "$out" | head -1)
code=$(echo "$out" | tail -1)
check_eq "range -5 status" "$code" "206"
check_eq "range -5 body" "$body" "PQRST"

# bytes=-100 → suffix larger than object → full object
out=$(curl -sS -H "Range: bytes=-100" "$URL/p9b/obj" -w "\n%{http_code}")
body=$(echo "$out" | head -1)
code=$(echo "$out" | tail -1)
check_eq "range -100 (clamp) status" "$code" "206"
check_eq "range -100 (clamp) body" "$body" "ABCDEFGHIJKLMNOPQRST"

# ---------- Range: clamp last byte to object size ---------------------------
# bytes=5-999 → S3 clamps last to obj_size-1 = 19 → "FGHIJKLMNOPQRST"
out=$(curl -sS -H "Range: bytes=5-999" "$URL/p9b/obj" -w "\n%{http_code}")
body=$(echo "$out" | head -1)
code=$(echo "$out" | tail -1)
check_eq "range 5-999 clamped status" "$code" "206"
check_eq "range 5-999 clamped body" "$body" "FGHIJKLMNOPQRST"

# ---------- Range: Content-Range header check --------------------------------
cr=$(curl -sS -H "Range: bytes=0-4" "$URL/p9b/obj" -D - -o /dev/null \
     | grep -i '^content-range:' | tr -d '\r' | sed 's/[Cc]ontent-[Rr]ange: //')
check_eq "content-range header" "$cr" "bytes 0-4/20"

cl=$(curl -sS -H "Range: bytes=0-4" "$URL/p9b/obj" -D - -o /dev/null \
     | grep -i '^content-length:' | tr -d '\r' | awk '{print $2}')
check_eq "content-length for range" "$cl" "5"

# ---------- Range: 416 errors -----------------------------------------------
# first > last → 416
code=$(curl -sS -H "Range: bytes=10-5" "$URL/p9b/obj" -o /dev/null -w "%{http_code}")
check_eq "range 10-5 invalid → 416" "$code" "416"

# first beyond end of file → 416
code=$(curl -sS -H "Range: bytes=20-25" "$URL/p9b/obj" -o /dev/null -w "%{http_code}")
check_eq "range 20-25 beyond EOF → 416" "$code" "416"

# Range on 1-byte object where bytes=1-1 (OOB)
code=$(curl -sS -H "Range: bytes=1-1" "$URL/p9b/one" -o /dev/null -w "%{http_code}")
check_eq "range 1-1 on 1-byte object → 416" "$code" "416"

# ---------- Range: HEAD with Range (should return 206 with no body) ----------
# Use --head (not -X HEAD) so curl knows not to expect a body.
code=$(curl -sS --head -H "Range: bytes=0-4" "$URL/p9b/obj" -o /dev/null -w "%{http_code}")
check_eq "HEAD range 0-4 → 206" "$code" "206"

# ---------- No Range = full 200 GET ------------------------------------------
out=$(curl -sS "$URL/p9b/obj" -w "\n%{http_code}")
body=$(echo "$out" | head -1)
code=$(echo "$out" | tail -1)
check_eq "GET no range → 200" "$code" "200"
check_eq "GET no range body" "$body" "ABCDEFGHIJKLMNOPQRST"

# ---------- ?delete: PUT some keys to delete ---------------------------------
for k in del1 del2 del3; do
    printf '%s' "$k" | curl -sS -X PUT "$URL/p9b/$k" --data-binary @- -o /dev/null
done

# Basic delete of two existing keys
DEL_BODY='<Delete><Object><Key>del1</Key></Object><Object><Key>del2</Key></Object></Delete>'
code=$(curl -sS -X POST "$URL/p9b?delete" -H "Content-Type: application/xml" \
       --data-binary "$DEL_BODY" -o /tmp/fs3-p9-$$.delresp -w "%{http_code}")
body=$(cat /tmp/fs3-p9-$$.delresp)
check_eq "?delete 2 keys → 200" "$code" "200"
# Response must contain <Deleted> entries for both keys (XML is multi-line)
echo "$body" | grep -q '<Key>del1</Key>' && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); printf '\nFAIL: del1 not in DeleteResult\n'; }
printf '.'
echo "$body" | grep -q '<Key>del2</Key>' && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); printf '\nFAIL: del2 not in DeleteResult\n'; }
printf '.'

# Keys are gone
code=$(curl -sS "$URL/p9b/del1" -o /dev/null -w "%{http_code}")
check_eq "del1 gone after delete" "$code" "404"
code=$(curl -sS "$URL/p9b/del2" -o /dev/null -w "%{http_code}")
check_eq "del2 gone after delete" "$code" "404"

# del3 still present
code=$(curl -sS "$URL/p9b/del3" -o /dev/null -w "%{http_code}")
check_eq "del3 still present" "$code" "200"

# Idempotent: delete already-absent key returns 200 with <Deleted>
DEL_BODY='<Delete><Object><Key>del1</Key></Object></Delete>'
code=$(curl -sS -X POST "$URL/p9b?delete" -H "Content-Type: application/xml" \
       --data-binary "$DEL_BODY" -o /tmp/fs3-p9-$$.delresp2 -w "%{http_code}")
body=$(cat /tmp/fs3-p9-$$.delresp2)
check_eq "?delete absent key → 200 (idempotent)" "$code" "200"
echo "$body" | grep -q '<Deleted>' && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); printf '\nFAIL: missing <Deleted> for absent key\n'; }
printf '.'

# Quiet mode: <Deleted> elements suppressed, response still 200
DEL_BODY='<Delete><Quiet>true</Quiet><Object><Key>del3</Key></Object></Delete>'
code=$(curl -sS -X POST "$URL/p9b?delete" -H "Content-Type: application/xml" \
       --data-binary "$DEL_BODY" -o /tmp/fs3-p9-$$.delresp3 -w "%{http_code}")
body=$(cat /tmp/fs3-p9-$$.delresp3)
check_eq "?delete quiet mode → 200" "$code" "200"
echo "$body" | grep -qv '<Deleted>' && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); printf '\nFAIL: <Deleted> should be absent in quiet mode\n'; }
printf '.'

# Malformed XML → 400
DEL_BODY='not xml at all'
code=$(curl -sS -X POST "$URL/p9b?delete" -H "Content-Type: application/xml" \
       --data-binary "$DEL_BODY" -o /dev/null -w "%{http_code}")
check_eq "?delete malformed XML → 400" "$code" "400"

# ?delete on non-existent bucket → 404
DEL_BODY='<Delete><Object><Key>k</Key></Object></Delete>'
code=$(curl -sS -X POST "$URL/nosuchbucket?delete" -H "Content-Type: application/xml" \
       --data-binary "$DEL_BODY" -o /dev/null -w "%{http_code}")
check_eq "?delete no-such-bucket → 404" "$code" "404"

# ---------- ?location --------------------------------------------------------
code=$(curl -sS "$URL/p9b?location" -o /tmp/fs3-p9-$$.loc -w "%{http_code}")
body=$(cat /tmp/fs3-p9-$$.loc)
check_eq "GET ?location → 200" "$code" "200"
echo "$body" | grep -q 'LocationConstraint' && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); printf '\nFAIL: ?location missing LocationConstraint\n'; }
printf '.'

# ?location on missing bucket → 404
code=$(curl -sS "$URL/nosuchbucket?location" -o /dev/null -w "%{http_code}")
check_eq "GET ?location no-such-bucket → 404" "$code" "404"

# ---------- ?versioning -------------------------------------------------------
code=$(curl -sS "$URL/p9b?versioning" -o /tmp/fs3-p9-$$.ver -w "%{http_code}")
body=$(cat /tmp/fs3-p9-$$.ver)
check_eq "GET ?versioning → 200" "$code" "200"
echo "$body" | grep -q 'VersioningConfiguration' && PASS=$((PASS+1)) || { FAIL=$((FAIL+1)); printf '\nFAIL: ?versioning missing VersioningConfiguration\n'; }
printf '.'

# ?versioning on missing bucket → 404
code=$(curl -sS "$URL/nosuchbucket?versioning" -o /dev/null -w "%{http_code}")
check_eq "GET ?versioning no-such-bucket → 404" "$code" "404"

# ---------- Final report ------------------------------------------------------
printf '\n===== phase9 e2e: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
