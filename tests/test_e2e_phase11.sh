#!/usr/bin/env bash
#
# tests/test_e2e_phase11.sh — Phase 11 feature tests:
#   1. GET /_health endpoint
#   2. --credentials-file loading multiple key pairs
#   3. --min-free-bytes quota enforcement
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 19850 + RANDOM % 100 ))}
DATA=/tmp/fs3-p11-e2e-$$
LOG=/tmp/fs3-p11-e2e-$$.log
URL="http://127.0.0.1:$PORT"
CRED_FILE=/tmp/fs3-p11-creds-$$

ALICE_AK="ALICEKEYID12345678"
ALICE_SK="alicesecretkey0000000000000000001"
BOB_AK="BOBKEYIDABCDEF9876"
BOB_SK="bobsecretkey000000000000000000001"

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; }
    rm -rf "$DATA"
    rm -f "$CRED_FILE" /tmp/fs3-p11-$$.*
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then
        PASS=$((PASS+1)); printf '.'
    else
        FAIL=$((FAIL+1))
        printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"
    fi
}

# Helper: signed request via sign_request.py; returns "STATUS=NNN"
sign() {
    local ak="$1" sk="$2"; shift 2
    FS3_AK="$ak" FS3_SK="$sk" python3 "$ROOT/tests/sign_request.py" "$@" 2>&1 | head -1
}

start_server() {
    rm -rf "$DATA"; mkdir -p "$DATA"
    "$ROOT/fs3" -p "$PORT" -d "$DATA" "$@" >"$LOG" 2>&1 &
    SP=$!
    sleep 0.4
    if ! kill -0 "$SP" 2>/dev/null; then
        echo "server did not start" >&2; cat "$LOG" >&2; exit 1
    fi
}

stop_server() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; }
    SP=
}

# ===================================================================
# 1. Health endpoint
# ===================================================================
start_server

code=$(curl -sS "$URL/_health" -o /tmp/fs3-p11-$$.health -w "%{http_code}")
body=$(cat /tmp/fs3-p11-$$.health)
check_eq "GET /_health → 200" "$code" "200"

echo "$body" | grep -q '"status"' && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: /_health missing status field\n'; }
printf '.'
echo "$body" | grep -q '"ok"' && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: /_health status not ok\n'; }
printf '.'

ct=$(curl -sS "$URL/_health" -D - -o /dev/null \
     | grep -i '^content-type:' | tr -d '\r' | awk '{print $2}')
check_eq "/_health content-type" "$ct" "application/json"

# HEAD also works (no body returned but 200)
code=$(curl -sS --head "$URL/_health" -o /dev/null -w "%{http_code}")
check_eq "HEAD /_health → 200" "$code" "200"

# Wrong method → 405
code=$(curl -sS -X DELETE "$URL/_health" -o /dev/null -w "%{http_code}")
check_eq "DELETE /_health → 405" "$code" "405"

# /_health works even when auth is required (it's exempt)
# (the server started without --require-auth so any request works here)

stop_server

# ===================================================================
# 2. --credentials-file
# ===================================================================
cat > "$CRED_FILE" <<EOF
# fs3 credentials file
$ALICE_AK:$ALICE_SK
$BOB_AK:$BOB_SK
EOF

start_server --credentials-file "$CRED_FILE" --require-auth

# Create a bucket without auth → 403
code=$(curl -sS -X PUT "$URL/p11bkt" -o /dev/null -w "%{http_code}")
check_eq "no-auth request rejected (require-auth)" "$code" "403"

# Alice creates bucket
st=$(sign "$ALICE_AK" "$ALICE_SK" --method PUT --url "$URL/p11bkt")
check_eq "Alice can create bucket" "$st" "STATUS=200"

# Bob uploads object
st=$(sign "$BOB_AK" "$BOB_SK" --method PUT --url "$URL/p11bkt/bob-obj" \
     --body "hello from bob" --header "Content-Type:text/plain")
check_eq "Bob can upload object" "$st" "STATUS=200"

# Alice reads Bob's object
st=$(sign "$ALICE_AK" "$ALICE_SK" --method GET --url "$URL/p11bkt/bob-obj")
check_eq "Alice can read Bob's object" "$(echo "$st" | head -1)" "STATUS=200"

# Wrong secret → 403
st=$(FS3_AK="$ALICE_AK" FS3_SK="WRONGSECRETKEY000000000000000000" \
     python3 "$ROOT/tests/sign_request.py" \
     --method GET --url "$URL/p11bkt" 2>&1 | head -1)
check_eq "wrong secret → 403" "$st" "STATUS=403"

# Unknown access key → 403
st=$(FS3_AK="UNKNOWNKEYID0000001" FS3_SK="unknownsecretkey0000000000000000" \
     python3 "$ROOT/tests/sign_request.py" \
     --method GET --url "$URL/p11bkt" 2>&1 | head -1)
check_eq "unknown access key → 403" "$st" "STATUS=403"

stop_server

# --credentials-file and --auth together
cat > "$CRED_FILE" <<EOF
$ALICE_AK:$ALICE_SK
EOF

PORT2=$(( PORT + 1 ))
rm -rf "$DATA"; mkdir -p "$DATA"
"$ROOT/fs3" -p "$PORT2" -d "$DATA" \
    --credentials-file "$CRED_FILE" \
    --auth "$BOB_AK:$BOB_SK" \
    --require-auth >"$LOG" 2>&1 &
SP=$!
sleep 0.4

URL2="http://127.0.0.1:$PORT2"

st=$(sign "$ALICE_AK" "$ALICE_SK" --method PUT --url "$URL2/combo-bkt")
check_eq "file+flag: Alice (from file) → 200" "$st" "STATUS=200"

st=$(sign "$BOB_AK" "$BOB_SK" --method GET --url "$URL2/combo-bkt")
check_eq "file+flag: Bob (from --auth) → 200" "$st" "STATUS=200"

stop_server

# ===================================================================
# 3. --min-free-bytes quota
# ===================================================================
# 999 PiB — no filesystem will have this much free space
start_server --min-free-bytes 999999999999999

curl -sS -X PUT "$URL/qbkt" -o /dev/null >/dev/null 2>&1 || true

code=$(printf 'quota test' | curl -sS -X PUT "$URL/qbkt/obj" \
       --data-binary @- -o /dev/null -w "%{http_code}")
check_eq "PUT rejected (min-free-bytes too high) → 507" "$code" "507"

stop_server

# 1 byte → any sane disk has at least 1 byte free
start_server --min-free-bytes 1

curl -sS -X PUT "$URL/qbkt" -o /dev/null >/dev/null 2>&1 || true

code=$(printf 'quota ok' | curl -sS -X PUT "$URL/qbkt/obj" \
       --data-binary @- -o /dev/null -w "%{http_code}")
check_eq "PUT allowed (1-byte threshold) → 200" "$code" "200"

stop_server

# ===================================================================
# Report
# ===================================================================
printf '\n===== phase11 e2e: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
