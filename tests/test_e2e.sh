#!/usr/bin/env bash
#
# tests/test_e2e.sh — end-to-end HTTP tests for fs3.
#
# Spawns a fresh server bound to an ephemeral port with a fresh data
# root, exercises every handler via curl/nc, and verifies wire-level
# response shapes (status codes, headers, body bytes).
#
# Each test is a function. Failures print a clear FAIL line; the
# counter is reported at the end.
#
# Usage:
#   tests/test_e2e.sh [-v]         # default: release build
#   DEBUG=1 tests/test_e2e.sh      # build with sanitizers (slower)

set -u

VERBOSE=0
[ "${1:-}" = "-v" ] && VERBOSE=1

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd -- "$SCRIPT_DIR/.." && pwd)

# Build target — DEBUG=1 in env requests sanitizers
BUILD_FLAGS=""
[ "${DEBUG:-}" = "1" ] && BUILD_FLAGS="DEBUG=1"

PORT=$(( 19500 + RANDOM % 500 ))
DATA=/tmp/fs3-e2e-$$
LOG=/tmp/fs3-e2e-$$.log
SERVER_PID=

cleanup() {
    if [ -n "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null
        wait $SERVER_PID 2>/dev/null
    fi
    rm -rf "$DATA" "$LOG"
}
trap cleanup EXIT

# ---- Build & start ------------------------------------------------------

(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1) || {
    echo "BUILD FAILED" >&2
    (cd "$ROOT" && make $BUILD_FLAGS fs3 2>&1 | tail -10) >&2
    exit 1
}

"$ROOT/fs3" -p $PORT -d "$DATA" >"$LOG" 2>&1 &
SERVER_PID=$!

# Wait for server to be reachable
for i in 1 2 3 4 5 6 7 8 9 10; do
    if curl -sS -m 1 -o /dev/null "http://127.0.0.1:$PORT/" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

URL="http://127.0.0.1:$PORT"

# ---- Test framework -----------------------------------------------------

PASS=0
FAIL=0
CURRENT_TEST=""

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

# Compare two values; first is got, second is want
check_eq() {
    local label=$1 got=$2 want=$3
    if [ "$got" = "$want" ]; then
        [ $VERBOSE = 1 ] && echo "  ok: $label = $got"
        return 0
    fi
    fail "$label: got [$got] want [$want]"
    return 1
}

check_contains() {
    local label=$1 haystack=$2 needle=$3
    case "$haystack" in
        *"$needle"*)
            [ $VERBOSE = 1 ] && echo "  ok: $label contains [$needle]"
            return 0 ;;
    esac
    fail "$label: missing [$needle] in:"
    echo "$haystack" | head -10 | sed 's/^/      /'
    return 1
}

run_test() {
    CURRENT_TEST=$1
    [ $VERBOSE = 1 ] && echo "=== $CURRENT_TEST ==="
    local before_fail=$FAIL
    "$1"
    if [ "$FAIL" = "$before_fail" ]; then
        PASS=$((PASS + 1))
        [ $VERBOSE = 0 ] && printf "."
    else
        [ $VERBOSE = 0 ] && echo " FAIL($CURRENT_TEST)"
    fi
}

# Curl wrappers. They capture status code as stdout (so the caller can
# do `code=$(http_get ...)`); the body is left in /tmp/fs3-body.$$
# for the caller to read via `BODY=$(cat /tmp/fs3-body.$$)` after.
# We can't rely on shell-variable side effects because $(...) runs in a
# subshell that doesn't propagate variables to the parent.
BODY_FILE=/tmp/fs3-body.$$
HEADERS_FILE=/tmp/fs3-headers.$$
trap 'rm -f $BODY_FILE $HEADERS_FILE' EXIT

http_get() {
    curl -sS -m 5 -o "$BODY_FILE" -w "%{http_code}" "$URL$1"
}
http_put() {
    local path=$1 body=$2
    local args=()
    [ $# -ge 3 ] && args+=(-H "$3")
    printf '%s' "$body" | \
        curl -sS -m 5 -o "$BODY_FILE" -w "%{http_code}" \
            -X PUT --data-binary @- "${args[@]}" "$URL$path"
}
http_put_empty() {
    curl -sS -m 5 -o "$BODY_FILE" -w "%{http_code}" -X PUT "$URL$1"
}
http_head() {
    curl -sS -m 5 -D "$HEADERS_FILE" -o /dev/null "$URL$1" >/dev/null
    head -1 "$HEADERS_FILE" | awk '{print $2}'
}
http_delete() {
    curl -sS -m 5 -o "$BODY_FILE" -w "%{http_code}" -X DELETE "$URL$1"
}
read_body() { cat "$BODY_FILE" 2>/dev/null || true; }
read_headers() { cat "$HEADERS_FILE" 2>/dev/null || true; }

# ---- Tests --------------------------------------------------------------

t_bucket_create() {
    code=$(http_put_empty /test-bucket-create)
    check_eq "PUT bucket status" "$code" "200"
}

t_bucket_create_invalid() {
    code=$(http_put_empty /Bad)
    check_eq "PUT short uppercase bucket" "$code" "400"
    check_contains "InvalidBucketName error body" "$(read_body)" "InvalidBucketName"
}

t_bucket_create_duplicate() {
    http_put_empty /dup-bucket >/dev/null
    code=$(http_put_empty /dup-bucket)
    check_eq "PUT duplicate bucket" "$code" "409"
    check_contains "duplicate error body" "$(read_body)" "BucketAlreadyExists"
}

t_object_put_get() {
    http_put_empty /bpg >/dev/null
    code=$(http_put /bpg/hello "Hello, world!" "Content-Type: text/plain")
    check_eq "PUT object" "$code" "200"

    code=$(http_get /bpg/hello)
    check_eq "GET object status" "$code" "200"
    check_eq "GET object body" "$(read_body)" "Hello, world!"
}

t_object_put_etag() {
    http_put_empty /bpe >/dev/null
    # MD5 of "hello world" is 5eb63bbbe01eeed093cb22bb8f5acdc3
    HEADERS=$(printf 'hello world' | curl -sS -m 5 -i -X PUT \
        --data-binary @- "$URL/bpe/k")
    check_contains "ETag matches MD5" "$HEADERS" '"5eb63bbbe01eeed093cb22bb8f5acdc3"'
}

t_object_head() {
    http_put_empty /bhd >/dev/null
    http_put /bhd/k "12345" "Content-Type: text/plain" >/dev/null
    HEADERS=$(curl -sS -m 5 -I "$URL/bhd/k")
    check_contains "HEAD has Content-Length" "$HEADERS" "Content-Length: 5"
    check_contains "HEAD has Content-Type" "$HEADERS" "text/plain"
    check_contains "HEAD has ETag"          "$HEADERS" "ETag:"
    check_contains "HEAD has Last-Modified" "$HEADERS" "Last-Modified:"
    check_contains "HEAD has Accept-Ranges" "$HEADERS" "Accept-Ranges: bytes"
}

t_object_delete() {
    http_put_empty /bdl >/dev/null
    http_put /bdl/k "x" >/dev/null
    code=$(http_delete /bdl/k)
    check_eq "DELETE returns 204" "$code" "204"

    code=$(http_get /bdl/k)
    check_eq "GET after delete returns 404" "$code" "404"
    check_contains "404 body has NoSuchKey" "$(read_body)" "NoSuchKey"

    # Idempotent: DELETE again should still succeed
    code=$(http_delete /bdl/k)
    check_eq "DELETE missing returns 204 (idempotent)" "$code" "204"
}

t_object_overwrite() {
    http_put_empty /bow >/dev/null
    http_put /bow/k "first" >/dev/null
    http_put /bow/k "second" >/dev/null
    code=$(http_get /bow/k)
    check_eq "GET overwritten body" "$(read_body)" "second"
}

t_object_missing_bucket() {
    code=$(http_get /no-such-bucket-here/k)
    check_eq "GET on missing bucket" "$code" "404"
    check_contains "NoSuchBucket error" "$(read_body)" "NoSuchBucket"
}

t_object_missing_key() {
    http_put_empty /bmk >/dev/null
    code=$(http_get /bmk/missing)
    check_eq "GET on missing key" "$code" "404"
    check_contains "NoSuchKey error" "$(read_body)" "NoSuchKey"
}

t_list_basic() {
    http_put_empty /blb >/dev/null
    http_put /blb/a "x" >/dev/null
    http_put /blb/b "x" >/dev/null
    http_put /blb/c "x" >/dev/null
    code=$(http_get /blb)
    check_eq "list status" "$code" "200"
    check_contains "list contains a" "$(read_body)" "<Key>a</Key>"
    check_contains "list contains b" "$(read_body)" "<Key>b</Key>"
    check_contains "list contains c" "$(read_body)" "<Key>c</Key>"
    check_contains "list IsTruncated false" "$(read_body)" "<IsTruncated>false</IsTruncated>"
    check_contains "list MaxKeys default" "$(read_body)" "<MaxKeys>1000</MaxKeys>"
}

t_list_truncated() {
    http_put_empty /blt >/dev/null
    for i in 1 2 3 4 5 6 7 8; do
        http_put /blt/k$i "x" >/dev/null
    done
    code=$(http_get "/blt?max-keys=3")
    check_eq "truncated list status" "$code" "200"
    check_contains "list MaxKeys=3" "$(read_body)" "<MaxKeys>3</MaxKeys>"
    check_contains "list IsTruncated true" "$(read_body)" "<IsTruncated>true</IsTruncated>"
    # First 3 keys lexicographically
    check_contains "list contains k1" "$(read_body)" "<Key>k1</Key>"
    check_contains "list contains k2" "$(read_body)" "<Key>k2</Key>"
    check_contains "list contains k3" "$(read_body)" "<Key>k3</Key>"
    # k4..k8 should NOT be in this page
    case "$(read_body)" in
        *"<Key>k4</Key>"*) fail "k4 should not appear in truncated page" ;;
    esac
}

t_list_prefix() {
    http_put_empty /blp >/dev/null
    http_put /blp/photos/a "x" >/dev/null
    http_put /blp/photos/b "x" >/dev/null
    http_put /blp/videos/x "x" >/dev/null
    code=$(http_get "/blp?prefix=photos/")
    check_eq "prefix list status" "$code" "200"
    check_contains "prefix=photos/ in response" "$(read_body)" "<Prefix>photos/</Prefix>"
    check_contains "list contains photos/a" "$(read_body)" "<Key>photos/a</Key>"
    check_contains "list contains photos/b" "$(read_body)" "<Key>photos/b</Key>"
    case "$(read_body)" in
        *"videos/x"*) fail "videos/x should not appear with prefix=photos/" ;;
    esac
}

t_list_delimiter() {
    http_put_empty /bld >/dev/null
    http_put /bld/photos/a "x" >/dev/null
    http_put /bld/photos/b "x" >/dev/null
    http_put /bld/videos/x "x" >/dev/null
    http_put /bld/readme   "x" >/dev/null
    code=$(http_get "/bld?delimiter=/")
    check_eq "delimiter list status" "$code" "200"
    check_contains "delimiter / in response" "$(read_body)" "<Delimiter>/</Delimiter>"
    check_contains "CommonPrefix photos/" "$(read_body)" "<Prefix>photos/</Prefix>"
    check_contains "CommonPrefix videos/" "$(read_body)" "<Prefix>videos/</Prefix>"
    check_contains "literal readme key" "$(read_body)" "<Key>readme</Key>"
}

t_xml_escaping() {
    # S3 keys may include & < > characters that must be escaped in
    # response XML. Verify escaping in both the GET 404 body's
    # <Resource> and the listing's <Key>.
    http_put_empty /bxe >/dev/null
    # URL-encode tricky bytes in the key
    code=$(http_put "/bxe/cat%26dog%3C2%3E" "y")
    check_eq "PUT key with special chars" "$code" "200"

    code=$(http_get "/bxe")
    check_contains "list <Key> escaped &amp;"  "$(read_body)" "&amp;"
    check_contains "list <Key> escaped &lt;"   "$(read_body)" "&lt;"
    check_contains "list <Key> escaped &gt;"   "$(read_body)" "&gt;"
    # Raw '<' in body would mean unescaped output — should never happen
    # inside the <Key> element. Hard to assert generically here without
    # a real XML parser; the presence of escapes is the main check.
}

t_keep_alive_pipelined() {
    http_put_empty /bka >/dev/null
    for i in 1 2 3 4; do http_put /bka/k$i "body$i" >/dev/null; done

    # Send 4 pipelined GETs; collect with nc reading until close.
    OUT=$( { for i in 1 2 3 4; do
        printf 'GET /bka/k%d HTTP/1.1\r\nHost: x\r\n\r\n' $i
    done
    sleep 0.3   # give server time to respond before we close stdin
    } | nc -w3 127.0.0.1 $PORT )

    n=$(echo "$OUT" | grep -c "HTTP/1.1 200")
    check_eq "pipelined status count" "$n" "4"
    check_contains "pipelined response 1 body" "$OUT" "body1"
    check_contains "pipelined response 4 body" "$OUT" "body4"
}

t_method_not_allowed() {
    code=$(curl -sS -m 5 -o /tmp/body.$$ -w "%{http_code}" \
        -X POST -d "" "$URL/")
    BODY=$(cat /tmp/body.$$); rm -f /tmp/body.$$
    # Service-level POST → 405 or 501 (we return NotImplemented for
    # service-level GET right now; POST also rejected)
    case "$code" in
        405|501) ;;
        *) fail "service POST: got $code, expected 405 or 501" ;;
    esac
}

t_large_object() {
    # 2 MB object — exercises sendfile-driven streaming GET
    http_put_empty /big >/dev/null
    BIG=$(yes "x" | tr -d '\n' | head -c 2000000)
    code=$(printf '%s' "$BIG" | curl -sS -m 30 -o /dev/null \
        -w "%{http_code}" -X PUT --data-binary @- "$URL/big/blob")
    check_eq "PUT 2MB status" "$code" "200"

    # GET back, count bytes
    SIZE=$(curl -sS -m 30 "$URL/big/blob" | wc -c)
    check_eq "GET 2MB body size" "$SIZE" "2000000"
}

t_content_type_roundtrip() {
    http_put_empty /bct >/dev/null
    http_put /bct/a "{}" "Content-Type: application/json" >/dev/null
    HEADERS=$(curl -sS -m 5 -I "$URL/bct/a")
    check_contains "Content-Type echoed back" "$HEADERS" "Content-Type: application/json"
}

t_path_traversal_safe() {
    http_put_empty /bpt >/dev/null
    # URL-encoded "../../etc/passwd" as the key
    code=$(http_put "/bpt/..%2F..%2Fetc%2Fpasswd" "yo")
    check_eq "PUT traversal key status" "$code" "200"

    # Should be retrievable as exactly that key
    code=$(http_get "/bpt/..%2F..%2Fetc%2Fpasswd")
    check_eq "GET traversal key body" "$(read_body)" "yo"

    # And no /etc directory at the data root level
    if [ -e "$DATA/etc" ]; then
        fail "path traversal escaped to $DATA/etc"
    fi
}

# Force the response body past the 16 KB wbuf so ext_body spillover
# kicks in. Each Contents block is ~250 bytes, so 80 entries → ~20 KB
# body, comfortably above wbuf. We verify all 80 keys are present and
# the response is well-formed XML (no truncation, no internal error).
t_list_ext_body_spillover() {
    http_put_empty /bspill >/dev/null
    # Insert 80 keys in parallel for speed
    seq 1 80 | xargs -P 20 -I{} bash -c '
        i=$(printf "%03d" $1)
        printf x | curl -sS -m 5 -X PUT --data-binary @- \
            "'"$URL"'/bspill/key$i" -o /dev/null
    ' _ {}

    code=$(http_get "/bspill?max-keys=80")
    check_eq "spillover list status" "$code" "200"

    body=$(read_body)
    body_len=${#body}
    # Sanity: the body must be larger than wbuf (16384) — otherwise this
    # test isn't actually exercising the spillover path.
    if [ "$body_len" -le 16384 ]; then
        fail "spillover body only $body_len bytes (≤16384, not exercising ext_body)"
    fi

    n_keys=$(printf '%s' "$body" | grep -c '<Key>')
    check_eq "spillover key count" "$n_keys" "80"
    check_contains "spillover not truncated" "$body" "<IsTruncated>false</IsTruncated>"
    # First and last lex-sorted keys present
    check_contains "spillover first key"     "$body" "<Key>key001</Key>"
    check_contains "spillover last key"      "$body" "<Key>key080</Key>"
    # Closing root tag — proves response wasn't cut off mid-stream
    check_contains "spillover well-closed"   "$body" "</ListBucketResult>"
}

# ---- Run ----------------------------------------------------------------

run_test t_bucket_create
run_test t_bucket_create_invalid
run_test t_bucket_create_duplicate
run_test t_object_put_get
run_test t_object_put_etag
run_test t_object_head
run_test t_object_delete
run_test t_object_overwrite
run_test t_object_missing_bucket
run_test t_object_missing_key
run_test t_list_basic
run_test t_list_truncated
run_test t_list_prefix
run_test t_list_delimiter
run_test t_xml_escaping
run_test t_keep_alive_pipelined
run_test t_method_not_allowed
run_test t_large_object
run_test t_content_type_roundtrip
run_test t_path_traversal_safe
run_test t_list_ext_body_spillover

echo
echo "===== $PASS passed, $FAIL failed ====="

# Check for sanitizer output in the log
if grep -qE "(ERROR|runtime error|leaked|SUMMARY)" "$LOG"; then
    echo "SANITIZER OUTPUT FOUND:"
    grep -E "(ERROR|runtime error|leaked|SUMMARY)" "$LOG"
    FAIL=$((FAIL + 1))
fi

[ "$FAIL" = "0" ] || exit 1
exit 0
