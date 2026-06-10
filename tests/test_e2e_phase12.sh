#!/usr/bin/env bash
#
# tests/test_e2e_phase12.sh — Tier-2 NAS-readiness feature tests:
#   1. startup recovery (orphaned tmp/ files cleared on boot)
#   2. --max-body-size: declared and streamed 413 enforcement
#   3. --idle-timeout: stalled connections are reclaimed
#   4. --max-conns: connection cap rejects past the limit
#
set -eu
# The idle-timeout test deliberately writes into a socket the server has
# closed; without this the resulting SIGPIPE kills the whole script.
trap '' PIPE

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 19950 + RANDOM % 100 ))}
DATA=/tmp/fs3-p12-e2e-$$
LOG=/tmp/fs3-p12-e2e-$$.log
URL="http://127.0.0.1:$PORT"

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; }
    rm -rf "$DATA"
    rm -f /tmp/fs3-p12-$$.*
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

start_server() {
    mkdir -p "$DATA"
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

tmp_count() {
    find "$DATA/tmp" -mindepth 1 2>/dev/null | wc -l | tr -d ' '
}

# ===================================================================
# 1. Startup recovery: orphaned tmp files are swept on boot
# ===================================================================
mkdir -p "$DATA/tmp"
echo "half-written object from a crash" > "$DATA/tmp/obj.ORPHAN1"
echo "half-written part from a crash"   > "$DATA/tmp/part.ORPHAN2"

start_server
check_eq "recovery cleared orphaned tmp files" "$(tmp_count)" "0"
grep -q "recovered 2 orphaned temp file" "$LOG" && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: recovery log line missing\n'; }
printf '.'

# Server still works normally after recovery
code=$(curl -sS -X PUT "$URL/p12bkt" -o /dev/null -w "%{http_code}")
check_eq "bucket create after recovery" "$code" "200"
stop_server

# ===================================================================
# 2. --max-body-size
# ===================================================================
start_server --max-body-size 1M

# Under the cap → accepted and readable
head -c 100000 /dev/zero | tr '\0' 'a' > /tmp/fs3-p12-$$.small
code=$(curl -sS -X PUT "$URL/p12bkt/small" \
       --data-binary @/tmp/fs3-p12-$$.small -o /dev/null -w "%{http_code}")
check_eq "100K PUT under 1M cap → 200" "$code" "200"
got=$(curl -sS "$URL/p12bkt/small" | wc -c | tr -d ' ')
check_eq "100K object reads back" "$got" "100000"

# Declared Content-Length over the cap → 413 before any write
head -c 2097152 /dev/zero | tr '\0' 'b' > /tmp/fs3-p12-$$.big
code=$(curl -sS -X PUT "$URL/p12bkt/big" \
       --data-binary @/tmp/fs3-p12-$$.big -o /tmp/fs3-p12-$$.bigout -w "%{http_code}")
check_eq "2M PUT over 1M cap → 413" "$code" "413"
grep -q "EntityTooLarge" /tmp/fs3-p12-$$.bigout && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: 413 body missing EntityTooLarge\n'; }
printf '.'
check_eq "no tmp orphan after declared-length 413" "$(tmp_count)" "0"
code=$(curl -sS "$URL/p12bkt/big" -o /dev/null -w "%{http_code}")
check_eq "oversized object did not land" "$code" "404"

# Streamed (chunked, no Content-Length) body over the cap → 413 mid-stream
code=$(curl -sS -X PUT "$URL/p12bkt/chunked-big" \
       -H "Transfer-Encoding: chunked" -H "Content-Type: text/plain" \
       -T /tmp/fs3-p12-$$.big -o /tmp/fs3-p12-$$.chout -w "%{http_code}" || true)
check_eq "chunked 2M over 1M cap → 413" "$code" "413"
check_eq "no tmp orphan after streamed 413" "$(tmp_count)" "0"
code=$(curl -sS "$URL/p12bkt/chunked-big" -o /dev/null -w "%{http_code}")
check_eq "chunked oversized object did not land" "$code" "404"

# Exactly at the cap → accepted (boundary is >, not >=)
head -c 1048576 /dev/zero | tr '\0' 'c' > /tmp/fs3-p12-$$.exact
code=$(curl -sS -X PUT "$URL/p12bkt/exact" \
       --data-binary @/tmp/fs3-p12-$$.exact -o /dev/null -w "%{http_code}")
check_eq "exactly-1M PUT at 1M cap → 200" "$code" "200"

stop_server

# ===================================================================
# 3. --idle-timeout
# ===================================================================
start_server --idle-timeout 2

# Open a raw connection, send nothing, wait past the timeout: the
# server must close it (read returns EOF rather than blocking).
exec 3<>"/dev/tcp/127.0.0.1/$PORT"
sleep 4
got="open"
if ! { printf 'GET / HTTP/1.1\r\nHost: x\r\n\r\n' >&3; } 2>/dev/null; then
    got="closed"
else
    # Write may succeed into the kernel buffer even after FIN; the
    # tell is that the read side is at EOF.
    if ! IFS= read -r -t 2 line <&3; then got="closed"; fi
fi
exec 3<&- 3>&- 2>/dev/null || true
check_eq "idle connection reclaimed after timeout" "$got" "closed"

# An active connection inside the window still works
code=$(curl -sS "$URL/" -o /dev/null -w "%{http_code}")
check_eq "fresh request still served" "$code" "200"

stop_server

# ===================================================================
# 4. --max-conns
# ===================================================================
start_server --max-conns 2 --idle-timeout 0

# Occupy both slots with idle connections...
exec 4<>"/dev/tcp/127.0.0.1/$PORT"
exec 5<>"/dev/tcp/127.0.0.1/$PORT"
sleep 0.3
# ...then the third client must be turned away (accept + immediate close).
if curl -sS --max-time 3 "$URL/" -o /dev/null 2>/dev/null; then code="OK"; else code="REJ"; fi
check_eq "third connection rejected at cap 2" "$code" "REJ"

# Freeing a slot lets clients in again
exec 4<&- 4>&-
exec 5<&- 5>&-
sleep 0.3
code=$(curl -sS --max-time 3 "$URL/" -o /dev/null -w "%{http_code}")
check_eq "connection accepted after slots freed" "$code" "200"

stop_server

# ===================================================================
# 5. SIGHUP credential reload (rotation without restart)
# ===================================================================
CRED_FILE=/tmp/fs3-p12-$$.creds
ALICE_AK="ALICEKEYID12345678"
ALICE_SK="alicesecretkey0000000000000000001"
BOB_AK="BOBKEYIDABCDEF9876"
BOB_SK="bobsecretkey000000000000000000001"

sign() {
    local ak="$1" sk="$2"; shift 2
    FS3_AK="$ak" FS3_SK="$sk" python3 "$ROOT/tests/sign_request.py" "$@" 2>&1 | head -1
}

printf '%s:%s\n' "$ALICE_AK" "$ALICE_SK" > "$CRED_FILE"
start_server --credentials-file "$CRED_FILE" --require-auth

st=$(sign "$ALICE_AK" "$ALICE_SK" --method PUT --url "$URL/p12auth")
check_eq "alice works before reload" "$st" "STATUS=200"
st=$(sign "$BOB_AK" "$BOB_SK" --method GET --url "$URL/p12auth")
check_eq "bob rejected before reload" "$st" "STATUS=403"

# Add bob, HUP, both must work — no restart, same process.
printf '%s:%s\n' "$BOB_AK" "$BOB_SK" >> "$CRED_FILE"
kill -HUP "$SP"
sleep 1.5
kill -0 "$SP" || { echo "server died on SIGHUP" >&2; exit 1; }
st=$(sign "$BOB_AK" "$BOB_SK" --method GET --url "$URL/p12auth")
check_eq "bob works after reload" "$st" "STATUS=200"
st=$(sign "$ALICE_AK" "$ALICE_SK" --method GET --url "$URL/p12auth")
check_eq "alice still works after reload" "$st" "STATUS=200"

# Revoke alice, HUP: alice out, bob stays.
printf '%s:%s\n' "$BOB_AK" "$BOB_SK" > "$CRED_FILE"
kill -HUP "$SP"
sleep 1.5
st=$(sign "$ALICE_AK" "$ALICE_SK" --method GET --url "$URL/p12auth")
check_eq "revoked alice rejected after reload" "$st" "STATUS=403"
st=$(sign "$BOB_AK" "$BOB_SK" --method GET --url "$URL/p12auth")
check_eq "bob unaffected by alice's revocation" "$st" "STATUS=200"

# Malformed file + HUP: keep the old (working) credentials.
echo "not a credential line at all" > "$CRED_FILE"
kill -HUP "$SP"
sleep 1.5
st=$(sign "$BOB_AK" "$BOB_SK" --method GET --url "$URL/p12auth")
check_eq "bad reload keeps previous credentials" "$st" "STATUS=200"

rm -f "$CRED_FILE"
stop_server

# ===================================================================
# 6. Admin listener: /healthz + /metrics; auth-exempt /_health
# ===================================================================
MPORT=$((PORT + 1))
MURL="http://127.0.0.1:$MPORT"
start_server --metrics-port "$MPORT"

body=$(curl -s "$MURL/healthz")
check_eq "admin /healthz" "$body" "ok"
curl -s "$MURL/metrics" | grep -q "^fs3_up 1$" && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: fs3_up missing\n'; }
printf '.'

# Generate some traffic, then check the counters moved.
curl -s -X PUT "$URL/p12metrics" -o /dev/null
head -c 5000 /dev/zero | tr '\0' 'm' > /tmp/fs3-p12-$$.mobj
curl -s -X PUT "$URL/p12metrics/obj" --data-binary @/tmp/fs3-p12-$$.mobj -o /dev/null
curl -s "$URL/p12metrics/obj" -o /dev/null
scrape=$(curl -s "$MURL/metrics")
put2xx=$(echo "$scrape" | grep 'fs3_requests_total{method="PUT",status="2xx"}' | awk '{print $2}')
[ "${put2xx:-0}" -ge 2 ] && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: PUT 2xx counter=%s, want >=2\n' "$put2xx"; }
printf '.'
bin=$(echo "$scrape" | grep '^fs3_bytes_in_total' | awk '{print $2}')
[ "${bin:-0}" -ge 5000 ] && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: bytes_in=%s, want >=5000\n' "$bin"; }
printf '.'
bout=$(echo "$scrape" | grep '^fs3_bytes_out_total' | awk '{print $2}')
[ "${bout:-0}" -ge 5000 ] && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: bytes_out=%s, want >=5000 (GET body)\n' "$bout"; }
printf '.'
# DATA persists across this suite's sections, so count, don't assume 1.
nb=$(ls "$DATA/buckets" | wc -l | tr -d ' ')
echo "$scrape" | grep -q "^fs3_buckets_total $nb$" && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: buckets gauge != %s\n' "$nb"; }
printf '.'
dcount=$(echo "$scrape" | grep '^fs3_request_duration_seconds_count' | awk '{print $2}')
[ "${dcount:-0}" -ge 3 ] && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: duration count=%s, want >=3\n' "$dcount"; }
printf '.'

# The S3 namespace stays clean: /metrics there is just a missing bucket.
code=$(curl -s "$URL/metrics" -o /dev/null -w "%{http_code}")
check_eq "S3 port does not serve /metrics" "$code" "404"
stop_server

# /_health works without credentials even when auth is required.
printf '%s:%s\n' "$ALICE_AK" "$ALICE_SK" > "$CRED_FILE"
start_server --credentials-file "$CRED_FILE" --require-auth
code=$(curl -s "$URL/_health" -o /dev/null -w "%{http_code}")
check_eq "/_health auth-exempt under require-auth" "$code" "200"
code=$(curl -s "$URL/" -o /dev/null -w "%{http_code}")
check_eq "everything else still requires auth" "$code" "403"
rm -f "$CRED_FILE"
stop_server

printf '\n===== phase12 e2e: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
