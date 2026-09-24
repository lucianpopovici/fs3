#!/usr/bin/env bash
#
# tests/test_e2e_isolation.sh — per-user bucket isolation:
#   1. owners reach their buckets; other users get 403 on every verb
#   2. several keys can share a user; a key with no user is its own owner
#   3. ListAllMyBuckets shows only your buckets (admins see all)
#   4. server-side copy checks both source and destination
#   5. --admin users can act on any bucket
#   6. SIGHUP key rotation keeps a user's buckets
#   7. ownerless (pre-isolation) buckets: admin-only, --legacy-owner
#   8. anonymous requests without --require-auth own nothing
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 20050 + RANDOM % 100 ))}
DATA=/tmp/fs3-iso-e2e-$$
LOG=/tmp/fs3-iso-e2e-$$.log
CRED_FILE=/tmp/fs3-iso-$$.creds
URL="http://127.0.0.1:$PORT"

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; }
    rm -rf "$DATA"
    rm -f "$LOG" "$CRED_FILE"
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
check_has() {   # name haystack needle
    if printf '%s' "$2" | grep -q -- "$3"; then
        PASS=$((PASS+1)); printf '.'
    else
        FAIL=$((FAIL+1)); printf '\nFAIL: %s (missing %s)\n' "$1" "$3"
    fi
}
check_lacks() { # name haystack needle
    if printf '%s' "$2" | grep -q -- "$3"; then
        FAIL=$((FAIL+1)); printf '\nFAIL: %s (unexpected %s)\n' "$1" "$3"
    else
        PASS=$((PASS+1)); printf '.'
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

# Credentials: two keys for alice, one for bob, carol has no user (her
# access key is her identity), root is an admin.
A1=AKIAALICE0000000001; A1S=alicesecret00000000000000000000001
A2=AKIAALICE0000000002; A2S=alicesecret00000000000000000000002
B=AKIABOB000000000001;  BS=bobsecret0000000000000000000000001
C=AKIACAROL0000000001;  CS=carolsecret00000000000000000000001
R=AKIAROOT00000000001;  RS=rootsecret000000000000000000000001

write_creds() {
    cat > "$CRED_FILE" <<EOF
# ak:sk[:user]
$1:$2:alice
$A2:$A2S:alice
$B:$BS:bob
$C:$CS
$R:$RS:root
EOF
}

# "STATUS=NNN"; `req KEY SECRET args...`
req() {
    local ak="$1" sk="$2"; shift 2
    FS3_AK="$ak" FS3_SK="$sk" python3 "$ROOT/tests/sign_request.py" "$@" 2>&1 | head -1
}
# Full response (status line + body).
req_body() {
    local ak="$1" sk="$2"; shift 2
    FS3_AK="$ak" FS3_SK="$sk" python3 "$ROOT/tests/sign_request.py" "$@" 2>&1
}

write_creds "$A1" "$A1S"
start_server --credentials-file "$CRED_FILE" --require-auth --admin root

# ===================================================================
# 1. Owners vs. everyone else
# ===================================================================
check_eq "alice creates her bucket" \
    "$(req $A1 $A1S --method PUT --url "$URL/alice-bkt")" "STATUS=200"
check_eq "bob creates his bucket" \
    "$(req $B $BS --method PUT --url "$URL/bob-bkt")" "STATUS=200"
check_eq "alice uploads" \
    "$(req $A1 $A1S --method PUT --url "$URL/alice-bkt/secret.txt" --body "alice only")" \
    "STATUS=200"
check_eq "alice reads her object" \
    "$(req $A1 $A1S --method GET --url "$URL/alice-bkt/secret.txt")" "STATUS=200"

check_eq "bob: GET alice's object → 403" \
    "$(req $B $BS --method GET --url "$URL/alice-bkt/secret.txt")" "STATUS=403"
check_eq "bob: HEAD alice's object → 403" \
    "$(req $B $BS --method HEAD --url "$URL/alice-bkt/secret.txt")" "STATUS=403"
check_eq "bob: PUT into alice's bucket → 403" \
    "$(req $B $BS --method PUT --url "$URL/alice-bkt/x" --body "x")" "STATUS=403"
check_eq "bob: DELETE alice's object → 403" \
    "$(req $B $BS --method DELETE --url "$URL/alice-bkt/secret.txt")" "STATUS=403"
check_eq "bob: list alice's bucket → 403" \
    "$(req $B $BS --method GET --url "$URL/alice-bkt")" "STATUS=403"
check_eq "bob: HEAD alice's bucket → 403" \
    "$(req $B $BS --method HEAD --url "$URL/alice-bkt")" "STATUS=403"
check_eq "bob: DELETE alice's bucket → 403" \
    "$(req $B $BS --method DELETE --url "$URL/alice-bkt")" "STATUS=403"
check_eq "bob: GET ?acl on alice's bucket → 403" \
    "$(req $B $BS --method GET --url "$URL/alice-bkt?acl")" "STATUS=403"
check_eq "bob: start multipart upload in alice's bucket → 403" \
    "$(req $B $BS --method POST --url "$URL/alice-bkt/big?uploads")" "STATUS=403"
check_eq "bob: bulk delete in alice's bucket → 403" \
    "$(req $B $BS --method POST --url "$URL/alice-bkt?delete" \
        --body '<Delete><Object><Key>secret.txt</Key></Object></Delete>')" \
    "STATUS=403"
check_eq "bob: create a bucket named like alice's → 409" \
    "$(req $B $BS --method PUT --url "$URL/alice-bkt")" "STATUS=409"
check_eq "bob: missing bucket is still 404" \
    "$(req $B $BS --method GET --url "$URL/no-such-bkt")" "STATUS=404"
check_eq "alice's object survived all of that" \
    "$(req $A1 $A1S --method GET --url "$URL/alice-bkt/secret.txt")" "STATUS=200"

# ===================================================================
# 2. Shared user, and a key that is its own identity
# ===================================================================
check_eq "alice's second key reaches her bucket" \
    "$(req $A2 $A2S --method GET --url "$URL/alice-bkt/secret.txt")" "STATUS=200"
check_eq "carol (no user) creates a bucket" \
    "$(req $C $CS --method PUT --url "$URL/carol-bkt")" "STATUS=200"
check_eq "carol reaches it" \
    "$(req $C $CS --method GET --url "$URL/carol-bkt")" "STATUS=200"
check_eq "alice can't reach carol's" \
    "$(req $A1 $A1S --method GET --url "$URL/carol-bkt")" "STATUS=403"

# ===================================================================
# 3. ListAllMyBuckets
# ===================================================================
out=$(req_body $A1 $A1S --method GET --url "$URL/")
check_has   "alice lists her bucket" "$out" "<Name>alice-bkt</Name>"
check_lacks "alice doesn't see bob's" "$out" "<Name>bob-bkt</Name>"
check_lacks "alice doesn't see carol's" "$out" "<Name>carol-bkt</Name>"
out=$(req_body $B $BS --method GET --url "$URL/")
check_has   "bob lists his bucket" "$out" "<Name>bob-bkt</Name>"
check_lacks "bob doesn't see alice's" "$out" "<Name>alice-bkt</Name>"
out=$(req_body $R $RS --method GET --url "$URL/")
check_has "admin sees alice's" "$out" "<Name>alice-bkt</Name>"
check_has "admin sees bob's"   "$out" "<Name>bob-bkt</Name>"
check_has "admin sees carol's" "$out" "<Name>carol-bkt</Name>"

# ===================================================================
# 4. Server-side copy checks both ends
# ===================================================================
check_eq "bob: copy alice's object into his bucket → 403" \
    "$(req $B $BS --method PUT --url "$URL/bob-bkt/stolen" \
        --header "x-amz-copy-source:/alice-bkt/secret.txt")" "STATUS=403"
check_eq "nothing was copied" \
    "$(req $B $BS --method GET --url "$URL/bob-bkt/stolen")" "STATUS=404"
check_eq "alice: copy into bob's bucket → 403" \
    "$(req $A1 $A1S --method PUT --url "$URL/bob-bkt/gift" \
        --header "x-amz-copy-source:/alice-bkt/secret.txt")" "STATUS=403"
check_eq "alice: copy within her own bucket → 200" \
    "$(req $A1 $A1S --method PUT --url "$URL/alice-bkt/copy.txt" \
        --header "x-amz-copy-source:/alice-bkt/secret.txt")" "STATUS=200"

# ===================================================================
# 5. Admin
# ===================================================================
check_eq "admin reads alice's object" \
    "$(req $R $RS --method GET --url "$URL/alice-bkt/secret.txt")" "STATUS=200"
check_eq "admin deletes bob's (empty) bucket" \
    "$(req $R $RS --method DELETE --url "$URL/bob-bkt")" "STATUS=204"

# ===================================================================
# 6. Key rotation keeps the user's buckets
# ===================================================================
A3=AKIAALICE0000000003; A3S=alicesecret00000000000000000000003
write_creds "$A3" "$A3S"            # alice's first key replaced
kill -HUP "$SP"
sleep 1.5
check_eq "old key revoked" \
    "$(req $A1 $A1S --method GET --url "$URL/alice-bkt/secret.txt")" "STATUS=403"
check_eq "new key reaches alice's existing bucket" \
    "$(req $A3 $A3S --method GET --url "$URL/alice-bkt/secret.txt")" "STATUS=200"
stop_server

# ===================================================================
# 7. Ownerless (pre-isolation) buckets
# ===================================================================
mkdir -p "$DATA/buckets/oldbkt" "$DATA/data/oldbkt"   # bare marker = legacy
start_server --credentials-file "$CRED_FILE" --require-auth --admin root
grep -q "1 bucket(s) have no owner" "$LOG" && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: no startup warning about ownerless buckets\n'; }
printf '.'
check_eq "ownerless: alice → 403" \
    "$(req $A3 $A3S --method GET --url "$URL/oldbkt")" "STATUS=403"
check_eq "ownerless: can't be claimed by creating it" \
    "$(req $A3 $A3S --method PUT --url "$URL/oldbkt")" "STATUS=409"
check_eq "ownerless: admin → 200" \
    "$(req $R $RS --method GET --url "$URL/oldbkt")" "STATUS=200"
stop_server

start_server --credentials-file "$CRED_FILE" --require-auth --admin root \
             --legacy-owner alice
grep -q "assigned 1 ownerless bucket(s) to 'alice'" "$LOG" && PASS=$((PASS+1)) || \
    { FAIL=$((FAIL+1)); printf '\nFAIL: no --legacy-owner log line\n'; }
printf '.'
check_eq "--legacy-owner: alice → 200" \
    "$(req $A3 $A3S --method GET --url "$URL/oldbkt")" "STATUS=200"
check_eq "--legacy-owner: bob still → 403" \
    "$(req $B $BS --method GET --url "$URL/oldbkt")" "STATUS=403"
stop_server

# ===================================================================
# 8. Anonymous requests when auth is configured but not required
# ===================================================================
start_server --credentials-file "$CRED_FILE"
check_eq "anonymous: list alice's bucket → 403" \
    "$(curl -s -o /dev/null -w 'STATUS=%{http_code}' "$URL/alice-bkt")" "STATUS=403"
check_eq "anonymous: create bucket → 403" \
    "$(curl -s -o /dev/null -w 'STATUS=%{http_code}' -X PUT "$URL/anon-bkt")" "STATUS=403"
check_eq "anonymous: ListAllMyBuckets → 403" \
    "$(curl -s -o /dev/null -w 'STATUS=%{http_code}' "$URL/")" "STATUS=403"
check_eq "anonymous: /_health still 200" \
    "$(curl -s -o /dev/null -w 'STATUS=%{http_code}' "$URL/_health")" "STATUS=200"
check_eq "signed requests still work here" \
    "$(req $A3 $A3S --method GET --url "$URL/alice-bkt/secret.txt")" "STATUS=200"
stop_server

printf '\n===== isolation e2e: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
