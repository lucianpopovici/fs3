#!/usr/bin/env bash
#
# tests/test_e2e_identity.sh — end-to-end tests for brief 12a
# (DSM identity binding: per-user bucket ownership + authorization).
#
# Starts ./fs3 with a v2 credentials file (--identity-mode
# --require-auth), then exercises the authorization matrix from
# docs/synology-readiness/12-dsm-identity-binding/CLAUDE.md's 12a test
# list: a non-owner gets 403 on every operation against someone else's
# bucket, CopyObject is checked in both directions, ListAllMyBuckets is
# filtered per principal, admin bypasses ownership, and a legacy
# (pre-identity-mode) bucket is admin-only.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 19970 + RANDOM % 100 ))}
DATA=/tmp/fs3-identity-e2e-$$
LOG=/tmp/fs3-identity-e2e-$$.log
URL="http://127.0.0.1:$PORT"
CRED_FILE=/tmp/fs3-identity-creds-$$

ALICE_AK="AKIAALICE0000000001"
ALICE_SK="alicesecretkey00000000000000000001"
BOB_AK="AKIABOB000000000001"
BOB_SK="bobsecretkey0000000000000000000001"
ADMIN_AK="AKIAADMIN000000000A"
ADMIN_SK="adminsecretkey0000000000000000001"

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; }
    rm -rf "$DATA"
    rm -f "$CRED_FILE" /tmp/fs3-identity-$$.*
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1) || {
    echo "build failed" >&2
    (cd "$ROOT" && make $BUILD_FLAGS fs3 2>&1 | tail -10) >&2
    exit 1
}

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

write_v2_cred_file() {
    printf '#fs3-credentials v2\n' > "$CRED_FILE"
    printf '%s\talice\t1700000000000\ttest\t%s\n' "$ALICE_AK" "$ALICE_SK" >> "$CRED_FILE"
    printf '%s\tbob\t1700000000001\ttest\t%s\n'   "$BOB_AK"   "$BOB_SK"   >> "$CRED_FILE"
    printf '%s\t\t1700000000002\ttest\t%s\n'      "$ADMIN_AK" "$ADMIN_SK" >> "$CRED_FILE"
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
# 1. --identity-mode without --require-auth refuses to start
# ===================================================================
write_v2_cred_file
rm -rf "$DATA"; mkdir -p "$DATA"
# `timeout` guards against a regression that would start the server and
# block forever instead of refusing to start; distinguish that (124)
# from a clean non-zero refusal so a hang is reported as a failure, not
# accidentally scored as a pass.
rc=0
timeout 2 "$ROOT/fs3" -p "$PORT" -d "$DATA" --credentials-file "$CRED_FILE" \
    --identity-mode >/tmp/fs3-identity-$$.badstart 2>&1 || rc=$?
if [ "$rc" -eq 124 ]; then
    FAIL=$((FAIL+1))
    printf '\nFAIL: --identity-mode without --require-auth started the server (had to be killed)\n'
elif [ "$rc" -eq 0 ]; then
    FAIL=$((FAIL+1))
    printf '\nFAIL: --identity-mode without --require-auth exited 0\n'
else
    PASS=$((PASS+1)); printf '.'
fi

# ===================================================================
# 2. Bring up the real server: v2 creds, --require-auth --identity-mode
# ===================================================================
start_server --credentials-file "$CRED_FILE" --require-auth --identity-mode

# A legacy (pre-identity-mode) bucket: plain mkdir, no owner file.
mkdir -p "$DATA/buckets/legacy" "$DATA/data/legacy"

# ===================================================================
# 3. Ownership basics
# ===================================================================
st=$(sign "$ALICE_AK" "$ALICE_SK" --method PUT --url "$URL/alice-b")
check_eq "alice creates alice-b" "$st" "STATUS=200"

st=$(sign "$ALICE_AK" "$ALICE_SK" --method PUT --url "$URL/alice-b/k1" \
     --body "hello" --header "Content-Type:text/plain")
check_eq "alice PUTs object into alice-b" "$st" "STATUS=200"

st=$(sign "$BOB_AK" "$BOB_SK" --method PUT --url "$URL/bob-b")
check_eq "bob creates bob-b" "$st" "STATUS=200"

st=$(sign "$BOB_AK" "$BOB_SK" --method PUT --url "$URL/bob-b/k1" \
     --body "from bob" --header "Content-Type:text/plain")
check_eq "bob PUTs object into bob-b" "$st" "STATUS=200"

# ===================================================================
# 4. Bob gets 403 on every operation against alice's bucket
# ===================================================================
st=$(sign "$BOB_AK" "$BOB_SK" --method HEAD --url "$URL/alice-b")
check_eq "bob HEAD alice-b -> 403" "$st" "STATUS=403"

st=$(sign "$BOB_AK" "$BOB_SK" --method GET --url "$URL/alice-b")
check_eq "bob list alice-b -> 403" "$st" "STATUS=403"

st=$(sign "$BOB_AK" "$BOB_SK" --method GET --url "$URL/alice-b/k1")
check_eq "bob GET alice-b/k1 -> 403" "$st" "STATUS=403"

st=$(sign "$BOB_AK" "$BOB_SK" --method PUT --url "$URL/alice-b/k2" \
     --body "intrusion" --header "Content-Type:text/plain")
check_eq "bob PUT alice-b/k2 -> 403" "$st" "STATUS=403"

st=$(sign "$BOB_AK" "$BOB_SK" --method DELETE --url "$URL/alice-b/k1")
check_eq "bob DELETE alice-b/k1 -> 403" "$st" "STATUS=403"

st=$(sign "$BOB_AK" "$BOB_SK" --method DELETE --url "$URL/alice-b")
check_eq "bob DeleteBucket alice-b -> 403" "$st" "STATUS=403"

st=$(sign "$BOB_AK" "$BOB_SK" --method POST --url "$URL/alice-b?delete" \
     --body '<Delete><Object><Key>k1</Key></Object></Delete>' \
     --header "Content-Type:application/xml")
check_eq "bob bulk-delete alice-b -> 403" "$st" "STATUS=403"

st=$(sign "$BOB_AK" "$BOB_SK" --method POST --url "$URL/alice-b/newkey?uploads")
check_eq "bob MPU initiate alice-b -> 403" "$st" "STATUS=403"

st=$(sign "$BOB_AK" "$BOB_SK" --method GET --url "$URL/alice-b?uploads")
check_eq "bob ListMultipartUploads alice-b -> 403" "$st" "STATUS=403"

# ===================================================================
# 5. CopyObject checked in both directions
# ===================================================================
st=$(sign "$BOB_AK" "$BOB_SK" --method PUT --url "$URL/bob-b/copy-from-alice" \
     --header "x-amz-copy-source:/alice-b/k1")
check_eq "bob copy FROM alice-b -> 403" "$st" "STATUS=403"

st=$(sign "$BOB_AK" "$BOB_SK" --method PUT --url "$URL/alice-b/copy-into-alice" \
     --header "x-amz-copy-source:/bob-b/k1")
check_eq "bob copy INTO alice-b -> 403" "$st" "STATUS=403"

# ===================================================================
# 6. ListAllMyBuckets is filtered per principal; admin sees everything
#    including the admin-only legacy bucket
# ===================================================================
out=$(FS3_AK="$ALICE_AK" FS3_SK="$ALICE_SK" \
      python3 "$ROOT/tests/sign_request.py" --method GET --url "$URL/" 2>&1)
body=$(echo "$out" | tail -n +2)
echo "$body" | grep -q '<Name>alice-b</Name>' && { PASS=$((PASS+1)); printf '.'; } \
    || { FAIL=$((FAIL+1)); printf '\nFAIL: alice ListAllMyBuckets missing alice-b\n'; }
echo "$body" | grep -q '<Name>bob-b</Name>' && \
    { FAIL=$((FAIL+1)); printf '\nFAIL: alice ListAllMyBuckets leaked bob-b\n'; } \
    || { PASS=$((PASS+1)); printf '.'; }
echo "$body" | grep -q '<Name>legacy</Name>' && \
    { FAIL=$((FAIL+1)); printf '\nFAIL: alice ListAllMyBuckets leaked admin-only legacy\n'; } \
    || { PASS=$((PASS+1)); printf '.'; }

admin_out=$(FS3_AK="$ADMIN_AK" FS3_SK="$ADMIN_SK" \
      python3 "$ROOT/tests/sign_request.py" --method GET --url "$URL/" 2>&1)
admin_body=$(echo "$admin_out" | tail -n +2)
for name in alice-b bob-b legacy; do
    echo "$admin_body" | grep -q "<Name>$name</Name>" && { PASS=$((PASS+1)); printf '.'; } \
        || { FAIL=$((FAIL+1)); printf '\nFAIL: admin ListAllMyBuckets missing %s\n' "$name"; }
done

# ===================================================================
# 7. Admin bypasses ownership entirely, including on the legacy bucket
# ===================================================================
st=$(sign "$ADMIN_AK" "$ADMIN_SK" --method HEAD --url "$URL/alice-b")
check_eq "admin HEAD alice-b -> 200" "$st" "STATUS=200"

st=$(sign "$ADMIN_AK" "$ADMIN_SK" --method GET --url "$URL/alice-b/k1")
check_eq "admin GET alice-b/k1 -> 200" "$st" "STATUS=200"

st=$(sign "$ADMIN_AK" "$ADMIN_SK" --method HEAD --url "$URL/legacy")
check_eq "admin HEAD legacy -> 200" "$st" "STATUS=200"

st=$(sign "$ADMIN_AK" "$ADMIN_SK" --method DELETE --url "$URL/alice-b/k1")
check_eq "admin DELETE alice-b/k1 -> 200" "$st" "STATUS=204"

st=$(sign "$ADMIN_AK" "$ADMIN_SK" --method DELETE --url "$URL/alice-b")
check_eq "admin DeleteBucket alice-b -> 204" "$st" "STATUS=204"

# ===================================================================
# 8. Alice gets 403 on the admin-only legacy bucket
# ===================================================================
st=$(sign "$ALICE_AK" "$ALICE_SK" --method HEAD --url "$URL/legacy")
check_eq "alice HEAD legacy (admin-only) -> 403" "$st" "STATUS=403"

# ===================================================================
# 9. SIGHUP credential reload racing an in-flight request (ASan/UBSan
#    use-after-free regression). sigv4_verify_principal copies the
#    matched credential's owner into conn_t.principal at verify time
#    (never a pointer into the credential list), so a rotation that
#    lands mid-request must not touch freed memory. This section is
#    most meaningful run under `DEBUG=1` (ASan+UBSan instrumented fs3);
#    it still exercises the race path either way.
# ===================================================================
st=$(sign "$ALICE_AK" "$ALICE_SK" --method PUT --url "$URL/alice-slow")
check_eq "alice creates alice-slow" "$st" "STATUS=200"

coproc SLOWPUT {
    FS3_AK="$ALICE_AK" FS3_SK="$ALICE_SK" \
        python3 "$ROOT/tests/sign_slow_put.py" --port "$PORT" \
        --bucket alice-slow --key bigobj --size 65536
}
read -r pause_line <&"${SLOWPUT[0]}"
if [ "$pause_line" != "PAUSED" ]; then
    FAIL=$((FAIL+1))
    printf '\nFAIL: sign_slow_put.py did not pause as expected (got "%s")\n' "$pause_line"
else
    # Rotate alice's secret while the PUT is paused mid-body, then HUP.
    printf '#fs3-credentials v2\n' > "$CRED_FILE"
    printf '%s\talice\t1700000000000\ttest\trotatedsecretkey000000000000001\n' "$ALICE_AK" >> "$CRED_FILE"
    printf '%s\tbob\t1700000000001\ttest\t%s\n'   "$BOB_AK"   "$BOB_SK"   >> "$CRED_FILE"
    printf '%s\t\t1700000000002\ttest\t%s\n'      "$ADMIN_AK" "$ADMIN_SK" >> "$CRED_FILE"
    kill -HUP "$SP"
    sleep 1.5
    if ! kill -0 "$SP" 2>/dev/null; then
        FAIL=$((FAIL+1))
        printf '\nFAIL: server died on SIGHUP during in-flight request\n'
    fi

    echo "resume" >&"${SLOWPUT[1]}"
    read -r status_line <&"${SLOWPUT[0]}"
    wait "$SLOWPUT_PID" 2>/dev/null || true

    case "$status_line" in
        STATUS=200)
            PASS=$((PASS+1)); printf '.'
            ;;
        *)
            FAIL=$((FAIL+1))
            printf '\nFAIL: slow PUT across SIGHUP got unexpected result: %s\n' "$status_line"
            ;;
    esac
fi

if grep -qE 'AddressSanitizer|UndefinedBehaviorSanitizer' "$LOG"; then
    FAIL=$((FAIL+1))
    printf '\nFAIL: sanitizer report in server log during SIGHUP-race test\n'
    grep -E 'AddressSanitizer|UndefinedBehaviorSanitizer' "$LOG" >&2
else
    PASS=$((PASS+1)); printf '.'
fi

stop_server

printf '\n===== identity e2e: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
