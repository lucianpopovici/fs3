#!/usr/bin/env bash
#
# tests/test_e2e_admin.sh — item 11: /v1 admin API (bearer token on the
# localhost metrics port, Unix socket with peer-uid check), key
# create/delete with live reload, bucket owner and grants.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 23300 + RANDOM % 300 ))}
MPORT=$((PORT + 1))
DATA=/tmp/fs3-adm-e2e-$$
LOG=/tmp/fs3-adm-e2e-$$.log
T=/tmp/fs3-adm-$$
URL="http://127.0.0.1:$PORT"
AURL="http://127.0.0.1:$MPORT"
SOCK=$T.sock
AK=AKIAADMINTEST001
SK=adminTestSecret01234567890123456789012345

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; [ $? -ne 159 ] || echo "FAIL: server died with SIGSYS (seccomp blocked a syscall; see --seccomp=log)" >&2; } || true
    rm -rf "$DATA" "$LOG" "$T".*
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

printf '%s:%s:alice\n' "$AK" "$SK" > "$T.creds"
TOKEN=admintoken-0123456789abcdef
printf '%s\n' "$TOKEN" > "$T.token"

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}

# Token file permissions are enforced.
chmod 0644 "$T.token"
if ${FS3_WRAP:-} "$ROOT/fs3" -p "$PORT" -d "$DATA" --credentials-file "$T.creds" \
       --metrics-port "$MPORT" --admin-token-file "$T.token" >"$LOG" 2>&1 & then
    sleep 0.4
fi
check_eq "0644 token file refused" "$(grep -c 'mode 0600' "$LOG" || true)" "1"
chmod 0600 "$T.token"

${FS3_WRAP:-} "$ROOT/fs3" -p "$PORT" -d "$DATA" --credentials-file "$T.creds" --require-auth \
    --metrics-port "$MPORT" --admin-token-file "$T.token" --admin-socket "$SOCK" >"$LOG" 2>&1 &
SP=$!
sleep 0.4
kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }

adm() { curl -sS -H "Authorization: Bearer $TOKEN" "$@"; }
acode() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }
s3() {
    python3 - "$@" <<'PY'
import sys, boto3, botocore
url, ak, sk, cmd = sys.argv[1:5]
s3 = boto3.client("s3", endpoint_url=url, aws_access_key_id=ak, aws_secret_access_key=sk,
                  region_name="us-east-1")
try:
    if cmd == "mk": s3.create_bucket(Bucket=sys.argv[5])
    elif cmd == "ls": s3.list_buckets()
    elif cmd == "get": s3.list_objects_v2(Bucket=sys.argv[5])
    print("ok")
except botocore.exceptions.ClientError as e:
    print(e.response["Error"]["Code"])
PY
}

check_eq "no token → 401" "$(acode "$AURL/v1/keys")" "401"
sleep 1.2
check_eq "wrong token → 401" "$(acode -H 'Authorization: Bearer nope' "$AURL/v1/keys")" "401"
check_eq "retry inside backoff → 429" "$(acode -H "Authorization: Bearer $TOKEN" "$AURL/v1/keys")" "429"
sleep 2.2
check_eq "Origin header refused" \
    "$(acode -H "Authorization: Bearer $TOKEN" -H 'Origin: http://evil.example' "$AURL/v1/keys")" "403"
check_eq "non-loopback Host refused" \
    "$(acode -H "Authorization: Bearer $TOKEN" -H 'Host: attacker.example' "$AURL/v1/keys")" "403"
check_eq "list keys" "$(adm "$AURL/v1/keys" | python3 -c 'import sys,json; print([k["user"] for k in json.load(sys.stdin)["keys"]])')" "['alice']"
case "$(adm "$AURL/v1/keys")" in *"$SK"*) leak=yes ;; *) leak=no ;; esac
check_eq "secrets never listed" "$leak" "no"
check_eq "metrics still unauthenticated" "$(acode "$AURL/metrics")" "200"

# Create a key → immediately usable.
out=$(adm -X POST -d '{"user":"bob"}' "$AURL/v1/keys")
NAK=$(echo "$out" | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_key"])')
NSK=$(echo "$out" | python3 -c 'import sys,json; print(json.load(sys.stdin)["secret_key"])')
check_eq "new key works at once" "$(s3 "$URL" "$NAK" "$NSK" mk bobbucket)" "ok"
check_eq "file mode stays 0600" "$(stat -c %a "$T.creds")" "600"
check_eq "bad user name rejected" "$(acode -H "Authorization: Bearer $TOKEN" -X POST -d '{"user":"x:y\nroot"}' "$AURL/v1/keys")" "400"
check_eq "malformed JSON rejected" "$(acode -H "Authorization: Bearer $TOKEN" -X POST -d '{"user":' "$AURL/v1/keys")" "400"
check_eq "duplicate JSON keys rejected" "$(acode -H "Authorization: Bearer $TOKEN" -X POST -d '{"user":"a","user":"b"}' "$AURL/v1/keys")" "400"

# Buckets, owner, grants.
check_eq "alice creates a bucket" "$(s3 "$URL" "$AK" "$SK" mk alicebkt)" "ok"
check_eq "bob can't list alice's bucket" "$(s3 "$URL" "$NAK" "$NSK" get alicebkt)" "AccessDenied"
check_eq "grant bob r" "$(adm -X PUT -d '{"perms":"r"}' "$AURL/v1/buckets/alicebkt/grants/bob")" '{"ok":true}'
check_eq "grant visible without restart" "$(s3 "$URL" "$NAK" "$NSK" get alicebkt)" "ok"
check_eq "bucket detail shows grant" \
    "$(adm "$AURL/v1/buckets/alicebkt" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["owner"], d["grants"], d["versioning"])')" \
    "alice {'bob': 'r'} Unset"
check_eq "bad perms rejected" "$(acode -H "Authorization: Bearer $TOKEN" -X PUT -d '{"perms":"rx"}' "$AURL/v1/buckets/alicebkt/grants/bob")" "400"
check_eq "revoke grant" "$(adm -X DELETE "$AURL/v1/buckets/alicebkt/grants/bob")" '{"ok":true}'
check_eq "revoked at once" "$(s3 "$URL" "$NAK" "$NSK" get alicebkt)" "AccessDenied"
check_eq "set owner" "$(adm -X PUT -d '{"owner":"bob"}' "$AURL/v1/buckets/alicebkt/owner")" '{"ok":true}'
check_eq "new owner can list" "$(s3 "$URL" "$NAK" "$NSK" get alicebkt)" "ok"
check_eq "list buckets" "$(adm "$AURL/v1/buckets" | python3 -c 'import sys,json; print(sorted(b["name"] for b in json.load(sys.stdin)["buckets"]))')" "['alicebkt', 'bobbucket']"
check_eq "unknown bucket → 404" "$(acode -H "Authorization: Bearer $TOKEN" "$AURL/v1/buckets/nosuch")" "404"

# Delete the key → refused on the next request.
check_eq "delete key" "$(adm -X DELETE "$AURL/v1/keys/$NAK")" '{"deleted":true}'
check_eq "deleted key → 403" "$(s3 "$URL" "$NAK" "$NSK" ls)" "AccessDenied"
check_eq "deleting the last key refused" "$(acode -H "Authorization: Bearer $TOKEN" -X DELETE "$AURL/v1/keys/$AK")" "409"
check_eq "deleting unknown key → 404" "$(acode -H "Authorization: Bearer $TOKEN" -X DELETE "$AURL/v1/keys/FS3NOPE")" "404"

# Unix socket: authenticated by peer uid, no token needed.
check_eq "socket mode 0600" "$(stat -c %a "$SOCK")" "600"
check_eq "UDS list keys without token" \
    "$(curl -sS --unix-socket "$SOCK" http://x/v1/keys | python3 -c 'import sys,json; print(len(json.load(sys.stdin)["keys"]))')" "1"
check_eq "UDS serves only /v1" "$(curl -sS -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" http://x/metrics)" "404"

# Object listing and presigned URLs (the DSM tile's object browser).
uds() { curl -sS --unix-socket "$SOCK" "$@"; }
ucode() { curl -sS -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" "$@"; }
check_eq "browser bucket" "$(s3 "$URL" "$AK" "$SK" mk brws)" "ok"
pre() { uds -X POST --data "$1" http://x/v1/buckets/brws/presign; }
pcode() { ucode -X POST --data "$1" http://x/v1/buckets/brws/presign; }
H="127.0.0.1:$PORT"
u=$(pre '{"key":"d/k 1.txt","method":"PUT","host":"'$H'"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["url"])')
check_eq "presigned PUT works" "$(printf 'abc' | curl -s -o /dev/null -w '%{http_code}' -X PUT --data-binary @- "$u")" "200"
u=$(pre '{"key_enc":"d/k%201.txt","host":"'$H'"}' | python3 -c 'import sys,json; print(json.load(sys.stdin)["url"])')
check_eq "presigned GET via key_enc" "$(curl -s "$u")" "abc"
check_eq "listing (json)" "$(uds "http://x/v1/buckets/brws/objects" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["prefixes"], d["truncated"])')" "['d/'] False"
check_eq "listing (tsv, encoded)" "$(uds "http://x/v1/buckets/brws/objects?prefix=d/&format=tsv" | cut -f1,2,5 | tr '\t\n' ' ')" "T 0 O 3 d/k%201.txt "
check_eq "listing: bad max" "$(ucode "http://x/v1/buckets/brws/objects?max=0")" "400"
check_eq "listing: bad delimiter" "$(ucode "http://x/v1/buckets/brws/objects?delimiter=x")" "400"
check_eq "listing: bad escape" "$(ucode "http://x/v1/buckets/brws/objects?prefix=%zz")" "400"
check_eq "listing: unknown bucket" "$(ucode "http://x/v1/buckets/nope/objects")" "404"
check_eq "listing: POST refused" "$(ucode -X POST "http://x/v1/buckets/brws/objects")" "405"
check_eq "presign: bad host" "$(pcode '{"key":"a","host":"h/x"}')" "400"
check_eq "presign: no host" "$(pcode '{"key":"a"}')" "400"
check_eq "presign: bad method" "$(pcode '{"key":"a","host":"'$H'","method":"POST"}')" "400"
check_eq "presign: bad scheme" "$(pcode '{"key":"a","host":"'$H'","scheme":"ftp"}')" "400"
check_eq "presign: bad key_enc" "$(pcode '{"key_enc":"a%2","host":"'$H'"}')" "400"
check_eq "presign: key_enc with raw space" "$(pcode '{"key_enc":"a b","host":"'$H'"}')" "400"
check_eq "presign: over --presign-max-expires" "$(pcode '{"key":"a","host":"'$H'","expires":604800}')" "400"
check_eq "presign: GET via admin" "$(ucode -X GET http://x/v1/buckets/brws/presign)" "405"
uds -X PUT --data '{"owner":"ghost"}' http://x/v1/buckets/brws/owner >/dev/null
check_eq "presign: owner has no key and there is no admin → 409" \
    "$(pcode '{"key":"a","host":"'$H'"}')" "409"
check_eq "presign audited" "$(grep -c 'admin: presign PUT bucket brws key d/k%201.txt' "$LOG" || true)" "1"

echo
echo "===== admin e2e: $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
