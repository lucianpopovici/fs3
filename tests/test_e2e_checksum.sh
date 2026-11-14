#!/usr/bin/env bash
#
# tests/test_e2e_checksum.sh — item 1: trailer-variant chunked SigV4 and
# x-amz-checksum-* (CRC32, CRC32C, SHA1, SHA256, CRC64NVME), with boto3
# in its default checksum configuration as the oracle.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 21200 + RANDOM % 400 ))}
DATA=/tmp/fs3-ck-e2e-$$
LOG=/tmp/fs3-ck-e2e-$$.log
URL="http://127.0.0.1:$PORT"
T=/tmp/fs3-ck-$$
AK=AKIACHECKSUM0001
SK=checksumSecret0123456789012345678901234567

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; [ $? -ne 159 ] || echo "FAIL: server died with SIGSYS (seccomp blocked a syscall; see --seccomp=log)" >&2; } || true
    [ -n "${SP2:-}" ] && kill "$SP2" 2>/dev/null || true
    rm -rf "$DATA" "$DATA-open" "$LOG" "$T".*
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

${FS3_WRAP:-} "$ROOT/fs3" -p "$PORT" -d "$DATA" --auth "$AK:$SK" --require-auth >"$LOG" 2>&1 &
SP=$!
sleep 0.4
kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }

export FS3_URL="$URL" FS3_AK="$AK" FS3_SK="$SK"
unset AWS_REQUEST_CHECKSUM_CALCULATION AWS_RESPONSE_CHECKSUM_VALIDATION || true
boto() { python3 "$ROOT/tests/boto_checksum.py" "$@" 2>&1 | tail -1; }
trailer() { python3 "$ROOT/tests/sign_trailer.py" "$@"; }

PASS=0; FAIL=0; SKIP=0
# boto3's CRC32C / CRC64NVME need the awscrt wheel. Without it those
# client-side cases are skipped (visibly); FS3_TEST_STRICT=1 (CI) makes a
# skip a failure. The server paths are still covered by the hand-framed
# trailer cases below, which compute the digests in pure Python.
HAVE_CRT=1
python3 -c "import awscrt" 2>/dev/null || HAVE_CRT=0
[ "${FS3_TEST_NO_CRT:-0}" = 1 ] && HAVE_CRT=0     # exercise the skip path
needs_crt() {   # name algo → 0 to run the case, 1 to skip it
    case "$2" in CRC32C|CRC64NVME) ;; *) return 0 ;; esac
    [ "$HAVE_CRT" = 1 ] && return 0
    if [ "${FS3_TEST_STRICT:-0}" = 1 ]; then
        FAIL=$((FAIL+1)); printf '\nFAIL: %s (awscrt missing, FS3_TEST_STRICT=1)\n' "$1"
    else
        SKIP=$((SKIP+1)); printf 's'
    fi
    return 1
}
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}
status_of() { echo "$1" | head -1; }
objfile() { find "$DATA/data/ckb" -type f 2>/dev/null | wc -l | tr -d ' '; }

python3 - <<PY
import boto3, os
s3 = boto3.client("s3", endpoint_url="$URL", aws_access_key_id="$AK",
                  aws_secret_access_key="$SK", region_name="us-east-1")
s3.create_bucket(Bucket="ckb")
PY

printf 'hello checksum world\n' > "$T.small"
head -c 300000 /dev/urandom > "$T.mid"
head -c 17000000 /dev/urandom > "$T.big"

# ---- boto3 default config (no env override) -------------------------------
check_eq "boto3 put_object default" "$(boto put ckb small "$T.small")" "200"
check_eq "boto3 get round-trip" "$(python3 "$ROOT/tests/boto_checksum.py" get ckb small | md5sum)" "$(md5sum < "$T.small")"
hc=$(boto head-checksum ckb small)
case "$hc" in ChecksumCRC32=*|ChecksumCRC64NVME=*|ChecksumCRC32C=*) ok=yes ;; *) ok="no:$hc" ;; esac
check_eq "head-object --checksum-mode ENABLED returns checksum" "$ok" "yes"
for a in CRC32 CRC32C SHA1 SHA256 CRC64NVME; do
    needs_crt "boto3 put_object $a" "$a" || continue
    check_eq "put_object $a" "$(boto put ckb "obj-$a" "$T.mid" "$a")" "200"
    hc=$(boto head-checksum ckb "obj-$a")
    case "$hc" in *"Checksum$a="*) ok=yes ;; *) ok="no:$hc" ;; esac
    check_eq "head $a checksum round-trip" "$ok" "yes"
done

# Multipart via upload_file (17 MB, 5 MB parts), default config.
check_eq "upload_file multipart default" "$(boto upload ckb big "$T.big")" "ok"
check_eq "download multipart" "$(boto download ckb big "$T.big.dl")" "ok"
check_eq "multipart bytes" "$(md5sum < "$T.big.dl")" "$(md5sum < "$T.big")"
for a in CRC32 SHA256 CRC64NVME; do
    needs_crt "boto3 upload_file $a" "$a" || continue
    check_eq "upload_file multipart $a" "$(boto upload ckb "big-$a" "$T.big" "$a")" "ok"
    hc=$(boto head-checksum ckb "big-$a")
    case "$hc" in *"Checksum$a="*) ok=yes ;; *) ok="no:$hc" ;; esac
    check_eq "multipart $a checksum stored" "$ok" "yes"
done

# AWS CLI, default settings: 100 MB cp up and down, checksum round-trip.
if command -v aws >/dev/null 2>&1; then
    head -c 104857600 /dev/urandom > "$T.100m"
    export AWS_ACCESS_KEY_ID="$AK" AWS_SECRET_ACCESS_KEY="$SK" AWS_DEFAULT_REGION=us-east-1
    aws --endpoint-url "$URL" s3 cp "$T.100m" s3://ckb/cli100m >/dev/null 2>&1 && r=ok || r=fail
    check_eq "aws s3 cp 100 MB up" "$r" "ok"
    aws --endpoint-url "$URL" s3 cp s3://ckb/cli100m "$T.100m.dl" >/dev/null 2>&1 && r=ok || r=fail
    check_eq "aws s3 cp 100 MB down" "$r" "ok"
    check_eq "aws s3 cp bytes" "$(md5sum < "$T.100m.dl")" "$(md5sum < "$T.100m")"
    hc=$(aws --endpoint-url "$URL" s3api head-object --bucket ckb --key cli100m \
         --checksum-mode ENABLED 2>&1)
    case "$hc" in *'"Checksum'*) ok=yes ;; *) ok="no:$hc" ;; esac
    check_eq "aws head-object --checksum-mode ENABLED" "$ok" "yes"
    rm -f "$T.100m" "$T.100m.dl"
fi

# DeleteObjects carries a body checksum under the default config.
check_eq "delete_objects with checksum" "$(boto delete-objects ckb obj-SHA1 obj-SHA256)" "2"

# ---- Trailer variants, hand-framed ----------------------------------------
n0=$(objfile)
for mode in unsigned signed; do
    for a in crc32 crc32c sha256 sha1 crc64nvme; do
        out=$(trailer --url "$URL/ckb/t-$mode-$a" --mode "$mode" --algo "$a" \
              --body-file "$T.mid" --chunk-size 65536)
        check_eq "$mode trailer $a PUT" "$(status_of "$out")" "STATUS=200"
        case "$out" in *"x-amz-checksum-$a"*) ok=yes ;; *) ok=no ;; esac
        check_eq "$mode trailer $a echoed" "$ok" "yes"
    done
    out=$(trailer --url "$URL/ckb/split-$mode" --mode "$mode" --body-file "$T.small" \
          --chunk-size 7 --split 3)
    check_eq "$mode trailer split across feeds" "$(status_of "$out")" "STATUS=200"
done
check_eq "trailer body stored decoded" \
    "$(python3 "$ROOT/tests/boto_checksum.py" get ckb t-signed-crc32 | md5sum)" "$(md5sum < "$T.mid")"
n1=$(objfile)

for mode in unsigned signed; do
    out=$(trailer --url "$URL/ckb/bad-$mode" --mode "$mode" --body-file "$T.mid" --malform bad-cksum)
    check_eq "$mode corrupted trailer → 400" "$(status_of "$out")" "STATUS=400"
    case "$out" in *BadDigest*) ok=yes ;; *) ok=no ;; esac
    check_eq "$mode corrupted trailer is BadDigest" "$ok" "yes"
    out=$(trailer --url "$URL/ckb/bad-$mode" --mode "$mode" --body-file "$T.small" --malform no-final-crlf)
    check_eq "$mode missing final CRLF → 4xx" "$(status_of "$out" | cut -c1-8)" "STATUS=4"
    out=$(trailer --url "$URL/ckb/bad-$mode" --mode "$mode" --body-file "$T.small" --malform unannounced)
    check_eq "$mode unannounced trailer → 4xx" "$(status_of "$out" | cut -c1-8)" "STATUS=4"
    out=$(trailer --url "$URL/ckb/bad-$mode" --mode "$mode" --body-file "$T.small" --malform no-trailer)
    check_eq "$mode announced trailer missing → 4xx" "$(status_of "$out" | cut -c1-8)" "STATUS=4"
    out=$(trailer --url "$URL/ckb/bad-$mode" --mode "$mode" --body-file "$T.small" --malform long-trailer)
    check_eq "$mode oversize trailer line → 4xx" "$(status_of "$out" | cut -c1-8)" "STATUS=4"
done
out=$(trailer --url "$URL/ckb/bad-sig" --mode signed --body-file "$T.small" --malform bad-trailer-sig)
check_eq "bad trailer signature → 403" "$(status_of "$out")" "STATUS=403"
check_eq "nothing on disk after failures" "$(objfile)" "$n1"
check_eq "bad-* keys absent" "$(curl -s -o /dev/null -w '%{http_code}' "$URL/ckb/bad-unsigned")" "403"

# Header-mode checksum mismatch, and malformed checksum header.
python3 - "$URL" "$AK" "$SK" > "$T.hdr" <<'PY'
import sys, base64, zlib
import botocore.session
from botocore.awsrequest import AWSRequest
from botocore.auth import S3SigV4Auth
import urllib.request
url, ak, sk = sys.argv[1:4]
creds = botocore.session.get_session().get_credentials() if False else None
from botocore.credentials import Credentials
creds = Credentials(ak, sk)
def put(key, body, hdrs):
    req = AWSRequest(method="PUT", url=f"{url}/ckb/{key}", data=body, headers=hdrs)
    req.headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD"
    S3SigV4Auth(creds, "s3", "us-east-1").add_auth(req)
    r = urllib.request.Request(req.url, data=body, method="PUT", headers=dict(req.headers))
    try:
        return urllib.request.urlopen(r).status
    except urllib.error.HTTPError as e:
        return e.code
good = base64.b64encode((zlib.crc32(b"abc") & 0xffffffff).to_bytes(4, "big")).decode()
bad = base64.b64encode(((zlib.crc32(b"abc") ^ 1) & 0xffffffff).to_bytes(4, "big")).decode()
print(put("h-good", b"abc", {"x-amz-checksum-crc32": good}))
print(put("h-bad", b"abc", {"x-amz-checksum-crc32": bad}))
print(put("h-malformed", b"abc", {"x-amz-checksum-crc32": "!!!"}))
print(put("h-two", b"abc", {"x-amz-checksum-crc32": good, "x-amz-checksum-sha1": "AAAA"}))
import hashlib
md5 = base64.b64encode(hashlib.md5(b"abc").digest()).decode()
print(put("m-good", b"abc", {"Content-MD5": md5}))
print(put("m-bad", b"abd", {"Content-MD5": md5}))
PY
check_eq "header crc32 good" "$(sed -n 1p "$T.hdr")" "200"
check_eq "header crc32 mismatch → 400" "$(sed -n 2p "$T.hdr")" "400"
check_eq "header crc32 malformed → 400" "$(sed -n 3p "$T.hdr")" "400"
check_eq "two checksum headers → 400" "$(sed -n 4p "$T.hdr")" "400"
check_eq "Content-MD5 good" "$(sed -n 5p "$T.hdr")" "200"
check_eq "Content-MD5 mismatch → 400" "$(sed -n 6p "$T.hdr")" "400"

# Ranged GET never carries the full-object checksum.
python3 - "$URL" "$AK" "$SK" > "$T.rng" <<'PY'
import sys, boto3
s3 = boto3.client("s3", endpoint_url=sys.argv[1], aws_access_key_id=sys.argv[2],
                  aws_secret_access_key=sys.argv[3], region_name="us-east-1")
r = s3.get_object(Bucket="ckb", Key="obj-CRC32", Range="bytes=0-9", ChecksumMode="ENABLED")
print("ChecksumCRC32" in r)
from botocore.config import Config
s3n = boto3.client("s3", endpoint_url=sys.argv[1], aws_access_key_id=sys.argv[2],
                   aws_secret_access_key=sys.argv[3], region_name="us-east-1",
                   config=Config(response_checksum_validation="when_required"))
r = s3n.get_object(Bucket="ckb", Key="obj-CRC32")
print("ChecksumCRC32" in r)
PY
check_eq "ranged GET: no checksum" "$(sed -n 1p "$T.rng")" "False"
check_eq "GET without checksum-mode: no checksum" "$(sed -n 2p "$T.rng")" "False"

# ---- Open mode: aws-chunked framing is still decoded ----------------------
OPORT=$((PORT + 1))
${FS3_WRAP:-} "$ROOT/fs3" -p "$OPORT" -d "$DATA-open" >"$LOG.open" 2>&1 &
SP2=$!
sleep 0.4
curl -s -X PUT "http://127.0.0.1:$OPORT/openb" >/dev/null
out=$(trailer --url "http://127.0.0.1:$OPORT/openb/u" --mode unsigned --no-auth --body-file "$T.small")
check_eq "open mode unsigned trailer PUT" "$(status_of "$out")" "STATUS=200"
check_eq "open mode body decoded" "$(curl -s "http://127.0.0.1:$OPORT/openb/u" | md5sum)" "$(md5sum < "$T.small")"

echo
if [ "$SKIP" -gt 0 ]; then
    echo "===== checksum e2e: $PASS passed, $FAIL failed, $SKIP SKIP (awscrt missing: pip install -r tests/requirements.txt) ====="
else
    echo "===== checksum e2e: $PASS passed, $FAIL failed ====="
fi
[ "$FAIL" -eq 0 ]
