#!/usr/bin/env bash
#
# tests/test_e2e_scrub.sh — round 2 item 3: background integrity scrub.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 27000 + RANDOM % 200 ))}
MPORT=$((PORT + 1))
T=/tmp/fs3-scrub-e2e-$$
DATA=$T.data
LOG=$T.log
SOCK=$T.sock
URL="http://127.0.0.1:$PORT"

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; } || true
    [ -n "${KEEP:-}" ] || rm -rf "$DATA" "$T".*
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

start() {
    "$ROOT/fs3" -p "$PORT" -d "$DATA" --metrics-port "$MPORT" --admin-socket "$SOCK" \
        --mpu-min-part-size 0 --scrub-interval-days 0 --audit-log "$T.audit" "$@" >>"$LOG" 2>&1 &
    SP=$!
    for _ in $(seq 50); do [ -S "$SOCK" ] && curl -s -o /dev/null "$URL/" && break; sleep 0.1; done
    kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }
}
stop() { kill "$SP"; wait "$SP" 2>/dev/null || true; }

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}
st() { curl -sS --unix-socket "$SOCK" http://x/v1/scrub | python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }
run_pass() {   # start a pass and wait for it to finish
    local pass0; pass0=$(st '["pass"]')
    curl -sS --unix-socket "$SOCK" -X POST http://x/v1/scrub >/dev/null
    for _ in $(seq 600); do
        [ "$(st '["running"]')" = "False" ] && [ "$(st '["pass"]')" -gt "$pass0" ] && return 0
        sleep 0.1
    done
    echo "scrub pass did not finish"; exit 1
}
one() { local f; f=$(ls $1 2>/dev/null | head -1); [ -n "$f" ] || { echo "no file for $1"; exit 1; }; echo "$f"; }
flip() {   # flip the byte at offset $2 (negative: from the end) of file $1
    python3 - "$1" "$2" <<'PY'
import sys, os
p, off = sys.argv[1], int(sys.argv[2])
with open(p, "r+b") as f:
    size = os.fstat(f.fileno()).st_size
    o = off if off >= 0 else size + off
    f.seek(o); b = f.read(1); f.seek(o); f.write(bytes([b[0] ^ 0xFF]))
PY
}

start --scrub-rate 0 --scrub-fail-reads

# ---- data set -----------------------------------------------------------------
python3 - "$URL" <<'PY'
import sys, os, boto3, datetime
from botocore.config import Config
s3 = boto3.client("s3", endpoint_url=sys.argv[1], aws_access_key_id="x", aws_secret_access_key="y",
                  region_name="us-east-1", config=Config(signature_version="s3v4"))
for b in ("sgood", "sflip", "strunc", "shdr", "sver", "smpu", "smp"):
    s3.create_bucket(Bucket=b)
s3.put_object(Bucket="sgood", Key="ok", Body=os.urandom(3000))
s3.put_object(Bucket="sflip", Key="k", Body=os.urandom(5000))
s3.put_object(Bucket="strunc", Key="k", Body=os.urandom(5000))
s3.put_object(Bucket="shdr", Key="k", Body=os.urandom(5000))
s3.put_bucket_versioning(Bucket="sver", VersioningConfiguration={"Status": "Enabled"})
s3.put_object(Bucket="sver", Key="k", Body=b"old" * 1000)
s3.put_object(Bucket="sver", Key="k", Body=b"new" * 1000)
u = s3.create_multipart_upload(Bucket="smpu", Key="k")["UploadId"]
s3.upload_part(Bucket="smpu", Key="k", UploadId=u, PartNumber=1, Body=os.urandom(4000))
u = s3.create_multipart_upload(Bucket="smp", Key="k")["UploadId"]
e1 = s3.upload_part(Bucket="smp", Key="k", UploadId=u, PartNumber=1, Body=os.urandom(4000))["ETag"]
e2 = s3.upload_part(Bucket="smp", Key="k", UploadId=u, PartNumber=2, Body=os.urandom(1000))["ETag"]
s3.complete_multipart_upload(Bucket="smp", Key="k", UploadId=u,
    MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": e1}, {"PartNumber": 2, "ETag": e2}]})
s3.create_bucket(Bucket="slock", ObjectLockEnabledForBucket=True)
s3.put_object(Bucket="slock", Key="k", Body=b"locked",
              ObjectLockMode="GOVERNANCE",
              ObjectLockRetainUntilDate=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
PY
# Pre-v4 fixtures: verified by MD5 or unverifiable, never corrupt.
mkdir -p "$DATA/data/sgood/aa/bb"
cp "$ROOT/tests/fixtures/obj_v2_legacy.bin" "$DATA/data/sgood/aa/bb/$(printf 'a%.0s' $(seq 64))"
cp "$ROOT/tests/fixtures/obj_v3.bin" "$DATA/data/sgood/aa/bb/$(printf 'b%.0s' $(seq 64))"

# ---- clean pass ---------------------------------------------------------------------
run_pass
check_eq "clean pass: no corruption" "$(st '["corrupt"]')" "0"
check_eq "clean pass: files seen (9 objects/versions/parts/locks + 2 fixtures)" \
    "$(( $(st '["files"]') >= 11 ))" "1"
check_eq "clean pass: no corrupt.log" "$([ -s "$DATA/scrub/corrupt.log" ] && echo yes || echo no)" "no"
check_eq "clean pass: last_success set" "$(( $(st '["last_success"]') > 0 ))" "1"

# ---- damage ----------------------------------------------------------------------------
flip "$(one "$DATA/data/sflip/*/*/*")" -1                     # payload byte
F=$(one "$DATA/data/strunc/*/*/*"); truncate -s -10 "$F"      # truncated
flip "$(one "$DATA/data/shdr/*/*/*")" 0                       # header magic
flip "$(one "$DATA/versions/sver/*/*/*/*")" -1                # noncurrent version
flip "$(one "$DATA/mpu/smpu/*/part-00001")" 7                 # in-flight part
printf 'garbage\n' > "$(one "$DATA/locks/slock/*/*/*/*")"     # lock record

run_pass
check_eq "6 corrupt files found" "$(st '["corrupt"]')" "6"
check_eq "corrupt.log has 6 records" "$(wc -l < "$DATA/scrub/corrupt.log" | tr -d ' ')" "6"
check_eq "logged: payload crc64 (current + noncurrent)" "$(grep -c '"reason":"payload crc64"' "$DATA/scrub/corrupt.log" || true)" "2"
for r in '"reason":"size"' '"reason":"bad header"' '"reason":"part md5"' \
         '"reason":"unparseable lock record"' '"bucket":"sver"'; do
    check_eq "logged: $r" "$(grep -c "$r" "$DATA/scrub/corrupt.log" || true)" "1"
done
check_eq "log names the key" "$(grep '"bucket":"sflip"' "$DATA/scrub/corrupt.log" | grep -c '"key":"k"' || true)" "1"
check_eq "audit record" "$(grep -c '"who":"scrub"\|scrub.*corrupt' "$T.audit" | awk '{print ($1>=6)}')" "1"
M=$(curl -s "http://127.0.0.1:$MPORT/metrics")
check_eq "fs3_scrub_corrupt_total" "$(echo "$M" | grep '^fs3_scrub_corrupt_total ' | cut -d' ' -f2)" "6"
check_eq "fs3_scrub_objects_total > 0" "$(( $(echo "$M" | grep '^fs3_scrub_objects_total ' | cut -d' ' -f2) > 0 ))" "1"
check_eq "fs3_scrub_unverifiable_total present" "$(echo "$M" | grep -c '^fs3_scrub_unverifiable_total ' || true)" "1"
check_eq "--scrub-fail-reads: corrupt object → 500" "$(curl -s -o /dev/null -w '%{http_code}' "$URL/sflip/k")" "500"
check_eq "good object still 200" "$(curl -s -o /dev/null -w '%{http_code}' "$URL/sgood/ok")" "200"
check_eq "multipart object (combined CRC) verified" "$(grep -c '"bucket":"smp"' "$DATA/scrub/corrupt.log" || true)" "0"
check_eq "nothing deleted" "$(ls "$DATA"/data/sflip/*/*/* | wc -l | tr -d ' ')" "1"
check_eq "current version of sver still readable" "$(curl -s "$URL/sver/k" | head -c 3)" "new"
# Marks survive a restart (reloaded from the log).
stop; start --scrub-rate 0 --scrub-fail-reads
check_eq "fail-reads after restart" "$(curl -s -o /dev/null -w '%{http_code}' "$URL/sflip/k")" "500"
# A rewritten object is a new version: served again.
printf 'fresh' | curl -s -X PUT --data-binary @- "$URL/sflip/k" -o /dev/null
check_eq "rewritten object served" "$(curl -s "$URL/sflip/k")" "fresh"
stop

# ---- replace mid-scrub (slow rate): no false positive -------------------------------
rm -rf "$DATA"; : >"$LOG"
start --scrub-rate 2M
head -c $((6 * 1024 * 1024)) /dev/urandom > "$T.big"
curl -s -X PUT "$URL/sbig" -o /dev/null
curl -s -X PUT --data-binary @"$T.big" "$URL/sbig/big" -o /dev/null
curl -sS --unix-socket "$SOCK" -X POST http://x/v1/scrub >/dev/null
sleep 0.7
for i in 1 2 3; do curl -s -X PUT --data-binary @"$T.big" "$URL/sbig/big" -o /dev/null; sleep 0.3; done
for _ in $(seq 300); do [ "$(st '["running"]')" = "False" ] && break; sleep 0.1; done
check_eq "object replaced mid-read: not corrupt" "$(st '["corrupt"]')" "0"
stop

# ---- resume after kill -9 -----------------------------------------------------------------
rm -rf "$DATA"; : >"$LOG"
start --scrub-rate 3M
for b in sra srb src srd; do
    curl -s -X PUT "$URL/$b" -o /dev/null
    for k in 1 2 3; do head -c $((1024 * 1024)) /dev/urandom | curl -s -X PUT --data-binary @- "$URL/$b/k$k" -o /dev/null; done
done
curl -sS --unix-socket "$SOCK" -X POST http://x/v1/scrub >/dev/null
sleep 2.5
P1=$(st '["pass"]')
kill -9 "$SP"; wait "$SP" 2>/dev/null || true
check_eq "state shows an unfinished pass" "$(grep -c '^finished=0$' "$DATA/scrub/state" || true)" "1"
check_eq "cursor advanced past the first bucket" "$(grep '^bucket=' "$DATA/scrub/state" | grep -cv '^bucket=$' || true)" "1"
start --scrub-rate 0
for _ in $(seq 300); do [ "$(st '["finished"]')" != "0" ] && [ "$(st '["running"]')" = "False" ] && break; sleep 0.1; done
check_eq "resumed (log line)" "$(grep -c 'scrub: resuming pass' "$LOG" || true)" "1"
check_eq "same pass id after resume" "$(st '["pass"]')" "$P1"
check_eq "resumed pass finished clean" "$(st '["corrupt"]')" "0"
stop

printf '\n===== scrub e2e: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
