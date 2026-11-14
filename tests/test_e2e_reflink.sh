#!/usr/bin/env bash
#
# tests/test_e2e_reflink.sh — round 2 item 6a: reflink fast paths
# (multipart Complete, CopyObject, UploadPartCopy) on a reflink-capable
# filesystem. Needs FS3_REFLINK_DIR on Btrfs/XFS, e.g. a loopback image:
#   truncate -s 400M /tmp/btr.img && mkfs.btrfs /tmp/btr.img
#   mount -o loop /tmp/btr.img /mnt/btr && FS3_REFLINK_DIR=/mnt/btr ./tests/test_e2e_reflink.sh
# Skips without it (fails under FS3_TEST_STRICT=1).
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ -z "${FS3_REFLINK_DIR:-}" ]; then
    [ "${FS3_TEST_STRICT:-0}" = "1" ] && { echo "FAIL: FS3_REFLINK_DIR not set (FS3_TEST_STRICT=1)"; exit 1; }
    echo "SKIP: FS3_REFLINK_DIR not set (needs a Btrfs/XFS directory)"
    echo "===== reflink e2e: skipped ====="
    exit 0
fi
PORT=${FS3_TEST_PORT:-$(( 27600 + RANDOM % 200 ))}
MPORT=$((PORT + 1))
DATA=$FS3_REFLINK_DIR/fs3-reflink-e2e-$$
LOG=/tmp/fs3-reflink-e2e-$$.log
URL="http://127.0.0.1:$PORT"

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; [ $? -ne 159 ] || echo "FAIL: server died with SIGSYS (seccomp blocked a syscall; see --seccomp=log)" >&2; } || true
    rm -rf "$DATA" "$LOG"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

start() {
    ${FS3_WRAP:-} "$ROOT/fs3" -p "$PORT" -d "$DATA" --metrics-port "$MPORT" --mpu-min-part-size 0 "$@" >>"$LOG" 2>&1 &
    SP=$!
    for _ in $(seq 50); do curl -s -o /dev/null "$URL/" && break; sleep 0.1; done
    kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }
}
start
grep -q "reflink supported" "$LOG" || {
    [ "${FS3_TEST_STRICT:-0}" = "1" ] && { echo "FAIL: $FS3_REFLINK_DIR is not reflink-capable"; exit 1; }
    echo "SKIP: $FS3_REFLINK_DIR is not reflink-capable"; exit 0; }

run_py() {
python3 -u - "$URL" "$DATA" "$MPORT" "$1" <<'PY'
import sys, os, glob, hashlib, subprocess, urllib.request, boto3
from botocore.config import Config
url, data, mport, phase = sys.argv[1:5]
s3 = boto3.client("s3", endpoint_url=url, aws_access_key_id="x", aws_secret_access_key="y",
                  region_name="us-east-1", config=Config(signature_version="s3v4"))
PASS = FAIL = 0
def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(".", end="", flush=True)
    else:
        FAIL += 1; print(f"\nFAIL: {name}\n  want={want!r}\n  got ={got!r}")
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def clones():
    m = op.open(f"http://127.0.0.1:{mport}/metrics").read().decode()
    return int(next(l.split()[1] for l in m.splitlines() if l.startswith("fs3_reflink_clones_total ")))
def objfile(bucket):
    return sorted(glob.glob(f"{data}/data/{bucket}/*/*/*"), key=os.path.getmtime)[-1]
def shared(path):
    out = subprocess.run(["filefrag", "-v", path], capture_output=True, text=True).stdout
    return "shared" in out

MiB = 1024 * 1024
b = f"rl{phase}"
s3.create_bucket(Bucket=b)
p1, p2, p3 = os.urandom(5 * MiB), os.urandom(5 * MiB), os.urandom(1234)
c0 = clones()
uid = s3.create_multipart_upload(Bucket=b, Key="mp")["UploadId"]
es = [s3.upload_part(Bucket=b, Key="mp", UploadId=uid, PartNumber=i + 1, Body=p)["ETag"]
      for i, p in enumerate((p1, p2, p3))]
s3.complete_multipart_upload(Bucket=b, Key="mp", UploadId=uid,
    MultipartUpload={"Parts": [{"PartNumber": i + 1, "ETag": e} for i, e in enumerate(es)]})
body = s3.get_object(Bucket=b, Key="mp")["Body"].read()
check(f"{phase}: Complete bytes", hashlib.sha256(body).hexdigest(), hashlib.sha256(p1 + p2 + p3).hexdigest())
check(f"{phase}: multipart ETag", s3.head_object(Bucket=b, Key="mp")["ETag"].strip('"'),
      hashlib.md5(b"".join(hashlib.md5(p).digest() for p in (p1, p2, p3))).hexdigest() + "-3")
c1 = clones()
if phase == "on":
    check("Complete cloned every part", c1 - c0, 3)
else:
    check("--reflink off: Complete copied", c1 - c0, 0)

# Misaligned non-last part: clone stops, the rest is copied, bytes equal.
q1, q2 = os.urandom(5 * MiB + 1), os.urandom(4096)
uid = s3.create_multipart_upload(Bucket=b, Key="mis")["UploadId"]
es = [s3.upload_part(Bucket=b, Key="mis", UploadId=uid, PartNumber=i + 1, Body=p)["ETag"]
      for i, p in enumerate((q1, q2))]
s3.complete_multipart_upload(Bucket=b, Key="mis", UploadId=uid,
    MultipartUpload={"Parts": [{"PartNumber": i + 1, "ETag": e} for i, e in enumerate(es)]})
check(f"{phase}: misaligned part falls back, bytes equal", s3.get_object(Bucket=b, Key="mis")["Body"].read(), q1 + q2)
check(f"{phase}: misaligned Complete cloned nothing", clones() - c1, 0)

# CopyObject and UploadPartCopy.
big = os.urandom(8 * MiB + 77)
s3.put_object(Bucket=b, Key="src", Body=big)
c2 = clones()
s3.copy_object(Bucket=b, Key="dst", CopySource=f"{b}/src")
check(f"{phase}: copy bytes", s3.get_object(Bucket=b, Key="dst")["Body"].read(), big)
check(f"{phase}: copy ETag = MD5", s3.head_object(Bucket=b, Key="dst")["ETag"].strip('"'), hashlib.md5(big).hexdigest())
uid = s3.create_multipart_upload(Bucket=b, Key="pc")["UploadId"]
r = s3.upload_part_copy(Bucket=b, Key="pc", UploadId=uid, PartNumber=1, CopySource=f"{b}/src",
                        CopySourceRange=f"bytes=0-{4 * MiB - 1}")["CopyPartResult"]
check(f"{phase}: part copy ETag", r["ETag"].strip('"'), hashlib.md5(big[:4 * MiB]).hexdigest())
s3.abort_multipart_upload(Bucket=b, Key="pc", UploadId=uid)
if phase == "on":
    check("copy + part copy cloned", clones() - c2, 2)
    src_f = [f for f in glob.glob(f"{data}/data/{b}/*/*/*")]
    check("objects share extents (filefrag)", sum(shared(f) for f in src_f) >= 2, True)
    # Deleting one sharer keeps the other readable.
    s3.delete_object(Bucket=b, Key="src")
    check("delete one sharer, the other is intact", s3.get_object(Bucket=b, Key="dst")["Body"].read(), big)
else:
    check("--reflink off: copies copied", clones() - c2, 0)
print(f"\nPYPASS={PASS} PYFAIL={FAIL}")
sys.exit(1 if FAIL else 0)
PY
}
run_py on
kill "$SP"; wait "$SP" 2>/dev/null || true
start --reflink off
run_py off
echo "===== reflink e2e: done ====="
