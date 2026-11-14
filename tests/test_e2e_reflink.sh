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
kill "$SP"; wait "$SP" 2>/dev/null || true

# ---- 6b: whole-object dedup ---------------------------------------------------
A=AKIADEDUPALICE01; AS=dedupAliceSecret0123456789012345678901
B=AKIADEDUPBOB0001; BS=dedupBobSecret012345678901234567890123
dedup_phase() {   # $1 = owner|global, extra flags after
    local mode=$1; shift
    rm -rf "$DATA"; : >"$LOG"
    start --auth "$A:$AS:alice" --auth "$B:$BS:bob" --dedup "$mode" --dedup-min-size 64K \
          --scrub-interval-days 0 --admin-socket "$DATA.sock" "$@"
    python3 -u - "$URL" "$DATA" "$MPORT" "$mode" "$A" "$AS" "$B" "$BS" <<'PY'
import sys, os, glob, subprocess, urllib.request, json, time, boto3
from botocore.config import Config
url, data, mport, mode, a, asec, b, bsec = sys.argv[1:9]
mk = lambda ak, sk: boto3.client("s3", endpoint_url=url, aws_access_key_id=ak, aws_secret_access_key=sk,
                                 region_name="us-east-1", config=Config(signature_version="s3v4"))
al, bo = mk(a, asec), mk(b, bsec)
PASS = FAIL = 0
def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(".", end="", flush=True)
    else:
        FAIL += 1; print(f"\nFAIL: {name}\n  want={want!r}\n  got ={got!r}")
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def metric(name):
    m = op.open(f"http://127.0.0.1:{mport}/metrics").read().decode()
    return int(next(l.split()[1] for l in m.splitlines() if l.startswith(name + " ")))
def shared(path):
    return "shared" in subprocess.run(["filefrag", "-v", path], capture_output=True, text=True).stdout
def files(bucket): return glob.glob(f"{data}/data/{bucket}/*/*/*")
MiB = 1024 * 1024
blob = os.urandom(3 * MiB + 5)
al.create_bucket(Bucket="da1"); al.create_bucket(Bucket="da2"); bo.create_bucket(Bucket="db1")
h0 = metric("fs3_dedup_hits_total")
al.put_object(Bucket="da1", Key="x", Body=blob)
check(f"{mode}: first PUT adds a pool entry", len(glob.glob(f"{data}/cas/*/*/*/*")), 1)
al.put_object(Bucket="da2", Key="y", Body=blob)
check(f"{mode}: identical PUT is a hit", metric("fs3_dedup_hits_total") - h0, 1)
check(f"{mode}: the two objects share extents", shared(files("da1")[0]) and shared(files("da2")[0]), True)
check(f"{mode}: content intact", al.get_object(Bucket="da2", Key="y")["Body"].read(), blob)
bo.put_object(Bucket="db1", Key="z", Body=blob)
if mode == "owner":
    check("owner scope: another user's identical object is not shared", metric("fs3_dedup_hits_total") - h0, 1)
    check("owner scope: separate pool per owner", len(os.listdir(f"{data}/cas")), 2)
else:
    check("global scope: shared across users", metric("fs3_dedup_hits_total") - h0, 2)
small = os.urandom(1000)
al.put_object(Bucket="da1", Key="small", Body=small)
al.put_object(Bucket="da2", Key="small", Body=small)
check(f"{mode}: below --dedup-min-size not pooled", metric("fs3_dedup_hits_total") - h0, 1 if mode == "owner" else 2)
al.delete_object(Bucket="da1", Key="x")
check(f"{mode}: delete one sharer, the other intact", al.get_object(Bucket="da2", Key="y")["Body"].read(), blob)
subprocess.run(["rm", "-rf", f"{data}/cas"])
check(f"{mode}: pool wipe is harmless", al.get_object(Bucket="da2", Key="y")["Body"].read(), blob)
al.put_object(Bucket="da1", Key="again", Body=blob)
check(f"{mode}: pool re-created after a wipe", len(glob.glob(f"{data}/cas/*/*/*/*")) >= 1, True)
# Scrub GC: an entry no object references (and older than the pass) goes.
orphan_dir = f"{data}/cas/{os.listdir(data + '/cas')[0]}/00/00"
os.makedirs(orphan_dir, exist_ok=True)
orphan = orphan_dir + "/" + "0" * 64
open(orphan, "wb").write(b"orphan")
os.utime(orphan, (time.time() - 3600, time.time() - 3600))
for p in glob.glob(f"{data}/cas/*/*/*/*"):
    os.utime(p, (time.time() - 3600, time.time() - 3600))
subprocess.run(["curl", "-s", "--unix-socket", data + ".sock", "-X", "POST", "http://x/v1/scrub"], capture_output=True)
for _ in range(100):
    st = json.loads(subprocess.run(["curl", "-s", "--unix-socket", data + ".sock", "http://x/v1/scrub"],
                                   capture_output=True, text=True).stdout)
    if not st["running"] and st["finished"] >= st["started"] > 0: break
    time.sleep(0.1)
check(f"{mode}: scrub removed the unreferenced pool entry", os.path.exists(orphan), False)
check(f"{mode}: scrub kept the referenced one", len(glob.glob(f"{data}/cas/*/*/*/*")) >= 1, True)
check(f"{mode}: objects still verify", st["corrupt"], 0)
print(f"\nPYPASS={PASS} PYFAIL={FAIL}")
sys.exit(1 if FAIL else 0)
PY
    kill "$SP"; wait "$SP" 2>/dev/null || true
}
dedup_phase owner
dedup_phase global --dedup-verify
grep -q "verified" "$LOG" || { echo "FAIL: --dedup-verify not active"; exit 1; }
rm -rf "$DATA.sock"

# ---- 7a: filesystem compression --------------------------------------------------
compress_phase() {   # $1 = auto|all
    rm -rf "$DATA"; : >"$LOG"
    start --fs-compress "$1"
    grep -q "fs-compress: " "$LOG" || { echo "FAIL: fs-compress not enabled"; exit 1; }
    python3 -c "print('compressible text line\n' * 300000, end='')" > "$DATA.txt"
    curl -s -X PUT "$URL/czz" -o /dev/null
    curl -s -X PUT --data-binary @"$DATA.txt" "$URL/czz/doc.txt" -o /dev/null
    curl -s -X PUT --data-binary @"$DATA.txt" -H 'Content-Type: image/jpeg' "$URL/czz/photo.jpg" -o /dev/null
    head -c 100 "$DATA.txt" | curl -s -X PUT --data-binary @- "$URL/czz/tiny.txt" -o /dev/null
    sync
    flag() { lsattr "$(grep -l "$1" "$DATA"/data/czz/*/*/* | head -1)" | cut -c9; }
    [ "$(flag doc.txt)" = "c" ] || { echo "FAIL: $1: doc.txt not flagged for compression"; exit 1; }
    f=$(grep -l doc.txt "$DATA"/data/czz/*/*/* | head -1)
    filefrag -v "$f" | grep -q encoded || { echo "FAIL: $1: doc.txt extents not compressed"; exit 1; }
    if [ "$1" = auto ]; then
        [ "$(flag photo.jpg)" = "-" ] || { echo "FAIL: auto compressed a JPEG"; exit 1; }
        [ "$(flag tiny.txt)" = "-" ] || { echo "FAIL: auto compressed a 100-byte object"; exit 1; }
    else
        [ "$(flag photo.jpg)" = "c" ] || { echo "FAIL: all: JPEG not flagged"; exit 1; }
    fi
    curl -s "$URL/czz/doc.txt" | cmp -s - "$DATA.txt" || { echo "FAIL: $1: GET differs"; exit 1; }
    [ "$(curl -s -r 1000-1021 "$URL/czz/doc.txt")" = "$(tail -c +1001 "$DATA.txt" | head -c 22)" ] \
        || { echo "FAIL: $1: Range on a compressed object"; exit 1; }
    echo "fs-compress $1 ok"
    rm -f "$DATA.txt"
    kill "$SP"; wait "$SP" 2>/dev/null || true
}
compress_phase auto
compress_phase all
echo "===== reflink e2e: done ====="
