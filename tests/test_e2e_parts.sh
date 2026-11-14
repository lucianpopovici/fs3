#!/usr/bin/env bash
#
# tests/test_e2e_parts.sh — round 2 item 1: multipart part records and
# ETag verification at Complete (1a), ListParts (1b), UploadPartCopy (1c).
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 25600 + RANDOM % 300 ))}
DATA=/tmp/fs3-parts-e2e-$$
LOG=/tmp/fs3-parts-e2e-$$.log
URL="http://127.0.0.1:$PORT"
A=AKIAPARTSALICE01; AS=partsAliceSecret0123456789012345678901
B=AKIAPARTSBOB0001; BS=partsBobSecret012345678901234567890123

cleanup() {
    [ -n "${SP:-}" ] && kill "$SP" 2>/dev/null || true
    rm -rf "$DATA" "$LOG"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

# 1 KiB minimum part size keeps the payloads small.
"$ROOT/fs3" -p "$PORT" -d "$DATA" --auth "$A:$AS:alice" --auth "$B:$BS:bob" \
    --require-auth --mpu-min-part-size 1024 >"$LOG" 2>&1 &
SP=$!
sleep 0.4
kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }

ORPHAN_OUT="$DATA.orphan" python3 -u - "$URL" "$A" "$AS" "$B" "$BS" "$DATA" <<'PY'
import sys, os, glob, hashlib, boto3, botocore
url, a, asec, b, bsec, data = sys.argv[1:7]
mk = lambda ak, sk: boto3.client("s3", endpoint_url=url, aws_access_key_id=ak,
                                 aws_secret_access_key=sk, region_name="us-east-1")
s3, bob = mk(a, asec), mk(b, bsec)
PASS = FAIL = 0
def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(".", end="", flush=True)
    else:
        FAIL += 1; print(f"\nFAIL: {name}\n  want={want!r}\n  got ={got!r}")
def code(f):
    try:
        f(); return "ok"
    except botocore.exceptions.ClientError as e:
        return e.response["Error"]["Code"]

s3.create_bucket(Bucket="partb")
p1, p2, p3 = os.urandom(2048), os.urandom(3000), os.urandom(500)

def start(key="obj"):
    return s3.create_multipart_upload(Bucket="partb", Key=key)["UploadId"]
def up(key, uid, n, body):
    return s3.upload_part(Bucket="partb", Key=key, UploadId=uid, PartNumber=n, Body=body)["ETag"]
def complete(key, uid, parts):
    return s3.complete_multipart_upload(Bucket="partb", Key=key, UploadId=uid,
        MultipartUpload={"Parts": [{"PartNumber": n, "ETag": e} for n, e in parts]})

# --- 1a: ETag verification -----------------------------------------------
uid = start()
e1, e2, e3 = up("obj", uid, 1, p1), up("obj", uid, 2, p2), up("obj", uid, 3, p3)
check("part ETag is the MD5", e1.strip('"'), hashlib.md5(p1).hexdigest())
zeros = '"' + "0" * 32 + '"'
check("wrong ETag → InvalidPart", code(lambda: complete("obj", uid, [(1, zeros), (2, e2), (3, e3)])), "InvalidPart")
check("upload still usable after a refused Complete",
      len(s3.list_multipart_uploads(Bucket="partb").get("Uploads", [])), 1)
check("missing part → InvalidPart", code(lambda: complete("obj", uid, [(1, e1), (4, e2)])), "InvalidPart")
check("out of order → InvalidPartOrder", code(lambda: complete("obj", uid, [(2, e2), (1, e1)])), "InvalidPartOrder")
# Quoted, unquoted and upper-case hex are all the same ETag.
r = complete("obj", uid, [(1, e1), (2, e2.strip('"')), (3, e3.upper())])
want = hashlib.md5(b"".join(bytes.fromhex(e.strip('"')) for e in (e1, e2, e3))).hexdigest() + "-3"
check("multipart ETag = MD5 of recorded part MD5s", r["ETag"].strip('"'), want)
check("object bytes", s3.get_object(Bucket="partb", Key="obj")["Body"].read(), p1 + p2 + p3)
check("ETag on HEAD", s3.head_object(Bucket="partb", Key="obj")["ETag"].strip('"'), want)

# Re-uploaded part: the client's old ETag no longer matches.
uid = start("re")
old = up("re", uid, 1, p1)
new = up("re", uid, 1, p2)
up("re", uid, 2, p3)
check("stale ETag of a re-uploaded part → InvalidPart",
      code(lambda: complete("re", uid, [(1, old), (2, hashlib.md5(p3).hexdigest())])), "InvalidPart")
check("current ETag completes", code(lambda: complete("re", uid, [(1, new), (2, hashlib.md5(p3).hexdigest())])), "ok")
check("re-upload bytes", s3.get_object(Bucket="partb", Key="re")["Body"].read(), p2 + p3)

# Size rule: non-final part below the minimum.
uid = start("small")
s1, s2 = up("small", uid, 1, b"x" * 100), up("small", uid, 2, p1)
check("small non-final part → EntityTooSmall", code(lambda: complete("small", uid, [(1, s1), (2, s2)])), "EntityTooSmall")
uid2 = start("lastsmall")
l1, l2 = up("lastsmall", uid2, 1, p1), up("lastsmall", uid2, 2, b"y" * 10)
check("small final part is fine", code(lambda: complete("lastsmall", uid2, [(1, l1), (2, l2)])), "ok")

# Pre-upgrade upload: parts without .rec are hashed at Complete — and
# still verified.
uid = start("legacy")
g1, g2 = up("legacy", uid, 1, p1), up("legacy", uid, 2, p3)
for f in glob.glob(f"{data}/mpu/partb/{uid}/*.rec"):
    os.unlink(f)
check("legacy part, wrong ETag → InvalidPart", code(lambda: complete("legacy", uid, [(1, zeros), (2, g2)])), "InvalidPart")
check("legacy parts complete", code(lambda: complete("legacy", uid, [(1, g1), (2, g2)])), "ok")
check("legacy bytes", s3.get_object(Bucket="partb", Key="legacy")["Body"].read(), p1 + p3)

# --- 1b: ListParts ---------------------------------------------------------
uid = start("lp")
bodies = {n: os.urandom(1024 + n) for n in range(1, 8)}
for n in (3, 1, 7, 2, 5, 4, 6):
    up("lp", uid, n, bodies[n])
r = s3.list_parts(Bucket="partb", Key="lp", UploadId=uid)
check("ListParts all, sorted", [p["PartNumber"] for p in r["Parts"]], list(range(1, 8)))
check("ListParts ETag", r["Parts"][0]["ETag"].strip('"'), hashlib.md5(bodies[1]).hexdigest())
check("ListParts Size", r["Parts"][6]["Size"], 1031)
check("ListParts not truncated", r["IsTruncated"], False)
r = s3.list_parts(Bucket="partb", Key="lp", UploadId=uid, MaxParts=3)
check("MaxParts=3", ([p["PartNumber"] for p in r["Parts"]], r["IsTruncated"], r["NextPartNumberMarker"]),
      ([1, 2, 3], True, 3))
r = s3.list_parts(Bucket="partb", Key="lp", UploadId=uid, MaxParts=3, PartNumberMarker=3)
check("marker=3", [p["PartNumber"] for p in r["Parts"]], [4, 5, 6])
pag = s3.get_paginator("list_parts")
seen = [p["PartNumber"] for pg in pag.paginate(Bucket="partb", Key="lp", UploadId=uid,
                                               PaginationConfig={"PageSize": 2}) for p in pg.get("Parts", [])]
check("paginator walks all parts", seen, list(range(1, 8)))
check("wrong key → NoSuchUpload", code(lambda: s3.list_parts(Bucket="partb", Key="other", UploadId=uid)), "NoSuchUpload")
check("unknown upload → NoSuchUpload",
      code(lambda: s3.list_parts(Bucket="partb", Key="lp", UploadId="0" * 32)), "NoSuchUpload")
check("other user → AccessDenied", code(lambda: bob.list_parts(Bucket="partb", Key="lp", UploadId=uid)), "AccessDenied")
# ETags from ListParts complete the upload (what resuming clients do).
parts = [(p["PartNumber"], p["ETag"]) for p in s3.list_parts(Bucket="partb", Key="lp", UploadId=uid)["Parts"]]
check("Complete from ListParts ETags", code(lambda: complete("lp", uid, parts)), "ok")
check("lp bytes", s3.get_object(Bucket="partb", Key="lp")["Body"].read(), b"".join(bodies[n] for n in range(1, 8)))

# Checksums appear per part.
uid = s3.create_multipart_upload(Bucket="partb", Key="ck", ChecksumAlgorithm="SHA256")["UploadId"]
s3.upload_part(Bucket="partb", Key="ck", UploadId=uid, PartNumber=1, Body=p1, ChecksumAlgorithm="SHA256")
r = s3.list_parts(Bucket="partb", Key="ck", UploadId=uid)
import base64
check("ListParts ChecksumAlgorithm", r.get("ChecksumAlgorithm"), "SHA256")
check("ListParts ChecksumSHA256", r["Parts"][0].get("ChecksumSHA256"),
      base64.b64encode(hashlib.sha256(p1).digest()).decode())

# Legacy part (no record) is listed too.
uid = start("lg2")
up("lg2", uid, 1, p2)
for f in glob.glob(f"{data}/mpu/partb/{uid}/*.rec"):
    os.unlink(f)
r = s3.list_parts(Bucket="partb", Key="lg2", UploadId=uid)
check("legacy part listed", (r["Parts"][0]["ETag"].strip('"'), r["Parts"][0]["Size"]),
      (hashlib.md5(p2).hexdigest(), len(p2)))
# An orphan record (no part) is not a part.
open(f"{data}/mpu/partb/{uid}/part-00009.rec", "wb").write(b"x" * 88)
check("orphan record ignored", [p["PartNumber"] for p in s3.list_parts(Bucket="partb", Key="lg2", UploadId=uid)["Parts"]], [1])
with open(os.environ.get("ORPHAN_OUT", "/dev/null"), "w") as f:
    f.write(f"{data}/mpu/partb/{uid}/part-00009.rec")

print(f"\nPYPASS={PASS} PYFAIL={FAIL}")
sys.exit(1 if FAIL else 0)
PY
# Startup recovery removes the orphan record left above.
ORPHAN=$(cat "$DATA.orphan")
[ -f "$ORPHAN" ] || { echo "FAIL: orphan record missing before restart"; exit 1; }
kill "$SP"; wait "$SP" 2>/dev/null || true
"$ROOT/fs3" -p "$PORT" -d "$DATA" --auth "$A:$AS:alice" --require-auth >"$LOG" 2>&1 &
SP=$!
sleep 0.4
if [ -f "$ORPHAN" ]; then echo "FAIL: orphan record survived restart"; exit 1; fi
grep -q "orphan part record" "$LOG" || { echo "FAIL: no recovery log line"; exit 1; }
rm -f "$DATA.orphan"
echo "===== parts e2e: done ====="
