#!/usr/bin/env bash
#
# tests/test_e2e_versioning.sh — item 8: bucket versioning, driven by
# boto3: overwrite history, delete markers, undelete, version-id GET/
# DELETE, Suspended/null semantics, ListObjectVersions pagination over
# 1000+ versions, copy from a version, bucket-delete rules, and crash
# recovery of a half-done link-aside.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 23700 + RANDOM % 300 ))}
DATA=/tmp/fs3-ver-e2e-$$
LOG=/tmp/fs3-ver-e2e-$$.log
URL="http://127.0.0.1:$PORT"
AK=AKIAVERSIONING01
SK=versioningSecret012345678901234567890123456

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; } || true
    rm -rf "$DATA" "$LOG"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

start() {
    "$ROOT/fs3" -p "$PORT" -d "$DATA" --auth "$AK:$SK" --require-auth >>"$LOG" 2>&1 &
    SP=$!
    sleep 0.4
    kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }
}
stop() { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; SP=; }

start
python3 -u - "$URL" "$AK" "$SK" "$DATA" <<'PY'
import sys, os, boto3, botocore
url, ak, sk, data = sys.argv[1:5]
s3 = boto3.client("s3", endpoint_url=url, aws_access_key_id=ak,
                  aws_secret_access_key=sk, region_name="us-east-1")
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
def body(**kw):
    return s3.get_object(**kw)["Body"].read()

s3.create_bucket(Bucket="verb")
check("unset status", "Status" in s3.get_bucket_versioning(Bucket="verb"), False)
s3.put_object(Bucket="verb", Key="k", Body=b"null-version")
s3.put_bucket_versioning(Bucket="verb", VersioningConfiguration={"Status": "Enabled"})
check("enabled", s3.get_bucket_versioning(Bucket="verb")["Status"], "Enabled")

v1 = s3.put_object(Bucket="verb", Key="k", Body=b"one")["VersionId"]
v2 = s3.put_object(Bucket="verb", Key="k", Body=b"two")["VersionId"]
check("vids differ", v1 != v2 and len(v1) == 32, True)
check("current is v2", body(Bucket="verb", Key="k"), b"two")
check("GET v1", body(Bucket="verb", Key="k", VersionId=v1), b"one")
check("GET null", body(Bucket="verb", Key="k", VersionId="null"), b"null-version")
check("HEAD carries version id", s3.head_object(Bucket="verb", Key="k")["VersionId"], v2)
_v0 = s3.list_object_versions(Bucket="verb", Prefix="k")["Versions"][-1]
check("versioned read: multi-range → full object",
      len(s3.get_object(Bucket="verb", Key="k", VersionId=_v0["VersionId"], Range="bytes=0-0,2-2")["Body"].read()),
      _v0["Size"])
check("bad version id", code(lambda: s3.get_object(Bucket="verb", Key="k", VersionId="../../etc")), "InvalidArgument")
check("unknown version", code(lambda: s3.get_object(Bucket="verb", Key="k", VersionId="0"*31 + "1")), "NoSuchVersion")

vs = s3.list_object_versions(Bucket="verb", Prefix="k")
check("3 versions listed", [v["VersionId"] for v in vs["Versions"]], [v2, v1, "null"])
check("latest flag", [v["IsLatest"] for v in vs["Versions"]], [True, False, False])

# Delete marker.
r = s3.delete_object(Bucket="verb", Key="k")
check("delete → marker", r.get("DeleteMarker"), True)
dm = r["VersionId"]
check("GET after delete → 404", code(lambda: s3.get_object(Bucket="verb", Key="k")), "NoSuchKey")
try:
    s3.head_object(Bucket="verb", Key="k")
except botocore.exceptions.ClientError as e:
    check("404 carries x-amz-delete-marker", e.response["ResponseMetadata"]["HTTPHeaders"].get("x-amz-delete-marker"), "true")
check("list hides deleted key", s3.list_objects_v2(Bucket="verb").get("KeyCount", 0), 0)
check("old versions still readable", body(Bucket="verb", Key="k", VersionId=v1), b"one")
vs = s3.list_object_versions(Bucket="verb")
check("marker listed", [d["VersionId"] for d in vs.get("DeleteMarkers", [])], [dm])
check("GET marker by id → 405", code(lambda: s3.get_object(Bucket="verb", Key="k", VersionId=dm)), "MethodNotAllowed")

# Undelete: remove the marker.
r = s3.delete_object(Bucket="verb", Key="k", VersionId=dm)
check("removing marker reports it", r.get("DeleteMarker"), True)
check("undeleted", body(Bucket="verb", Key="k"), b"two")

# Delete current version by id → previous promoted.
s3.delete_object(Bucket="verb", Key="k", VersionId=v2)
check("v1 promoted", body(Bucket="verb", Key="k"), b"one")
s3.delete_object(Bucket="verb", Key="k", VersionId="null")
vs = s3.list_object_versions(Bucket="verb", Prefix="k")
check("null version removed", [v["VersionId"] for v in vs["Versions"]], [v1])

# Copy from a version.
v3 = s3.put_object(Bucket="verb", Key="k", Body=b"three")["VersionId"]
r = s3.copy_object(Bucket="verb", Key="copy", CopySource={"Bucket": "verb", "Key": "k", "VersionId": v1})
check("copy from version", body(Bucket="verb", Key="copy"), b"one")
check("copy has new version id", len(r["VersionId"]), 32)

# Multipart upload creates a version.
mp = s3.create_multipart_upload(Bucket="verb", Key="k")
p1 = s3.upload_part(Bucket="verb", Key="k", UploadId=mp["UploadId"], PartNumber=1, Body=b"mpu")
r = s3.complete_multipart_upload(Bucket="verb", Key="k", UploadId=mp["UploadId"],
    MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": p1["ETag"]}]})
check("MPU version id", len(r.get("VersionId", "")), 32)
check("v3 kept after MPU", body(Bucket="verb", Key="k", VersionId=v3), b"three")

# Suspended: null version overwritten in place.
s3.put_bucket_versioning(Bucket="verb", VersioningConfiguration={"Status": "Suspended"})
r1 = s3.put_object(Bucket="verb", Key="s", Body=b"a")
r2 = s3.put_object(Bucket="verb", Key="s", Body=b"b")
check("suspended vid null", (r1.get("VersionId"), r2.get("VersionId")), ("null", "null"))
vs = s3.list_object_versions(Bucket="verb", Prefix="s")
check("single null version", len(vs["Versions"]), 1)
check("can't return to Unset", code(lambda: s3.put_bucket_versioning(
    Bucket="verb", VersioningConfiguration={"Status": "Enabled", "MFADelete": "Enabled"},
    MFA="x 1")), "NotImplemented")
r = s3.delete_object(Bucket="verb", Key="s")
check("suspended delete → null marker", (r.get("DeleteMarker"), r.get("VersionId")), (True, "null"))

# Bucket delete needs every version gone.
check("versioned bucket not empty", code(lambda: s3.delete_bucket(Bucket="verb")), "BucketNotEmpty")

# Pagination over 1000+ versions.
s3.create_bucket(Bucket="vpage")
s3.put_bucket_versioning(Bucket="vpage", VersioningConfiguration={"Status": "Enabled"})
for i in range(1030):
    s3.put_object(Bucket="vpage", Key="many", Body=str(i).encode())
for i in range(5):
    s3.put_object(Bucket="vpage", Key=f"other{i}", Body=b"x")
seen, pages = [], 0
for page in s3.get_paginator("list_object_versions").paginate(Bucket="vpage", PaginationConfig={"PageSize": 300}):
    pages += 1
    seen += [(v["Key"], v["VersionId"]) for v in page.get("Versions", [])]
check("1035 versions across pages", len(seen), 1035)
check("no duplicates", len(set(seen)), 1035)
check("several pages", pages >= 4, True)
check("newest first", body(Bucket="vpage", Key="many", VersionId=seen[0][1]), b"1029")

# Bulk delete with VersionId.
vids = [v for k, v in seen if k == "many"][:3]
r = s3.delete_objects(Bucket="vpage", Delete={"Objects": [{"Key": "many", "VersionId": v} for v in vids]})
check("bulk version delete", len(r.get("Deleted", [])), 3)
check("versions gone", code(lambda: s3.get_object(Bucket="vpage", Key="many", VersionId=vids[1])), "NoSuchVersion")

# Crash between link-aside and rename: simulate the leftover duplicate
# link, restart, recovery removes it.
s3.create_bucket(Bucket="vcrash")
s3.put_bucket_versioning(Bucket="vcrash", VersioningConfiguration={"Status": "Enabled"})
s3.put_object(Bucket="vcrash", Key="c", Body=b"only")
import hashlib
h = hashlib.sha256(b"vcrash\0c").hexdigest()
cur = f"{data}/data/vcrash/{h[:2]}/{h[2:4]}/{h}"
vdir = f"{data}/versions/vcrash/{h[:2]}/{h[2:4]}/{h}"
os.makedirs(vdir, exist_ok=True)
vid = s3.head_object(Bucket="vcrash", Key="c")["VersionId"]
os.link(cur, f"{vdir}/{(2**64-1-12345):016x}-{vid}")
open(f"{data}/.crash-ready", "w").close()
print(f"\nPYPASS={PASS} PYFAIL={FAIL}")
sys.exit(1 if FAIL else 0)
PY
res=$(tail -n 1 "$LOG" 2>/dev/null || true)
stop
start
cnt=$(python3 - "$URL" "$AK" "$SK" <<'PY'
import sys, boto3
s3 = boto3.client("s3", endpoint_url=sys.argv[1], aws_access_key_id=sys.argv[2],
                  aws_secret_access_key=sys.argv[3], region_name="us-east-1")
print(len(s3.list_object_versions(Bucket="vcrash")["Versions"]))
PY
)
stop
if [ "$cnt" = "1" ] && grep -q "duplicate version link" "$LOG"; then
    echo "."; echo "===== versioning e2e: crash recovery ok, all passed ====="
else
    echo "FAIL: crash recovery: versions=$cnt"; exit 1
fi
