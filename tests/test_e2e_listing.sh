#!/usr/bin/env bash
#
# tests/test_e2e_listing.sh — round 2 item 1f: ListObjectsV2 and
# ListMultipartUploads pagination against the boto3 paginators, with
# more than 1000 keys / uploads.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 26400 + RANDOM % 300 ))}
DATA=/tmp/fs3-list-e2e-$$
LOG=/tmp/fs3-list-e2e-$$.log
URL="http://127.0.0.1:$PORT"
A=AKIALISTALICE001; AS=listAliceSecret01234567890123456789012

cleanup() {
    [ -n "${SP:-}" ] && kill "$SP" 2>/dev/null || true
    rm -rf "$DATA" "$LOG"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

"$ROOT/fs3" -p "$PORT" -d "$DATA" --auth "$A:$AS:alice" --require-auth >"$LOG" 2>&1 &
SP=$!
sleep 0.4
kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }

python3 -u - "$URL" "$A" "$AS" <<'PY'
import sys, concurrent.futures as cf, boto3, botocore
url, a, asec = sys.argv[1:4]
s3 = boto3.client("s3", endpoint_url=url, aws_access_key_id=a, aws_secret_access_key=asec,
                  region_name="us-east-1",
                  config=botocore.config.Config(max_pool_connections=16))
PASS = FAIL = 0
def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(".", end="", flush=True)
    else:
        FAIL += 1; print(f"\nFAIL: {name}\n  want={str(want)[:300]!r}\n  got ={str(got)[:300]!r}")
def code(f):
    try:
        f(); return "ok"
    except botocore.exceptions.ClientError as e:
        return e.response["Error"]["Code"]

s3.create_bucket(Bucket="lst")
keys = [f"d{i % 3}/k{i:05d}" + (" sp&ace+%" if i % 97 == 0 else "") for i in range(2503)]
keys += ["top1", "top2", "z" * 1024]
with cf.ThreadPoolExecutor(16) as ex:
    list(ex.map(lambda k: s3.put_object(Bucket="lst", Key=k, Body=b"x"), keys))
S = sorted(keys)

# --- ListObjectsV2 ---------------------------------------------------------
p = s3.get_paginator("list_objects_v2")
pages = list(p.paginate(Bucket="lst"))
got = [o["Key"] for pg in pages for o in pg.get("Contents", [])]
check("v2 paginator returns every key once, sorted", got, S)
check("v2 pages", len(pages), 3)
check("v2 KeyCount per page", [pg["KeyCount"] for pg in pages], [1000, 1000, len(S) - 2000])
check("v2 last page not truncated", (pages[-1]["IsTruncated"], "NextContinuationToken" in pages[-1]), (False, False))
check("v2 no Owner without fetch-owner", "Owner" in pages[0]["Contents"][0], False)
r = s3.list_objects_v2(Bucket="lst", MaxKeys=2, FetchOwner=True)
check("v2 fetch-owner", r["Contents"][0].get("Owner", {}).get("ID"), "alice")
got = [o["Key"] for pg in p.paginate(Bucket="lst", StartAfter="d1/k01000", PaginationConfig={"PageSize": 333})
       for o in pg.get("Contents", [])]
check("v2 start-after + small pages", got, [k for k in S if k > "d1/k01000"])
got = [o["Key"] for pg in p.paginate(Bucket="lst", Prefix="d2/", PaginationConfig={"PageSize": 100})
       for o in pg.get("Contents", [])]
check("v2 prefix", got, [k for k in S if k.startswith("d2/")])
# Delimiter with tiny pages: each CommonPrefix exactly once.
pr, ks = [], []
for pg in p.paginate(Bucket="lst", Delimiter="/", PaginationConfig={"PageSize": 1}):
    pr += [c["Prefix"] for c in pg.get("CommonPrefixes", [])]
    ks += [o["Key"] for o in pg.get("Contents", [])]
check("v2 delimiter, page size 1: prefixes once", pr, ["d0/", "d1/", "d2/"])
check("v2 delimiter, page size 1: top-level keys", ks, ["top1", "top2", "z" * 1024])
r = s3.list_objects_v2(Bucket="lst", Prefix="d0/k00000", EncodingType="url")
# An explicit EncodingType is not decoded by boto3: we see the wire form.
check("v2 encoding-type=url", [o["Key"] for o in r["Contents"]], ["d0/k00000%20sp%26ace%2B%25"])
check("bad continuation token → InvalidArgument",
      code(lambda: s3.list_objects_v2(Bucket="lst", ContinuationToken="!!!")), "InvalidArgument")
# Key of exactly 1024 bytes as the last key of a page.
r = s3.list_objects_v2(Bucket="lst", StartAfter="top2", MaxKeys=1)
check("1024-byte key listed", [o["Key"] for o in r["Contents"]], ["z" * 1024])

# --- ListObjects (v1) still works ------------------------------------------
got = [o["Key"] for pg in s3.get_paginator("list_objects").paginate(Bucket="lst") for o in pg.get("Contents", [])]
check("v1 paginator", got, S)
pr = [c["Prefix"] for pg in s3.get_paginator("list_objects").paginate(Bucket="lst", Delimiter="/",
      PaginationConfig={"PageSize": 1}) for c in pg.get("CommonPrefixes", [])]
check("v1 delimiter, page size 1", pr, ["d0/", "d1/", "d2/"])

# --- ListMultipartUploads -------------------------------------------------------
ids = {}
def mk(i):
    k = f"u{i % 400:04d}"
    return k, s3.create_multipart_upload(Bucket="lst", Key=k)["UploadId"]
with cf.ThreadPoolExecutor(16) as ex:
    made = list(ex.map(mk, range(1203)))
want = sorted(made)
pm = s3.get_paginator("list_multipart_uploads")
pages = list(pm.paginate(Bucket="lst"))
got = [(u["Key"], u["UploadId"]) for pg in pages for u in pg.get("Uploads", [])]
check("mpu paginator: every upload once, sorted", got, want)
check("mpu pages", len(pages), 2)
got = [(u["Key"], u["UploadId"]) for pg in pm.paginate(Bucket="lst", PaginationConfig={"PageSize": 7})
       for u in pg.get("Uploads", [])]
check("mpu small pages (same key across a page boundary)", got, want)
r = s3.list_multipart_uploads(Bucket="lst", KeyMarker="u0399")
check("key-marker skips that key", [u["Key"] for u in r.get("Uploads", [])], [])
r = s3.list_multipart_uploads(Bucket="lst", Prefix="u0001")
check("mpu prefix", len(r["Uploads"]), 4)

print(f"\nPYPASS={PASS} PYFAIL={FAIL}")
sys.exit(1 if FAIL else 0)
PY
echo "===== listing e2e: done ====="
