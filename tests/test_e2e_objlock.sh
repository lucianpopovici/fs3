#!/usr/bin/env bash
#
# tests/test_e2e_objlock.sh — item 10: Object Lock (lock-enabled bucket
# creation, COMPLIANCE/GOVERNANCE retention, admin bypass, legal hold,
# extend-vs-shorten, default retention, lifecycle skipping locked
# versions, maximum retention).
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 24500 + RANDOM % 300 ))}
DATA=/tmp/fs3-ol-e2e-$$
LOG=/tmp/fs3-ol-e2e-$$.log
URL="http://127.0.0.1:$PORT"
A=AKIAOBJLOCKUSER1; AS=objlockUserSecret0123456789012345678901
R=AKIAOBJLOCKROOT1; RS=objlockRootSecret0123456789012345678901

cleanup() {
    [ -n "${SP:-}" ] && kill "$SP" 2>/dev/null || true
    rm -rf "$DATA" "$LOG"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

start() {
    "$ROOT/fs3" -p "$PORT" -d "$DATA" --auth "$A:$AS:alice" --auth "$R:$RS:root" \
        --admin root --require-auth --max-retention-days 30 "$@" >>"$LOG" 2>&1 &
    SP=$!
    sleep 0.4
    kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }
}
stop() { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; SP=; }

start
python3 -u - "$URL" "$A" "$AS" "$R" "$RS" <<'PY'
import sys, datetime, boto3, botocore
url, a, asec, r, rsec = sys.argv[1:6]
mk = lambda ak, sk: boto3.client("s3", endpoint_url=url, aws_access_key_id=ak,
                                 aws_secret_access_key=sk, region_name="us-east-1")
s3, root = mk(a, asec), mk(r, rsec)
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
now = datetime.datetime.now(datetime.timezone.utc)
soon = now + datetime.timedelta(days=1)
later = now + datetime.timedelta(days=2)

s3.create_bucket(Bucket="lockb", ObjectLockEnabledForBucket=True)
check("lock bucket is versioned", s3.get_bucket_versioning(Bucket="lockb")["Status"], "Enabled")
check("can't suspend", code(lambda: s3.put_bucket_versioning(Bucket="lockb",
      VersioningConfiguration={"Status": "Suspended"})), "InvalidRequest")
check("lock config", s3.get_object_lock_configuration(Bucket="lockb")
      ["ObjectLockConfiguration"]["ObjectLockEnabled"], "Enabled")
s3.create_bucket(Bucket="plainb")
check("plain bucket has no lock config", code(lambda: s3.get_object_lock_configuration(Bucket="plainb")),
      "ObjectLockConfigurationNotFoundError")
check("retention on plain bucket refused", code(lambda: s3.put_object(Bucket="plainb", Key="x", Body=b"x",
      ObjectLockMode="GOVERNANCE", ObjectLockRetainUntilDate=soon)), "InvalidRequest")

# COMPLIANCE at write time.
v = s3.put_object(Bucket="lockb", Key="c", Body=b"compliance", ObjectLockMode="COMPLIANCE",
                  ObjectLockRetainUntilDate=soon)["VersionId"]
ret = s3.get_object_retention(Bucket="lockb", Key="c", VersionId=v)["Retention"]
check("retention stored", ret["Mode"], "COMPLIANCE")
check("COMPLIANCE delete refused", code(lambda: s3.delete_object(Bucket="lockb", Key="c", VersionId=v)), "AccessDenied")
check("even admin with bypass", code(lambda: root.delete_object(Bucket="lockb", Key="c", VersionId=v,
      BypassGovernanceRetention=True)), "AccessDenied")
check("shorten COMPLIANCE refused", code(lambda: s3.put_object_retention(Bucket="lockb", Key="c", VersionId=v,
      Retention={"Mode": "COMPLIANCE", "RetainUntilDate": now + datetime.timedelta(hours=1)})), "AccessDenied")
check("COMPLIANCE → GOVERNANCE refused", code(lambda: s3.put_object_retention(Bucket="lockb", Key="c", VersionId=v,
      Retention={"Mode": "GOVERNANCE", "RetainUntilDate": later})), "AccessDenied")
check("extend allowed", code(lambda: s3.put_object_retention(Bucket="lockb", Key="c", VersionId=v,
      Retention={"Mode": "COMPLIANCE", "RetainUntilDate": later})), "ok")
check("over max retention refused", code(lambda: s3.put_object_retention(Bucket="lockb", Key="c", VersionId=v,
      Retention={"Mode": "COMPLIANCE", "RetainUntilDate": now + datetime.timedelta(days=60)})), "InvalidArgument")
r2 = s3.delete_object(Bucket="lockb", Key="c")
check("plain delete still adds a marker", r2.get("DeleteMarker"), True)
check("locked version survives", s3.get_object(Bucket="lockb", Key="c", VersionId=v)["Body"].read(), b"compliance")

# Lock headers need an integrity check.
def put_nock():
    c = mk(a, asec)
    c.meta.events.register("before-sign.s3.PutObject", lambda request, **k: [request.headers.__delitem__(h)
        for h in list(request.headers.keys()) if h.lower().startswith("x-amz-checksum") or h.lower() in ("content-md5", "x-amz-trailer", "x-amz-sdk-checksum-algorithm")])
    from botocore.config import Config
    c2 = boto3.client("s3", endpoint_url=url, aws_access_key_id=a, aws_secret_access_key=asec,
                      region_name="us-east-1", config=Config(request_checksum_calculation="when_required"))
    c2.put_object(Bucket="lockb", Key="n", Body=b"x", ObjectLockMode="GOVERNANCE", ObjectLockRetainUntilDate=soon)
check("lock headers without checksum refused", code(put_nock), "InvalidRequest")

# GOVERNANCE: admin bypass only.
g = s3.put_object(Bucket="lockb", Key="g", Body=b"gov", ObjectLockMode="GOVERNANCE",
                  ObjectLockRetainUntilDate=soon)["VersionId"]
check("GOVERNANCE delete refused", code(lambda: s3.delete_object(Bucket="lockb", Key="g", VersionId=g)), "AccessDenied")
check("non-admin bypass refused", code(lambda: s3.delete_object(Bucket="lockb", Key="g", VersionId=g,
      BypassGovernanceRetention=True)), "AccessDenied")
check("shorten GOVERNANCE without bypass refused", code(lambda: s3.put_object_retention(Bucket="lockb", Key="g",
      VersionId=g, Retention={"Mode": "GOVERNANCE", "RetainUntilDate": now + datetime.timedelta(hours=1)})), "AccessDenied")
check("admin bypass deletes", code(lambda: root.delete_object(Bucket="lockb", Key="g", VersionId=g,
      BypassGovernanceRetention=True)), "ok")

# Legal hold is independent of retention.
h = s3.put_object(Bucket="lockb", Key="h", Body=b"hold")["VersionId"]
s3.put_object_legal_hold(Bucket="lockb", Key="h", VersionId=h, LegalHold={"Status": "ON"})
check("legal hold readable", s3.get_object_legal_hold(Bucket="lockb", Key="h", VersionId=h)["LegalHold"]["Status"], "ON")
check("held version can't be deleted", code(lambda: root.delete_object(Bucket="lockb", Key="h", VersionId=h,
      BypassGovernanceRetention=True)), "AccessDenied")
s3.put_object_legal_hold(Bucket="lockb", Key="h", VersionId=h, LegalHold={"Status": "OFF"})
check("released → deletable", code(lambda: s3.delete_object(Bucket="lockb", Key="h", VersionId=h)), "ok")

# Default retention applies to new objects.
s3.put_object_lock_configuration(Bucket="lockb", ObjectLockConfiguration={
    "ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Days": 1}}})
d = s3.put_object(Bucket="lockb", Key="d", Body=b"default")["VersionId"]
check("default retention applied", s3.get_object_retention(Bucket="lockb", Key="d", VersionId=d)
      ["Retention"]["Mode"], "GOVERNANCE")
check("default-locked delete refused", code(lambda: s3.delete_object(Bucket="lockb", Key="d", VersionId=d)), "AccessDenied")
check("default over max refused", code(lambda: s3.put_object_lock_configuration(Bucket="lockb",
      ObjectLockConfiguration={"ObjectLockEnabled": "Enabled",
      "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Years": 5}}})), "InvalidArgument")
check("bucket with locked versions can't be deleted", code(lambda: root.delete_bucket(Bucket="lockb")), "BucketNotEmpty")

# Lifecycle may not remove locked noncurrent versions.
s3.put_bucket_lifecycle_configuration(Bucket="lockb", LifecycleConfiguration={"Rules": [
    {"ID": "nc", "Status": "Enabled", "Filter": {"Prefix": ""},
     "NoncurrentVersionExpiration": {"NoncurrentDays": 1}}]})
print(f"\nPYPASS={PASS} PYFAIL={FAIL}")
open("/tmp/fs3-ol-vid", "w").write(v)
sys.exit(1 if FAIL else 0)
PY
stop
start --lifecycle-now --lifecycle-time-offset 172800
for _ in $(seq 1 50); do grep -q "lifecycle: .*expired" "$LOG" && break; sleep 0.1; done
V=$(cat /tmp/fs3-ol-vid); rm -f /tmp/fs3-ol-vid
left=$(python3 - "$URL" "$A" "$AS" "$V" <<'PY'
import sys, boto3
s3 = boto3.client("s3", endpoint_url=sys.argv[1], aws_access_key_id=sys.argv[2],
                  aws_secret_access_key=sys.argv[3], region_name="us-east-1")
print(s3.get_object(Bucket="lockb", Key="c", VersionId=sys.argv[4])["Body"].read().decode())
PY
)
stop
if [ "$left" = "compliance" ]; then
    echo "."; echo "===== objlock e2e: lifecycle skipped locked version, all passed ====="
else
    echo "FAIL: lifecycle removed a locked version"; exit 1
fi
