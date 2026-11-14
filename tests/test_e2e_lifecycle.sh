#!/usr/bin/env bash
#
# tests/test_e2e_lifecycle.sh — item 5: ?lifecycle CRUD and the sweeper
# (driven with --lifecycle-now and a shifted sweeper clock).
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 22500 + RANDOM % 300 ))}
MPORT=$((PORT + 1))
DATA=/tmp/fs3-lc-e2e-$$
LOG=/tmp/fs3-lc-e2e-$$.log
URL="http://127.0.0.1:$PORT"
AK=AKIALIFECYCLE001
SK=lifecycleSecret0123456789012345678901234567

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; } || true
    rm -rf "$DATA" "$LOG"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

start() {
    : > "$LOG"
    "$ROOT/fs3" -p "$PORT" -d "$DATA" --auth "$AK:$SK" --require-auth \
        --metrics-port "$MPORT" "$@" >"$LOG" 2>&1 &
    SP=$!
    sleep 0.4
    kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }
}
stop() { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; SP=; }
wait_sweep() {
    for _ in $(seq 1 50); do grep -q "lifecycle: .*expired" "$LOG" && return 0; sleep 0.1; done
    return 1
}

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}
py() {
    python3 - "$@" <<PY
import sys, boto3, botocore
s3 = boto3.client("s3", endpoint_url="$URL", aws_access_key_id="$AK",
                  aws_secret_access_key="$SK", region_name="us-east-1")
def code(f):
    try:
        f(); return "ok"
    except botocore.exceptions.ClientError as e:
        return e.response["Error"]["Code"]
cmd = sys.argv[1]
R = lambda **kw: {"LifecycleConfiguration": {"Rules": [dict(Status="Enabled", **kw)]}}
if cmd == "setup":
    s3.create_bucket(Bucket="lcb")
    for k in ("tmp/a", "tmp/b", "keep/c", "logs/d"):
        s3.put_object(Bucket="lcb", Key=k, Body=b"x")
    s3.create_multipart_upload(Bucket="lcb", Key="uploads/big")
    s3.create_multipart_upload(Bucket="lcb", Key="other/big")
    s3.create_bucket(Bucket="lcv")
    s3.put_bucket_versioning(Bucket="lcv", VersioningConfiguration={"Status": "Enabled"})
    s3.put_object(Bucket="lcv", Key="doc", Body=b"v1")
    s3.put_object(Bucket="lcv", Key="doc", Body=b"v2")
    s3.put_object(Bucket="lcv", Key="tmp/x", Body=b"t")
    s3.put_bucket_lifecycle_configuration(Bucket="lcv", LifecycleConfiguration={"Rules": [
        {"ID": "nc", "Status": "Enabled", "Filter": {"Prefix": ""},
         "NoncurrentVersionExpiration": {"NoncurrentDays": 1}},
        {"ID": "tmp", "Status": "Enabled", "Filter": {"Prefix": "tmp/"}, "Expiration": {"Days": 1}}]})
elif cmd == "lcv":
    r = s3.list_object_versions(Bucket="lcv")
    print(len(r.get("Versions", [])), len(r.get("DeleteMarkers", [])),
          s3.get_object(Bucket="lcv", Key="doc")["Body"].read().decode())
elif cmd == "nosuch":
    print(code(lambda: s3.get_bucket_lifecycle_configuration(Bucket="lcb")))
elif cmd == "put":
    print(code(lambda: s3.put_bucket_lifecycle_configuration(Bucket="lcb", LifecycleConfiguration={"Rules": [
        {"ID": "tmp", "Status": "Enabled", "Filter": {"Prefix": "tmp/"}, "Expiration": {"Days": 1}},
        {"ID": "logs-off", "Status": "Disabled", "Filter": {"Prefix": "logs/"}, "Expiration": {"Days": 1}},
        {"ID": "mpu", "Status": "Enabled", "Filter": {"Prefix": "uploads/"},
         "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}}]})))
elif cmd == "get":
    r = s3.get_bucket_lifecycle_configuration(Bucket="lcb"); print(len(r["Rules"]))
elif cmd == "transition":
    print(code(lambda: s3.put_bucket_lifecycle_configuration(Bucket="lcb", **R(
        Filter={"Prefix": ""}, Transitions=[{"Days": 30, "StorageClass": "GLACIER"}]))))
elif cmd == "tag":
    print(code(lambda: s3.put_bucket_lifecycle_configuration(Bucket="lcb", **R(
        Filter={"Tag": {"Key": "a", "Value": "b"}}, Expiration={"Days": 1}))))
elif cmd == "zero":
    print(code(lambda: s3.put_bucket_lifecycle_configuration(Bucket="lcb", **R(
        Filter={"Prefix": ""}, Expiration={"Days": 0}))))
elif cmd == "pastdate":
    import datetime
    print(code(lambda: s3.put_bucket_lifecycle_configuration(Bucket="lcb", **R(
        Filter={"Prefix": "nothing/"}, Expiration={"Date": datetime.datetime(2020, 1, 1)}))))
elif cmd == "pastdate-confirmed":
    import datetime
    def add(request, **kw): request.headers["x-fs3-confirm-immediate-expiry"] = "true"
    s3.meta.events.register("before-sign.s3.PutBucketLifecycleConfiguration", add)
    print(code(lambda: s3.put_bucket_lifecycle_configuration(Bucket="lcb", **R(
        Filter={"Prefix": "nothing/"}, Expiration={"Date": datetime.datetime(2020, 1, 1)}))))
elif cmd == "keys":
    r = s3.list_objects_v2(Bucket="lcb"); print(" ".join(o["Key"] for o in r.get("Contents", [])))
elif cmd == "uploads":
    r = s3.list_multipart_uploads(Bucket="lcb"); print(" ".join(sorted(u["Key"] for u in r.get("Uploads", []))))
elif cmd == "delete":
    print(code(lambda: s3.delete_bucket_lifecycle(Bucket="lcb")))
PY
}

start
py setup
check_eq "no config → NoSuchLifecycleConfiguration" "$(py nosuch)" "NoSuchLifecycleConfiguration"
check_eq "put lifecycle" "$(py put)" "ok"
check_eq "get lifecycle" "$(py get)" "3"
check_eq "Transition → NotImplemented" "$(py transition)" "NotImplemented"
check_eq "Tag filter → NotImplemented" "$(py tag)" "NotImplemented"
check_eq "Days 0 rejected" "$(py zero)" "InvalidArgument"
check_eq "past Date without confirmation rejected" "$(py pastdate)" "InvalidArgument"
check_eq "config unchanged after rejects" "$(py get)" "3"
check_eq "nothing swept yet" "$(py keys)" "keep/c logs/d tmp/a tmp/b"
stop

# Dry run two days ahead: logs, deletes nothing.
start --lifecycle-now --lifecycle-dry-run --lifecycle-time-offset 172800
wait_sweep || true
check_eq "dry run logged" "$(grep -c 'would expire lcb/tmp/' "$LOG" || true)" "2"
check_eq "dry run deleted nothing" "$(py keys)" "keep/c logs/d tmp/a tmp/b"
stop

# Real sweep with a clock shifted by 12 h: nothing old enough yet.
start --lifecycle-now --lifecycle-time-offset 0
wait_sweep || true
check_eq "fresh objects not expired" "$(py keys)" "keep/c logs/d tmp/a tmp/b"
stop

# Two days ahead: tmp/ expires, disabled rule ignored, uploads/ MPU aborted.
start --lifecycle-now --lifecycle-time-offset 172800
wait_sweep || { echo "sweep did not run" >&2; cat "$LOG" >&2; }
check_eq "tmp/ expired, others kept" "$(py keys)" "keep/c logs/d"
check_eq "uploads/ MPU aborted, other kept" "$(py uploads)" "other/big"
check_eq "versioned: noncurrent versions expired, tmp/x behind a marker, doc current kept" "$(py lcv)" "1 1 v2"
m=$(curl -s "http://127.0.0.1:$MPORT/metrics")
check_eq "expired counter" "$(echo "$m" | grep '^fs3_lifecycle_expired_total' | cut -d' ' -f2)" "5"
check_eq "aborted counter" "$(echo "$m" | grep '^fs3_lifecycle_aborted_mpu_total' | cut -d' ' -f2)" "1"
check_eq "past Date with confirmation header accepted" "$(py pastdate-confirmed)" "ok"
check_eq "delete lifecycle" "$(py delete)" "ok"
check_eq "gone after delete" "$(py nosuch)" "NoSuchLifecycleConfiguration"
stop

echo
echo "===== lifecycle e2e: $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
