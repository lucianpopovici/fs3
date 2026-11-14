#!/usr/bin/env bash
#
# tests/test_e2e_quota.sh — round 2 item 2: bucket and user quotas.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 26700 + RANDOM % 200 ))}
MPORT=$((PORT + 1))
T=/tmp/fs3-quota-e2e-$$
DATA=$T.data
LOG=$T.log
SOCK=$T.sock
URL="http://127.0.0.1:$PORT"
A=AKIAQUOTAALICE01; AS=quotaAliceSecret0123456789012345678901
B=AKIAQUOTABOB0001; BS=quotaBobSecret012345678901234567890123

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; } || true
    rm -rf "$DATA" "$T".*
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

printf '%s:%s:alice\n%s:%s:bob\n' "$A" "$AS" "$B" "$BS" > "$T.creds"

start() {
    "$ROOT/fs3" -p "$PORT" -d "$DATA" --credentials-file "$T.creds" --allow-public --allow-public-write \
        --metrics-port "$MPORT" --admin-socket "$SOCK" --mpu-min-part-size 0 \
        --audit-log "$T.audit" "$@" >>"$LOG" 2>&1 &
    SP=$!
    for _ in $(seq 50); do [ -S "$SOCK" ] && curl -s -o /dev/null "$URL/" && break; sleep 0.1; done
    kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }
}
start

run_py() {
python3 -u - "$URL" "$A" "$AS" "$B" "$BS" "$SOCK" "$MPORT" "$1" <<'PY'
import sys, os, json, socket, subprocess, time, threading, boto3, botocore
from botocore.config import Config
url, a, asec, b, bsec, sock, mport, phase = sys.argv[1:9]
mk = lambda ak, sk: boto3.client("s3", endpoint_url=url, aws_access_key_id=ak, aws_secret_access_key=sk,
                                 region_name="us-east-1", config=Config(signature_version="s3v4",
                                 retries={"max_attempts": 1}))
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
def adm(method, path, body=None):
    cmd = ["curl", "-sS", "--unix-socket", sock, "-X", method, "http://x" + path]
    if body is not None: cmd += ["--data-binary", json.dumps(body)]
    return json.loads(subprocess.run(cmd, capture_output=True, text=True).stdout)
def usage(bk): return adm("GET", f"/v1/buckets/{bk}/quota")["usage"]
def wait_reserved_zero(bk, t=5):
    for _ in range(int(t * 20)):
        if usage(bk)["reserved"] == 0: return 0
        time.sleep(0.05)
    return usage(bk)["reserved"]

if phase == "main":
    s3.create_bucket(Bucket="qaa")
    r = adm("PUT", "/v1/buckets/qaa/quota", {"max_bytes": 1000, "max_objects": 0})
    check("set bucket quota", r["quota"], {"max_bytes": 1000, "max_objects": 0, "explicit": True})
    check("bad quota body → 400", "error" in adm("PUT", "/v1/buckets/qaa/quota", {"max_bytes": -1}), True)

    # Exact boundary.
    check("PUT 600", code(lambda: s3.put_object(Bucket="qaa", Key="a", Body=b"x" * 600)), "ok")
    check("PUT 400 (exactly at the limit)", code(lambda: s3.put_object(Bucket="qaa", Key="b", Body=b"x" * 400)), "ok")
    check("usage at the limit", (usage("qaa")["bytes"], usage("qaa")["objects"]), (1000, 2))
    check("one more byte → QuotaExceeded", code(lambda: s3.put_object(Bucket="qaa", Key="c", Body=b"x")), "QuotaExceeded")
    check("refused object not stored", code(lambda: s3.head_object(Bucket="qaa", Key="c")), "404")
    check("an empty object still fits", code(lambda: s3.put_object(Bucket="qaa", Key="e", Body=b"")), "ok")
    # Refusal happens before any byte is stored, even for an overwrite
    # that would shrink usage (S3-style "used + reserved + n > limit").
    check("overwrite at a full quota refused", code(lambda: s3.put_object(Bucket="qaa", Key="a", Body=b"y")),
          "QuotaExceeded")
    s3.delete_object(Bucket="qaa", Key="b")
    check("delete releases", (usage("qaa")["bytes"], usage("qaa")["objects"]), (600, 2))
    # Unversioned overwrite charges new - old.
    check("overwrite smaller", code(lambda: s3.put_object(Bucket="qaa", Key="a", Body=b"y" * 100)), "ok")
    check("overwrite charged new - old", usage("qaa")["bytes"], 100)

    # Chunked transfer with no declared length: refused once it crosses.
    pu = s3.generate_presigned_url("put_object", Params={"Bucket": "qaa", "Key": "chunked"}, ExpiresIn=60)
    def chunked(n):
        p = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-X", "PUT",
                            "-H", "Transfer-Encoding: chunked", "-T", "-", pu],
                           input=b"z" * n, capture_output=True)
        return p.stdout.decode()
    check("chunked PUT under the limit", chunked(800), "200")
    check("chunked PUT crossing the limit → 403", chunked(5000), "403")
    check("crossing chunked PUT not stored (old object kept)",
          s3.head_object(Bucket="qaa", Key="chunked")["ContentLength"], 800)
    check("no reservation left behind", wait_reserved_zero("qaa"), 0)

    # Lowering below usage blocks writes, keeps data; clearing lifts it.
    adm("PUT", "/v1/buckets/qaa/quota", {"max_bytes": 10})
    check("quota below usage blocks writes", code(lambda: s3.put_object(Bucket="qaa", Key="n", Body=b"1")), "QuotaExceeded")
    check("…and keeps data", len(s3.get_object(Bucket="qaa", Key="chunked")["Body"].read()), 800)
    adm("DELETE", "/v1/buckets/qaa/quota")
    check("cleared quota", adm("GET", "/v1/buckets/qaa/quota")["quota"]["explicit"], False)
    check("writes again after clear", code(lambda: s3.put_object(Bucket="qaa", Key="n", Body=b"1" * 2000)), "ok")

    # Object-count limit.
    s3.create_bucket(Bucket="qcount")
    adm("PUT", "/v1/buckets/qcount/quota", {"max_objects": 2})
    s3.put_object(Bucket="qcount", Key="1", Body=b"1"); s3.put_object(Bucket="qcount", Key="2", Body=b"2")
    check("max_objects", code(lambda: s3.put_object(Bucket="qcount", Key="3", Body=b"3")), "QuotaExceeded")

    # Multipart crossing on part N; parts count while in flight.
    s3.create_bucket(Bucket="qmpu")
    adm("PUT", "/v1/buckets/qmpu/quota", {"max_bytes": 2500})
    uid = s3.create_multipart_upload(Bucket="qmpu", Key="m")["UploadId"]
    e1 = s3.upload_part(Bucket="qmpu", Key="m", UploadId=uid, PartNumber=1, Body=b"1" * 1000)["ETag"]
    e2 = s3.upload_part(Bucket="qmpu", Key="m", UploadId=uid, PartNumber=2, Body=b"2" * 1000)["ETag"]
    check("parts count while in flight", usage("qmpu")["bytes"], 2000)
    check("part 3 crosses → QuotaExceeded", code(lambda: s3.upload_part(Bucket="qmpu", Key="m", UploadId=uid,
          PartNumber=3, Body=b"3" * 1000)), "QuotaExceeded")
    e2b = s3.upload_part(Bucket="qmpu", Key="m", UploadId=uid, PartNumber=2, Body=b"2" * 500)["ETag"]
    check("re-uploaded part charges new - old", usage("qmpu")["bytes"], 1500)
    s3.complete_multipart_upload(Bucket="qmpu", Key="m", UploadId=uid,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": e1}, {"PartNumber": 2, "ETag": e2b}]})
    check("complete: parts become the object", (usage("qmpu")["bytes"], usage("qmpu")["objects"]), (1500, 1))
    uid = s3.create_multipart_upload(Bucket="qmpu", Key="m2")["UploadId"]
    s3.upload_part(Bucket="qmpu", Key="m2", UploadId=uid, PartNumber=1, Body=b"1" * 700)
    s3.abort_multipart_upload(Bucket="qmpu", Key="m2", UploadId=uid)
    check("abort releases parts", usage("qmpu")["bytes"], 1500)

    # Copy goes through the same reserve/commit.
    check("copy over the limit → QuotaExceeded", code(lambda: s3.copy_object(Bucket="qmpu", Key="m-copy",
          CopySource="qmpu/m")), "QuotaExceeded")

    # Versioned overwrite growth; version delete releases.
    s3.create_bucket(Bucket="qver")
    s3.put_bucket_versioning(Bucket="qver", VersioningConfiguration={"Status": "Enabled"})
    adm("PUT", "/v1/buckets/qver/quota", {"max_bytes": 1000})
    s3.put_object(Bucket="qver", Key="k", Body=b"1" * 400)
    v2 = s3.put_object(Bucket="qver", Key="k", Body=b"2" * 400)["VersionId"]
    check("versioned overwrite charges the full size", (usage("qver")["bytes"], usage("qver")["objects"]), (800, 2))
    check("third version crosses", code(lambda: s3.put_object(Bucket="qver", Key="k", Body=b"3" * 400)), "QuotaExceeded")
    s3.delete_object(Bucket="qver", Key="k")
    check("delete marker counts as an object", (usage("qver")["bytes"], usage("qver")["objects"]), (800, 3))
    s3.delete_object(Bucket="qver", Key="k", VersionId=v2)
    check("version delete releases", usage("qver")["bytes"], 400)

    # Per-user limit across two buckets.
    adm("PUT", "/v1/users/bob/quota", {"max_bytes": 1500})
    bob.create_bucket(Bucket="qbob1"); bob.create_bucket(Bucket="qbob2")
    bob.put_object(Bucket="qbob1", Key="x", Body=b"x" * 1000)
    check("user limit spans buckets", code(lambda: bob.put_object(Bucket="qbob2", Key="y", Body=b"y" * 600)),
          "QuotaExceeded")
    check("…fits under it", code(lambda: bob.put_object(Bucket="qbob2", Key="y", Body=b"y" * 500)), "ok")
    check("user usage", adm("GET", "/v1/users/bob/quota")["usage"]["bytes"], 1500)
    check("bad user name → 400", "error" in adm("GET", "/v1/users/a%2Fb/quota"), True)

    # Anonymous write is charged to the bucket owner.
    bob.put_bucket_policy(Bucket="qbob2", Policy=json.dumps({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": "*", "Action": "s3:PutObject", "Resource": "arn:aws:s3:::qbob2/*"}]}))
    adm("PUT", "/v1/users/bob/quota", {"max_bytes": 2000})
    st = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-X", "PUT",
                         "--data-binary", "a" * 300, f"{url}/qbob2/anon"], capture_output=True, text=True).stdout
    check("anonymous PUT accepted", st, "200")
    check("anonymous PUT charged to the owner", adm("GET", "/v1/users/bob/quota")["usage"]["bytes"], 1800)
    st = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "-X", "PUT",
                         "--data-binary", "a" * 300, f"{url}/qbob2/anon2"], capture_output=True, text=True).stdout
    check("anonymous PUT over the owner's quota → 403", st, "403")

    # Reservation leak: drop connections mid-PUT in a loop.
    s3.create_bucket(Bucket="qleak")
    adm("PUT", "/v1/buckets/qleak/quota", {"max_bytes": 10_000_000})
    put_url = s3.generate_presigned_url("put_object", Params={"Bucket": "qleak", "Key": "half"}, ExpiresIn=60)
    path = put_url.split(url, 1)[1]
    host, port = "127.0.0.1", int(url.rsplit(":", 1)[1])
    for i in range(20):
        sk = socket.create_connection((host, port))
        sk.sendall(f"PUT {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: 4000000\r\n\r\n".encode()
                   + b"q" * (50000 + i * 1000))
        time.sleep(0.01)
        sk.close()
    check("reservations return to 0 after dropped uploads", wait_reserved_zero("qleak"), 0)
    check("dropped uploads stored nothing", usage("qleak")["bytes"], 0)

    # Metrics and audit.
    import urllib.request
    m = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
        f"http://127.0.0.1:{mport}/metrics").read().decode()
    check("fs3_bucket_bytes gauge", 'fs3_bucket_bytes{bucket="qver"} 400' in m, True)
    check("fs3_bucket_quota_bytes gauge", 'fs3_bucket_quota_bytes{bucket="qver"} 1000' in m, True)
    check("fs3_quota_rejections_total counts", any(l.startswith("fs3_quota_rejections_total ") and
          int(l.split()[1]) > 0 for l in m.splitlines()), True)
    check("QuotaExceeded in fs3_errors_total", 'error="QuotaExceeded"' in m, True)
    check("admin bucket list carries usage", "usage" in adm("GET", "/v1/buckets")["buckets"][0], True)
    json.dump({k: usage(k) for k in ("qaa", "qmpu", "qver", "qbob1", "qbob2")},
              open(os.environ["SNAP"], "w"))

else:   # phase "restart": usage survives a restart (clean or not)
    snap = json.load(open(os.environ["SNAP"]))
    for k, v in snap.items():
        u = usage(k)
        check(f"{phase}: usage of {k}", (u["bytes"], u["objects"]), (v["bytes"], v["objects"]))
    check(f"{phase}: bucket quota kept", adm("GET", "/v1/buckets/qver/quota")["quota"]["max_bytes"], 1000)
    check(f"{phase}: user quota kept", adm("GET", "/v1/users/bob/quota")["quota"]["max_bytes"], 2000)
    check(f"{phase}: still enforced", code(lambda: s3.put_object(Bucket="qver", Key="z", Body=b"z" * 700)),
          "QuotaExceeded")

print(f"\nPYPASS={PASS} PYFAIL={FAIL}")
sys.exit(1 if FAIL else 0)
PY
}

export SNAP=$T.snap
run_py main
grep -q '"error":"QuotaExceeded"' "$T.audit" || { echo "FAIL: QuotaExceeded not in the audit log"; exit 1; }
echo "audit log records QuotaExceeded"

# Clean restart: usage files are trusted.
kill "$SP"; wait "$SP" 2>/dev/null || true
[ -f "$DATA/buckets/qaa/usage" ] || { echo "FAIL: no usage file after clean shutdown"; exit 1; }
start
grep -q "rebuilt usage" "$LOG" && { echo "FAIL: clean restart rebuilt usage"; exit 1; }
run_py clean-restart

# Unclean restart: SIGKILL leaves the running marker → rebuild from disk.
kill -9 "$SP"; wait "$SP" 2>/dev/null || true
[ -f "$DATA/.fs3-running" ] || { echo "FAIL: running marker missing after SIGKILL"; exit 1; }
: >"$LOG"
start
grep -q "rebuilt usage.*unclean" "$LOG" || { echo "FAIL: unclean restart did not rebuild"; cat "$LOG"; exit 1; }
run_py unclean-restart
echo "===== quota e2e: done ====="
