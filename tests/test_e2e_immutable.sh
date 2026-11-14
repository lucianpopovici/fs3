#!/usr/bin/env bash
#
# tests/test_e2e_immutable.sh — round 2 item 9: layout-2 object-lock
# buckets and FS_IMMUTABLE_FL through fs3-lockd. Needs root (to run the
# helper and to drop fs3 to an unprivileged uid without capabilities);
# skips otherwise. The data dir must be on a filesystem with chattr +i
# support (ext4/Btrfs/XFS).
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
if [ "$(id -u)" != 0 ] && [ "${FS3_TEST_ROOT:-0}" != 1 ]; then
    echo "SKIP: needs root (FS3_TEST_ROOT=1)"; echo "===== immutable e2e: skipped ====="; exit 0
fi
command -v setpriv >/dev/null || { echo "SKIP: setpriv missing"; exit 0; }
SVC=65534
PORT=${FS3_TEST_PORT:-$(( 28300 + RANDOM % 150 ))}
T=/tmp/fs3-imm-$$
DATA=$T/data
SOCK=$T/lockd.sock
JOURNAL=/tmp/fs3-imm-journal-$$
LOG=$T/fs3.log; LLOG=/tmp/fs3-imm-lockd-$$.log
URL="http://127.0.0.1:$PORT"
AK=AKIAIMMUTABLE001; SK=immutableSecret0123456789012345678901

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; [ $? -ne 159 ] || echo "FAIL: server died with SIGSYS (seccomp blocked a syscall; see --seccomp=log)" >&2; } || true
    [ -n "${LP:-}" ] && { kill "$LP" 2>/dev/null; wait "$LP" 2>/dev/null; } || true
    # Clear any leftover immutable flags so the tree can be removed.
    [ -d "$T" ] && find "$T" -type f -exec chattr -i {} + 2>/dev/null || true
    rm -rf "$T" "$JOURNAL" "$LLOG"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 fs3-lockd >/dev/null 2>&1)

mkdir -p "$DATA"; chmod 755 "$T"; chown -R $SVC:$SVC "$DATA" "$T"
touch "$T/probe" && chattr +i "$T/probe" 2>/dev/null && chattr -i "$T/probe" || {
    echo "SKIP: filesystem without FS_IMMUTABLE_FL"; exit 0; }
rm -f "$T/probe"

as_svc() { setpriv --reuid=$SVC --regid=$SVC --clear-groups --inh-caps=-all --bounding-set=-all "$@"; }
start_lockd() {
    "$ROOT/fs3-lockd" --root "$DATA" --socket "$SOCK" --journal "$JOURNAL" --peer-uid $SVC >>"$LLOG" 2>&1 &
    LP=$!
    for _ in $(seq 30); do [ -S "$SOCK" ] && break; sleep 0.1; done
}
start_fs3() {
    as_svc ${FS3_WRAP:-} "$ROOT/fs3" -p "$PORT" -d "$DATA" --auth "$AK:$SK:alice" --require-auth \
        "$@" >>"$LOG" 2>&1 &
    SP=$!
    for _ in $(seq 50); do curl -s -o /dev/null "$URL/" && break; sleep 0.1; done
}

# Fail closed: --lock-immutable without a reachable helper refuses to start.
touch "$LOG"; chown $SVC "$LOG"
as_svc "$ROOT/fs3" -p "$PORT" -d "$DATA" --lock-immutable --lockd-socket "$SOCK" >>"$LOG" 2>&1 && st=started || st=refused
[ "$st" = refused ] && grep -q "refusing to start" "$LOG" || {
    echo "FAIL: --lock-immutable without fs3-lockd: $st"; tail -5 "$LOG"; exit 1; }
echo "refuses to start without fs3-lockd"

start_lockd
start_fs3 --lock-immutable --lockd-socket "$SOCK"
kill -0 "$SP" 2>/dev/null || { echo "server did not start"; cat "$LOG"; exit 1; }

python3 -u - "$URL" "$AK" "$SK" "$DATA" "$SOCK" "$SVC" "$T" <<'PY'
import sys, os, glob, time, datetime, subprocess, boto3, botocore
from botocore.config import Config
url, ak, sk, data, sock, svc_uid, T = sys.argv[1:8]
s3 = boto3.client("s3", endpoint_url=url, aws_access_key_id=ak, aws_secret_access_key=sk,
                  region_name="us-east-1", config=Config(signature_version="s3v4", retries={"max_attempts": 1}))
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
def svc(*cmd):
    return subprocess.run(["setpriv", f"--reuid={svc_uid}", f"--regid={svc_uid}", "--clear-groups",
                           "--inh-caps=-all", "--bounding-set=-all", *cmd], capture_output=True, text=True,
                          cwd="/")
def immutable(p):
    out = subprocess.run(["lsattr", p], capture_output=True, text=True).stdout
    return len(out) > 4 and out[4] == "i"
def vfile(bucket, vid):
    v = vid.replace("-", "")
    hits = [p for p in glob.glob(f"{data}/versions/{bucket}/*/*/*/*") if p.endswith(v) or p.endswith(vid)]
    return hits[0] if hits else None
def lockd(req):
    r = svc("python3", "-c", f"import socket;s=socket.socket(socket.AF_UNIX);s.connect({sock!r});"
            f"s.sendall({(req + chr(10)).encode()!r});print(s.recv(300).decode().strip())")
    if not r.stdout.strip(): print("\nlockd helper stderr:", r.stderr.strip()[-300:])
    return r.stdout.strip()
now = lambda: datetime.datetime.now(datetime.timezone.utc)

s3.create_bucket(Bucket="immb", ObjectLockEnabledForBucket=True)
r1 = s3.put_object(Bucket="immb", Key="k", Body=b"v1", ObjectLockMode="COMPLIANCE",
                   ObjectLockRetainUntilDate=now() + datetime.timedelta(seconds=40))
v1 = r1["VersionId"]
f1 = vfile("immb", v1)
check("layout 2: the version lives in versions/", f1 is not None, True)
dpath = glob.glob(f"{data}/data/immb/*/*/*")
check("layout 2: data/ holds a symlink", len(dpath) == 1 and os.path.islink(dpath[0]), True)
check("COMPLIANCE version is immutable", immutable(f1), True)
check("service user can't rm it", svc("rm", "-f", f1).returncode != 0 and os.path.exists(f1), True)
check("service user can't chattr -i it", svc("chattr", "-i", f1).returncode != 0 and immutable(f1), True)
check("API delete of the version refused", code(lambda: s3.delete_object(Bucket="immb", Key="k", VersionId=v1)),
      "AccessDenied")
check("early CLEAR refused by the helper even when fs3's uid asks", lockd(f"CLEAR {f1}").startswith("ERR retained"),
      True)
check("SET can't shorten retention", lockd(f"SET {f1} 1 0"), "OK")
check("…still refused", lockd(f"CLEAR {f1}").startswith("ERR retained"), True)
check("path outside the store refused", lockd("SET /etc/passwd 0 0").startswith("ERR"), True)
check("symlink path refused", lockd(f"SET {dpath[0]} 0 0").startswith("ERR"), True)

# Overwrite still makes a new current version.
r2 = s3.put_object(Bucket="immb", Key="k", Body=b"v2")
check("overwrite → new current", s3.get_object(Bucket="immb", Key="k")["Body"].read(), b"v2")
check("old version still readable", s3.get_object(Bucket="immb", Key="k", VersionId=v1)["Body"].read(), b"v1")
vs = s3.list_object_versions(Bucket="immb", Prefix="k")["Versions"]
check("two versions listed, no duplicates", sorted(v["VersionId"] for v in vs), sorted([v1, r2["VersionId"]]))
check("listing shows the key once", [o["Key"] for o in s3.list_objects_v2(Bucket="immb").get("Contents", [])], ["k"])
s3.delete_object(Bucket="immb", Key="k")
check("delete marker hides the key", code(lambda: s3.head_object(Bucket="immb", Key="k")), "404")
check("old versions survive the marker", s3.get_object(Bucket="immb", Key="k", VersionId=v1)["Body"].read(), b"v1")

# Legal hold: immutable until HOLD_OFF; then deletable.
r3 = s3.put_object(Bucket="immb", Key="held", Body=b"h", ObjectLockLegalHoldStatus="ON")
f3 = vfile("immb", r3["VersionId"])
check("legal hold → immutable", immutable(f3), True)
check("held version: delete refused", code(lambda: s3.delete_object(Bucket="immb", Key="held",
      VersionId=r3["VersionId"])), "AccessDenied")
s3.put_object_legal_hold(Bucket="immb", Key="held", VersionId=r3["VersionId"], LegalHold={"Status": "OFF"})
check("hold off → delete allowed (helper clears, fs3 unlinks)",
      code(lambda: s3.delete_object(Bucket="immb", Key="held", VersionId=r3["VersionId"])), "ok")
check("…file gone", os.path.exists(f3), False)

# Expiry: after retention, the delete path gets CLEAR and works.
r4 = s3.put_object(Bucket="immb", Key="short", Body=b"s", ObjectLockMode="COMPLIANCE",
                   ObjectLockRetainUntilDate=now() + datetime.timedelta(seconds=3))
f4 = vfile("immb", r4["VersionId"])
check("short retention → immutable", immutable(f4), True)
time.sleep(4.2)
check("after expiry the version deletes", code(lambda: s3.delete_object(Bucket="immb", Key="short",
      VersionId=r4["VersionId"])), "ok")
check("…file gone", os.path.exists(f4), False)

# GOVERNANCE is not made immutable (meant to be bypassable).
r5 = s3.put_object(Bucket="immb", Key="gov", Body=b"g", ObjectLockMode="GOVERNANCE",
                   ObjectLockRetainUntilDate=now() + datetime.timedelta(days=1))
check("GOVERNANCE not immutable", immutable(vfile("immb", r5["VersionId"])), False)
open(T + "/f1", "w").write(f1)
print(f"\nPYPASS={PASS} PYFAIL={FAIL}")
sys.exit(1 if FAIL else 0)
PY

# Helper restart keeps its journal: early CLEAR still refused.
F1=$(cat "$T/f1")
kill "$LP"; wait "$LP" 2>/dev/null || true
start_lockd
rep=$(cd / && as_svc python3 -c "import socket;s=socket.socket(socket.AF_UNIX);s.connect('$SOCK');s.sendall(b'CLEAR $F1\n');print(s.recv(300).decode().strip())")
case "$rep" in "ERR retained"*) echo "journal survives a helper restart";; *) echo "FAIL: after restart: $rep"; exit 1;; esac
grep -q "^SET " "$JOURNAL" || { echo "FAIL: journal empty"; exit 1; }
[ "$(stat -c %a "$JOURNAL")" = 600 ] || { echo "FAIL: journal not 0600"; exit 1; }
echo "===== immutable e2e: done ====="
