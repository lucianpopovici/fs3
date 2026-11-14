#!/usr/bin/env bash
#
# tests/test_e2e_keys.sh — round 2 item 4: key expiry, disable,
# read-only keys, last-used.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 27300 + RANDOM % 200 ))}
MPORT=$((PORT + 1))
T=/tmp/fs3-keys-e2e-$$
DATA=$T.data
LOG=$T.log
SOCK=$T.sock
URL="http://127.0.0.1:$PORT"
A=AKIAKEYSALICE001; AS=keysAliceSecret01234567890123456789012
R=AKIAKEYSREAD0001; RS=keysReadSecret012345678901234567890123

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; } || true
    rm -rf "$DATA" "$T".*
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

printf '%s:%s:alice\n%s:%s:alice:created=1763107200,ro\n' "$A" "$AS" "$R" "$RS" > "$T.creds"
chmod 600 "$T.creds"

start() {
    "$ROOT/fs3" -p "$PORT" -d "$DATA" --credentials-file "$T.creds" --require-auth \
        --metrics-port "$MPORT" --admin-socket "$SOCK" --audit-log "$T.audit" "$@" >>"$LOG" 2>&1 &
    SP=$!
    for _ in $(seq 50); do [ -S "$SOCK" ] && curl -s -o /dev/null "$URL/" && break; sleep 0.1; done
    kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }
}
start --key-max-age-days 30

python3 -u - "$URL" "$A" "$AS" "$R" "$RS" "$SOCK" "$T" "$MPORT" <<'PY'
import sys, json, time, subprocess, urllib.request, boto3, botocore
from botocore.config import Config
url, a, asec, r, rsec, sock, T, mport = sys.argv[1:9]
def mk(ak, sk):
    return boto3.client("s3", endpoint_url=url, aws_access_key_id=ak, aws_secret_access_key=sk,
                        region_name="us-east-1", config=Config(signature_version="s3v4",
                        retries={"max_attempts": 1}))
s3, ro = mk(a, asec), mk(r, rsec)
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
    out = subprocess.run(cmd, capture_output=True, text=True).stdout
    return json.loads(out)
def key(ak): return next(k for k in adm("GET", "/v1/keys")["keys"] if k["access_key"] == ak)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def http(u):
    try:
        with opener.open(u) as resp: return resp.status, resp.read()
    except urllib.error.HTTPError as e: return e.code, e.read()

s3.create_bucket(Bucket="keyb")
s3.put_object(Bucket="keyb", Key="k", Body=b"data")

# --- read-only key ------------------------------------------------------
check("ro: GET", code(lambda: ro.get_object(Bucket="keyb", Key="k")), "ok")
check("ro: list", code(lambda: ro.list_objects_v2(Bucket="keyb")), "ok")
check("ro: HEAD bucket", code(lambda: ro.head_bucket(Bucket="keyb")), "ok")
check("ro: PUT refused", code(lambda: ro.put_object(Bucket="keyb", Key="x", Body=b"x")), "AccessDenied")
check("ro: DELETE refused", code(lambda: ro.delete_object(Bucket="keyb", Key="k")), "AccessDenied")
check("ro: bulk delete refused", code(lambda: ro.delete_objects(Bucket="keyb",
      Delete={"Objects": [{"Key": "k"}]})), "AccessDenied")
check("ro: PutBucketPolicy refused", code(lambda: ro.put_bucket_policy(Bucket="keyb",
      Policy='{"Version":"2012-10-17","Statement":[]}')), "AccessDenied")
check("ro: CreateBucket refused", code(lambda: ro.create_bucket(Bucket="robucket")), "AccessDenied")
check("ro: multipart refused", code(lambda: ro.create_multipart_upload(Bucket="keyb", Key="m")), "AccessDenied")
check("ro: copy refused", code(lambda: ro.copy_object(Bucket="keyb", Key="c", CopySource="keyb/k")), "AccessDenied")
check("object survived", s3.get_object(Bucket="keyb", Key="k")["Body"].read(), b"data")

# --- admin API: attributes and last_used ------------------------------------
k = key(r)
check("GET /v1/keys attributes", (k["read_only"], k["created"], k["disabled"]), (True, 1763107200, False))
check("last_used recorded", k["last_used"] > 0, True)
check("secret never listed", r and rsec not in json.dumps(adm("GET", "/v1/keys")), True)
c = subprocess.run(["curl", "-sS", "--unix-socket", sock, "-X", "POST", "http://x/v1/keys",
                    "--data-binary", json.dumps({"user": "bob", "read_only": True})],
                   capture_output=True, text=True).stdout
nk = json.loads(c)
check("POST read_only + --key-max-age-days default expiry",
      (nk["read_only"], 29 * 86400 < nk["expires"] - nk["created"] <= 30 * 86400), (True, True))
nk2 = json.loads(subprocess.run(["curl", "-sS", "--unix-socket", sock, "-X", "POST", "http://x/v1/keys",
                                 "--data-binary", json.dumps({"user": "carol", "expires": 4102444800})],
                                capture_output=True, text=True).stdout)
check("POST explicit expires", nk2["expires"], 4102444800)
carol = mk(nk2["access_key"], nk2["secret_key"])
check("new key works", code(lambda: carol.list_buckets()), "ok")

# --- disable / re-enable: immediate, same answer as an unknown key -----------
adm("PATCH", f"/v1/keys/{nk2['access_key']}", {"disabled": True})
check("disabled key → AccessDenied at once", code(lambda: carol.list_buckets()), "AccessDenied")
ghost = mk("AKIANOSUCHKEY0001", "x" * 40)
check("unknown key → the same AccessDenied", code(lambda: ghost.list_buckets()), "AccessDenied")
d1 = http(carol.generate_presigned_url("list_buckets"))
d2 = http(ghost.generate_presigned_url("list_buckets"))
check("disabled and unknown: identical bodies", d1, d2)
adm("PATCH", f"/v1/keys/{nk2['access_key']}", {"disabled": False})
check("re-enabled", code(lambda: carol.list_buckets()), "ok")
check("PATCH bad body → 400", "error" in adm("PATCH", f"/v1/keys/{nk2['access_key']}", {"disabled": "yes"}), True)
check("PATCH unknown key → 404", "error" in adm("PATCH", "/v1/keys/NOSUCH", {"disabled": True}), True)

# --- expiry --------------------------------------------------------------------
soon = int(time.time()) + 4
adm("PATCH", f"/v1/keys/{nk2['access_key']}", {"expires": soon + 60})
check("presigned URL outliving its key refused",
      http(carol.generate_presigned_url("get_object", Params={"Bucket": "keyb", "Key": "k"}, ExpiresIn=3600))[0], 403)
adm("PATCH", f"/v1/keys/{nk2['access_key']}", {"expires": soon})
check("key valid until expiry", code(lambda: carol.list_buckets()), "ok")
pre = carol.generate_presigned_url("list_buckets", ExpiresIn=2)
m = opener.open(f"http://127.0.0.1:{mport}/metrics").read().decode()
check("fs3_keys_expiring_soon", "fs3_keys_expiring_soon 1" in m, True)
check("fs3_keys_unused_90d (ro key created long ago is in use)", "fs3_keys_unused_90d 0" in m, True)
time.sleep(5)
check("expired key → AccessDenied", code(lambda: carol.list_buckets()), "AccessDenied")
adm("PATCH", f"/v1/keys/{nk2['access_key']}", {"expires": 0})
check("expiry cleared", code(lambda: carol.list_buckets()), "ok")

# --- lockout guard --------------------------------------------------------------
for k in adm("GET", "/v1/keys")["keys"]:
    if k["access_key"] != a:
        adm("PATCH", f"/v1/keys/{k['access_key']}", {"disabled": True})
r409 = adm("PATCH", f"/v1/keys/{a}", {"disabled": True})
check("refuses to disable the last enabled key", "error" in r409, True)
for k in adm("GET", "/v1/keys")["keys"]:
    adm("PATCH", f"/v1/keys/{k['access_key']}", {"disabled": False})
json.dump({"ro_last_used": key(r)["last_used"]}, open(T + ".lu", "w"))
print(f"\nPYPASS={PASS} PYFAIL={FAIL}")
sys.exit(1 if FAIL else 0)
PY

grep -q '"deny":"key_disabled"' "$T.audit" || { echo "FAIL: key_disabled not in audit log"; exit 1; }
grep -q '"deny":"key_expired"' "$T.audit" || { echo "FAIL: key_expired not in audit log"; exit 1; }
grep -q '"deny":"unknown_key"' "$T.audit" || { echo "FAIL: unknown_key not in audit log"; exit 1; }
grep -q '"deny":"presign_outlives_key"' "$T.audit" || { echo "FAIL: presign_outlives_key not in audit log"; exit 1; }
echo "audit log records the real refusal reasons"

# last_used survives SIGHUP and restart.
LU=$(python3 -c "import json; print(json.load(open('$T.lu'))['ro_last_used'])")
lu_now() { curl -sS --unix-socket "$SOCK" http://x/v1/keys | python3 -c "
import sys, json; print(next(k['last_used'] for k in json.load(sys.stdin)['keys'] if k['access_key'] == '$R'))"; }
kill -HUP "$SP"; sleep 1.2
[ "$(lu_now)" = "$LU" ] || { echo "FAIL: last_used lost on SIGHUP ($(lu_now) != $LU)"; exit 1; }
kill "$SP"; wait "$SP" 2>/dev/null || true
[ -s "$DATA/keys.state" ] || { echo "FAIL: keys.state not written at shutdown"; exit 1; }
grep -q "$A" "$T.creds" && ! grep -q "last" "$T.creds" || { echo "FAIL: credentials file touched by last-used"; exit 1; }
start
[ "$(lu_now)" = "$LU" ] || { echo "FAIL: last_used lost on restart ($(lu_now) != $LU)"; exit 1; }
echo "last_used survives SIGHUP and restart"

# A bad attribute in the file: the reload keeps the live keys.
cp "$T.creds" "$T.creds.good"
printf 'AKIAKEYSBAD00001:badSecret0123456789:dave:sometimes\n' >> "$T.creds"
kill -HUP "$SP"; sleep 1.2
grep -q "keeping old credentials" "$LOG" || { echo "FAIL: bad attribute not refused"; exit 1; }
echo "unknown attribute refused; live keys kept"
echo "===== keys e2e: done ====="
