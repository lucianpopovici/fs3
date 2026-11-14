#!/usr/bin/env bash
#
# tests/test_e2e_policy.sh — item 9: bucket policies (public read with
# unsigned curl, prefix-limited sharing, explicit deny, lockout rule,
# --allow-public guards, trusted-proxy SecureTransport).
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 24100 + RANDOM % 300 ))}
DATA=/tmp/fs3-pol-e2e-$$
LOG=/tmp/fs3-pol-e2e-$$.log
URL="http://127.0.0.1:$PORT"
A=AKIAPOLICYALICE1; AS=policyAliceSecret0123456789012345678901
B=AKIAPOLICYBOB001; BS=policyBobSecret012345678901234567890123

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; } || true
    rm -rf "$DATA" "$LOG"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

start() {
    "$ROOT/fs3" -p "$PORT" -d "$DATA" --auth "$A:$AS:alice" --auth "$B:$BS:bob" "$@" >"$LOG" 2>&1 &
    SP=$!
    sleep 0.4
    kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }
}
stop() { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; SP=; }

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}
code() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }
py() {
    python3 - "$@" <<PY
import sys, json, boto3, botocore
who, cmd = sys.argv[1], sys.argv[2]
ak, sk = {"alice": ("$A", "$AS"), "bob": ("$B", "$BS")}[who]
s3 = boto3.client("s3", endpoint_url="$URL", aws_access_key_id=ak,
                  aws_secret_access_key=sk, region_name="us-east-1")
def code(f):
    try:
        f(); return "ok"
    except botocore.exceptions.ClientError as e:
        return e.response["Error"]["Code"]
P = lambda *st: json.dumps({"Version": "2012-10-17", "Statement": list(st)})
if cmd == "setup":
    s3.create_bucket(Bucket="polb")
    for k in ("public/a.txt", "private/s.txt", "home/bob/b.txt", "home/carol/c.txt"):
        s3.put_object(Bucket="polb", Key=k, Body=k.encode())
elif cmd == "public":
    print(code(lambda: s3.put_bucket_policy(Bucket="polb", Policy=P(
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::polb/public/*"},
        {"Effect": "Allow", "Principal": {"AWS": "bob"}, "Action": ["s3:GetObject", "s3:PutObject"],
         "Resource": "arn:aws:s3:::polb/home/bob/*"},
        {"Effect": "Deny", "Principal": "*", "Action": "s3:DeleteObject",
         "Resource": "arn:aws:s3:::polb/private/*"}))))
elif cmd == "publicwrite":
    print(code(lambda: s3.put_bucket_policy(Bucket="polb", Policy=P(
        {"Effect": "Allow", "Principal": "*", "Action": "s3:PutObject",
         "Resource": "arn:aws:s3:::polb/drop/*"}))))
elif cmd == "malformed":
    print(code(lambda: s3.put_bucket_policy(Bucket="polb", Policy='{"Version":"2012-10-17","Statement":[')))
elif cmd == "otherbucket":
    print(code(lambda: s3.put_bucket_policy(Bucket="polb", Policy=P(
        {"Effect": "Allow", "Principal": {"AWS": "bob"}, "Action": "s3:GetObject",
         "Resource": "arn:aws:s3:::otherb/*"}))))
elif cmd == "denyall":
    print(code(lambda: s3.put_bucket_policy(Bucket="polb", Policy=P(
        {"Effect": "Deny", "Principal": "*", "Action": "s3:*",
         "Resource": ["arn:aws:s3:::polb", "arn:aws:s3:::polb/*"]}))))
elif cmd == "tls":
    print(code(lambda: s3.put_bucket_policy(Bucket="polb", Policy=P(
        {"Effect": "Deny", "Principal": "*", "Action": "s3:*",
         "Resource": ["arn:aws:s3:::polb", "arn:aws:s3:::polb/*"],
         "Condition": {"Bool": {"aws:SecureTransport": "false"}}}))))
elif cmd == "getpol":
    print(code(lambda: s3.get_bucket_policy(Bucket="polb")))
elif cmd == "delpol":
    print(code(lambda: s3.delete_bucket_policy(Bucket="polb")))
elif cmd.startswith("get:"):
    print(code(lambda: s3.get_object(Bucket="polb", Key=cmd[4:])))
elif cmd.startswith("put:"):
    print(code(lambda: s3.put_object(Bucket="polb", Key=cmd[4:], Body=b"x")))
elif cmd.startswith("del:"):
    print(code(lambda: s3.delete_object(Bucket="polb", Key=cmd[4:])))
elif cmd == "list":
    print(code(lambda: s3.list_objects_v2(Bucket="polb")))
PY
}

start
py alice setup
check_eq "public policy refused without --allow-public" "$(py alice public)" "AccessDenied"
stop
start --allow-public
check_eq "malformed policy" "$(py alice malformed)" "MalformedPolicy"
check_eq "policy naming another bucket" "$(py alice otherbucket)" "MalformedPolicy"
check_eq "public-write policy needs --allow-public-write" "$(py alice publicwrite)" "AccessDenied"
check_eq "put policy" "$(py alice public)" "ok"
check_eq "bob can't read the policy" "$(py bob getpol)" "AccessDenied"
check_eq "unsigned GET public/ → 200" "$(code "$URL/polb/public/a.txt")" "200"
check_eq "unsigned GET body" "$(curl -sS "$URL/polb/public/a.txt")" "public/a.txt"
check_eq "unsigned GET private/ → 403" "$(code "$URL/polb/private/s.txt")" "403"
check_eq "unsigned PUT public/ → 403" "$(code -X PUT --data x "$URL/polb/public/new")" "403"
check_eq "unsigned list → 403" "$(code "$URL/polb")" "403"
check_eq "unsigned GET missing bucket → 403 (no enumeration)" "$(code "$URL/nosuchb/x")" "403"
check_eq "bob GET home/bob" "$(py bob get:home/bob/b.txt)" "ok"
check_eq "bob PUT home/bob" "$(py bob put:home/bob/new.txt)" "ok"
check_eq "bob GET home/carol → denied" "$(py bob get:home/carol/c.txt)" "AccessDenied"
check_eq "bob list → denied" "$(py bob list)" "AccessDenied"
check_eq "explicit Deny binds the owner too" "$(py alice del:private/s.txt)" "AccessDenied"
check_eq "owner unaffected elsewhere" "$(py alice get:private/s.txt)" "ok"
check_eq "deny-all policy accepted" "$(py alice denyall)" "ok"
check_eq "owner denied data access" "$(py alice get:public/a.txt)" "AccessDenied"
check_eq "lockout rule: owner can still read policy" "$(py alice getpol)" "ok"
check_eq "lockout rule: owner can delete policy" "$(py alice delpol)" "ok"
check_eq "access restored" "$(py alice get:public/a.txt)" "ok"
check_eq "no policy → anonymous denied again" "$(code "$URL/polb/public/a.txt")" "403"
stop

# aws:SecureTransport via a trusted proxy's X-Forwarded-Proto only.
start --allow-public --trusted-proxy 127.0.0.1
check_eq "deny non-TLS policy" "$(py alice tls)" "ok"
check_eq "plain request denied" "$(py alice get:public/a.txt)" "AccessDenied"
python3 - "$URL" "$A" "$AS" > "$DATA.tls" <<'PY'
import sys, urllib.request
from botocore.awsrequest import AWSRequest
from botocore.auth import S3SigV4Auth
from botocore.credentials import Credentials
url, ak, sk = sys.argv[1:4]
req = AWSRequest(method="GET", url=url + "/polb/public/a.txt", headers={})
S3SigV4Auth(Credentials(ak, sk), "s3", "us-east-1").add_auth(req)
h = dict(req.headers); h["X-Forwarded-Proto"] = "https"
try:
    print(urllib.request.urlopen(urllib.request.Request(req.url, headers=h)).status)
except urllib.error.HTTPError as e:
    print(e.code)
PY
check_eq "X-Forwarded-Proto: https from trusted proxy → allowed" "$(cat "$DATA.tls")" "200"
rm -f "$DATA.tls"
stop
start --allow-public
check_eq "policy persists (deny non-TLS)" "$(py alice get:public/a.txt)" "AccessDenied"
python3 - "$URL" "$A" "$AS" > "$DATA.tls" <<'PY'
import sys, urllib.request
from botocore.awsrequest import AWSRequest
from botocore.auth import S3SigV4Auth
from botocore.credentials import Credentials
url, ak, sk = sys.argv[1:4]
req = AWSRequest(method="GET", url=url + "/polb/public/a.txt", headers={})
S3SigV4Auth(Credentials(ak, sk), "s3", "us-east-1").add_auth(req)
h = dict(req.headers); h["X-Forwarded-Proto"] = "https"
try:
    print(urllib.request.urlopen(urllib.request.Request(req.url, headers=h)).status)
except urllib.error.HTTPError as e:
    print(e.code)
PY
check_eq "X-Forwarded-Proto ignored without --trusted-proxy" "$(cat "$DATA.tls")" "403"
rm -f "$DATA.tls"
stop

echo
echo "===== policy e2e: $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
