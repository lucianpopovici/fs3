#!/usr/bin/env bash
#
# tests/test_e2e_cors.sh — item 4: bucket CORS (?cors CRUD, preflights,
# headers on actual and error responses).
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 22100 + RANDOM % 300 ))}
DATA=/tmp/fs3-cors-e2e-$$
LOG=/tmp/fs3-cors-e2e-$$.log
URL="http://127.0.0.1:$PORT"
T=/tmp/fs3-cors-$$
AK=AKIACORS00000001
SK=corsSecret012345678901234567890123456789012

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; } || true
    rm -rf "$DATA" "$LOG" "$T".*
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

"$ROOT/fs3" -p "$PORT" -d "$DATA" --auth "$AK:$SK" --require-auth >"$LOG" 2>&1 &
SP=$!
sleep 0.4
kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}
has() { case "$1" in *"$2"*) echo yes ;; *) echo no ;; esac; }
s3py() {
    python3 - "$@" <<PY
import sys, boto3, botocore
s3 = boto3.client("s3", endpoint_url="$URL", aws_access_key_id="$AK",
                  aws_secret_access_key="$SK", region_name="us-east-1")
cmd = sys.argv[1]
try:
    if cmd == "mk":
        s3.create_bucket(Bucket="corsb"); s3.put_object(Bucket="corsb", Key="k", Body=b"v")
    elif cmd == "put":
        s3.put_bucket_cors(Bucket="corsb", CORSConfiguration={"CORSRules": [
            {"AllowedOrigins": ["https://app.example.com"], "AllowedMethods": ["GET", "PUT"],
             "AllowedHeaders": ["x-amz-*", "content-type"], "ExposeHeaders": ["ETag"],
             "MaxAgeSeconds": 600},
            {"AllowedOrigins": ["https://*.public.example"], "AllowedMethods": ["GET"]}]})
        print("ok")
    elif cmd == "get":
        r = s3.get_bucket_cors(Bucket="corsb"); print(len(r["CORSRules"]))
    elif cmd == "del":
        s3.delete_bucket_cors(Bucket="corsb"); print("ok")
    elif cmd == "bad":
        s3.put_bucket_cors(Bucket="corsb", CORSConfiguration={"CORSRules": [
            {"AllowedOrigins": ["https://*.*.x"], "AllowedMethods": ["GET"]}]})
        print("accepted")
    elif cmd == "badmethod":
        s3.put_bucket_cors(Bucket="corsb", CORSConfiguration={"CORSRules": [
            {"AllowedOrigins": ["*"], "AllowedMethods": ["PATCH"]}]})
        print("accepted")
except botocore.exceptions.ClientError as e:
    print(e.response["Error"]["Code"])
PY
}

s3py mk
check_eq "get-bucket-cors before any → NoSuchCORSConfiguration" "$(s3py get)" "NoSuchCORSConfiguration"
check_eq "put-bucket-cors" "$(s3py put)" "ok"
check_eq "get-bucket-cors" "$(s3py get)" "2"
check_eq "two '*' in an origin rejected" "$(s3py bad)" "InvalidRequest"
check_eq "unknown method rejected" "$(s3py badmethod)" "InvalidRequest"
check_eq "config intact after rejected puts" "$(s3py get)" "2"

pre() { curl -sS -o /dev/null -D - -X OPTIONS "$@" | tr -d '\r'; }
out=$(pre -H 'Origin: https://app.example.com' -H 'Access-Control-Request-Method: PUT' \
      -H 'Access-Control-Request-Headers: x-amz-date, Content-Type' "$URL/corsb/k")
check_eq "preflight allowed: 200" "$(echo "$out" | head -1 | cut -d' ' -f2)" "200"
check_eq "preflight Allow-Origin" "$(has "$out" "Access-Control-Allow-Origin: https://app.example.com")" "yes"
check_eq "preflight Allow-Methods" "$(has "$out" "Access-Control-Allow-Methods: GET, PUT")" "yes"
check_eq "preflight Max-Age" "$(has "$out" "Access-Control-Max-Age: 600")" "yes"
check_eq "never Allow-Credentials" "$(has "$out" "Allow-Credentials")" "no"
out=$(pre -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: GET' "$URL/corsb/k")
check_eq "disallowed origin: 403" "$(echo "$out" | head -1 | cut -d' ' -f2)" "403"
out=$(pre -H 'Origin: https://app.example.com' -H 'Access-Control-Request-Method: PUT' \
      -H 'Access-Control-Request-Headers: x-forbidden' "$URL/corsb/k")
check_eq "disallowed header: 403" "$(echo "$out" | head -1 | cut -d' ' -f2)" "403"
out=$(pre -H 'Origin: https://app.example.com' -H 'Access-Control-Request-Method: DELETE' "$URL/corsb/k")
check_eq "disallowed method: 403" "$(echo "$out" | head -1 | cut -d' ' -f2)" "403"
out=$(pre -H 'Origin: https://cdn.public.example' -H 'Access-Control-Request-Method: GET' "$URL/corsb")
check_eq "wildcard origin rule" "$(echo "$out" | head -1 | cut -d' ' -f2)" "200"
# S7: no-such-bucket and no-matching-rule are indistinguishable.
a=$(curl -sS -X OPTIONS -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: GET' "$URL/corsb/k" -w '%{http_code}')
b=$(curl -sS -X OPTIONS -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: GET' "$URL/nosuchbucket/k" -w '%{http_code}')
check_eq "missing bucket == no rule" "$b" "$a"
check_eq "preflight without request-method → 400" \
    "$(curl -sS -o /dev/null -w '%{http_code}' -X OPTIONS -H 'Origin: https://x' "$URL/corsb")" "400"

# Actual requests: signed GET with Origin gets CORS headers; so do errors.
python3 - "$URL" "$AK" "$SK" > "$T.act" <<'PY'
import sys, urllib.request
from botocore.awsrequest import AWSRequest
from botocore.auth import S3SigV4Auth
from botocore.credentials import Credentials
url, ak, sk = sys.argv[1:4]
def get(path, origin, sign=True):
    req = AWSRequest(method="GET", url=url + path, headers={"Origin": origin})
    if sign:
        S3SigV4Auth(Credentials(ak, sk), "s3", "us-east-1").add_auth(req)
    r = urllib.request.Request(req.url, headers=dict(req.headers))
    try:
        resp = urllib.request.urlopen(r)
    except urllib.error.HTTPError as e:
        resp = e
    return resp.status, dict(resp.headers)
for path, origin, sign in (("/corsb/k", "https://app.example.com", True),
                           ("/corsb/missing", "https://app.example.com", True),
                           ("/corsb/k", "https://app.example.com", False),
                           ("/corsb/k", "https://evil.example", True)):
    st, h = get(path, origin, sign)
    print(st, h.get("Access-Control-Allow-Origin", "-"), h.get("Access-Control-Expose-Headers", "-"),
          h.get("Vary", "-"), h.get("X-Content-Type-Options", "-"))
PY
check_eq "signed GET with Origin" "$(sed -n 1p "$T.act")" "200 https://app.example.com ETag Origin nosniff"
check_eq "404 error carries CORS" "$(sed -n 2p "$T.act")" "404 https://app.example.com ETag Origin nosniff"
check_eq "403 (unsigned) carries CORS" "$(sed -n 3p "$T.act")" "403 https://app.example.com ETag Origin nosniff"
check_eq "non-matching origin: no CORS headers" "$(sed -n 4p "$T.act")" "200 - - - nosniff"

check_eq "delete-bucket-cors" "$(s3py del)" "ok"
sleep 1.1   # preflight cache TTL
out=$(pre -H 'Origin: https://app.example.com' -H 'Access-Control-Request-Method: GET' "$URL/corsb/k")
check_eq "after delete: preflight 403" "$(echo "$out" | head -1 | cut -d' ' -f2)" "403"
check_eq "bucket survived DELETE ?cors" \
    "$(python3 -c "
import boto3; s3=boto3.client('s3',endpoint_url='$URL',aws_access_key_id='$AK',aws_secret_access_key='$SK',region_name='us-east-1')
print(s3.get_object(Bucket='corsb',Key='k')['Body'].read().decode())")" "v"

echo
echo "===== cors e2e: $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
