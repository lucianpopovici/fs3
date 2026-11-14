#!/usr/bin/env bash
#
# tests/test_e2e_website.sh — item 6: static website hosting on a
# dedicated anonymous listener, and the --allow-public guard (S6).
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 22900 + RANDOM % 300 ))}
WPORT=$((PORT + 1))
DATA=/tmp/fs3-web-e2e-$$
LOG=/tmp/fs3-web-e2e-$$.log
URL="http://127.0.0.1:$PORT"
WURL="http://127.0.0.1:$WPORT"
AK=AKIAWEBSITE00001
SK=websiteSecret0123456789012345678901234567890

cleanup() {
    [ -n "${SP:-}" ] && kill "$SP" 2>/dev/null || true
    rm -rf "$DATA" "$LOG"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

start() {
    "$ROOT/fs3" -p "$PORT" -d "$DATA" --auth "$AK:$SK" --require-auth \
        --web-port "$WPORT" --web-root-domain web.example.lan "$@" >"$LOG" 2>&1 &
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
if cmd == "setup":
    s3.create_bucket(Bucket="site")
    s3.create_bucket(Bucket="redir")
    s3.create_bucket(Bucket="private")
    for k, b, ct in (("index.html", b"<h1>home</h1>", "text/html"),
                     ("docs/index.html", b"<h1>docs</h1>", "text/html"),
                     ("404.html", b"<h1>custom 404</h1>", "text/html"),
                     ("app.js", b"console.log(1)", "application/javascript"),
                     ("big.bin", b"0123456789", "application/octet-stream")):
        s3.put_object(Bucket="site", Key=k, Body=b, ContentType=ct)
    s3.put_object(Bucket="private", Key="index.html", Body=b"secret")
elif cmd == "put-site":
    print(code(lambda: s3.put_bucket_website(Bucket="site", WebsiteConfiguration={
        "IndexDocument": {"Suffix": "index.html"}, "ErrorDocument": {"Key": "404.html"}})))
elif cmd == "put-redir":
    print(code(lambda: s3.put_bucket_website(Bucket="redir", WebsiteConfiguration={
        "RedirectAllRequestsTo": {"HostName": "example.org", "Protocol": "https"}})))
elif cmd == "routing":
    print(code(lambda: s3.put_bucket_website(Bucket="site", WebsiteConfiguration={
        "IndexDocument": {"Suffix": "index.html"},
        "RoutingRules": [{"Redirect": {"HostName": "x.org"}}]})))
elif cmd == "get":
    r = s3.get_bucket_website(Bucket="site"); print(r["IndexDocument"]["Suffix"])
elif cmd == "delete":
    print(code(lambda: s3.delete_bucket_website(Bucket="site")))
PY
}
wget() { curl -sS -H "Host: $1" "${@:3}" "$WURL$2"; }
wcode() { curl -sS -o /dev/null -w '%{http_code}' -H "Host: $1" "${@:3}" "$WURL$2"; }

# Block-public-access by default.
start
py setup
check_eq "website config refused without --allow-public" "$(py put-site)" "AccessDenied"
stop

start --allow-public
check_eq "put website" "$(py put-site)" "ok"
check_eq "get website" "$(py get)" "index.html"
check_eq "RoutingRules → NotImplemented" "$(py routing)" "NotImplemented"
check_eq "put redirect-all" "$(py put-redir)" "ok"

H=site.web.example.lan
check_eq "/ serves index" "$(wget $H /)" "<h1>home</h1>"
check_eq "/docs/ serves index" "$(wget $H /docs/)" "<h1>docs</h1>"
check_eq "/docs → 302" "$(wcode $H /docs)" "302"
check_eq "/docs Location" \
    "$(curl -sS -o /dev/null -D - -H "Host: $H" "$WURL/docs" | tr -d '\r' | grep -i '^location:' | cut -d' ' -f2)" "/docs/"
check_eq "//evil.example/docs → no protocol-relative redirect" \
    "$(curl -sS -o /dev/null -D - -H "Host: $H" --path-as-is "$WURL//docs" | tr -d '\r' | grep -i '^location:' | cut -d' ' -f2)" "/docs/"
check_eq "file with content type" \
    "$(curl -sS -o /dev/null -w '%{content_type}' -H "Host: $H" "$WURL/app.js")" "application/javascript"
check_eq "Range works" "$(wget $H /big.bin -H 'Range: bytes=2-4')" "234"
check_eq "multi-range → whole object" "$(wcode $H /big.bin -H 'Range: bytes=0-1,3-4')" "200"
check_eq "missing → custom 404 status" "$(wcode $H /nope)" "404"
check_eq "missing → custom 404 body" "$(wget $H /nope)" "<h1>custom 404</h1>"
check_eq "HEAD ok" "$(curl -sS -o /dev/null -w '%{http_code}' -I -H "Host: $H" "$WURL/")" "200"
check_eq "PUT → 405" "$(wcode $H /x -X PUT --data x)" "405"
check_eq "DELETE → 405" "$(wcode $H /index.html -X DELETE)" "405"
check_eq "index.html survived" "$(wget $H /)" "<h1>home</h1>"
check_eq "?acl → 400" "$(wcode $H '/?acl')" "400"
check_eq "?list-type → listing never served" "$(wget $H '/?list-type=2' | head -c 14)" "<h1>home</h1>"
check_eq "X-Amz-Signature query → 400" "$(wcode $H '/?X-Amz-Signature=x')" "400"
check_eq "Authorization header ignored" \
    "$(wget $H / -H 'Authorization: AWS4-HMAC-SHA256 Credential=bogus')" "<h1>home</h1>"
check_eq "errors are HTML, never S3 XML" "$(wget nosuch.web.example.lan / | grep -c '<Error>' || true)" "0"
check_eq "unknown host → 404" "$(wcode nosuch.web.example.lan /)" "404"
check_eq "bucket without website → 404" "$(wcode private.web.example.lan /)" "404"
check_eq "invalid bucket in Host → 404" "$(wcode 'UPPER_case.web.example.lan' /)" "404"
check_eq "custom domain: Host == bucket" "$(wget site /)" "<h1>home</h1>"
check_eq "Host with port" "$(wget "$H:8080" /)" "<h1>home</h1>"
check_eq "redirect-all → 301" "$(wcode redir.web.example.lan /a/b)" "301"
check_eq "redirect-all Location" \
    "$(curl -sS -o /dev/null -D - -H 'Host: redir.web.example.lan' "$WURL/a/b" | tr -d '\r' | grep -i '^location:' | cut -d' ' -f2)" "https://example.org/a/b"
check_eq "S3 endpoint still requires auth" "$(curl -sS -o /dev/null -w '%{http_code}' "$URL/site/index.html")" "403"
check_eq "nosniff on website" \
    "$(curl -sS -o /dev/null -D - -H "Host: $H" "$WURL/" | tr -d '\r' | grep -ci 'x-content-type-options: nosniff')" "1"
check_eq "delete website" "$(py delete)" "ok"
sleep 1.1
check_eq "site gone after delete" "$(wcode $H /)" "404"
stop

echo
echo "===== website e2e: $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
