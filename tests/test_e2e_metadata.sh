#!/usr/bin/env bash
#
# tests/test_e2e_metadata.sh — round 2 item 1e: user metadata, standard
# object headers, x-amz-metadata-directive and response-* overrides.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 26000 + RANDOM % 300 ))}
WPORT=$((PORT + 1))
DATA=/tmp/fs3-meta-e2e-$$
LOG=/tmp/fs3-meta-e2e-$$.log
URL="http://127.0.0.1:$PORT"
WURL="http://127.0.0.1:$WPORT"
A=AKIAMETAALICE001; AS=metaAliceSecret01234567890123456789012

cleanup() {
    [ -n "${SP:-}" ] && kill "$SP" 2>/dev/null || true
    rm -rf "$DATA" "$LOG"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

"$ROOT/fs3" -p "$PORT" -d "$DATA" --auth "$A:$AS:alice" --mpu-min-part-size 0 \
    --allow-public --web-port "$WPORT" --web-root-domain web.example.lan >"$LOG" 2>&1 &
SP=$!
sleep 0.4
kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }

FS3_TEST_STRICT=${FS3_TEST_STRICT:-0} python3 -u - "$URL" "$A" "$AS" "$DATA" "$WURL" <<'PY'
import sys, os, socket, hashlib, datetime, urllib.request, urllib.error, boto3, botocore
url, a, asec, data, wurl = sys.argv[1:6]
from botocore.config import Config
s3 = boto3.client("s3", endpoint_url=url, aws_access_key_id=a, aws_secret_access_key=asec,
                  region_name="us-east-1", config=Config(signature_version="s3v4"))
urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))
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

def raw(method, path, headers=None, body=b"", port=None):
    """Plain HTTP, no client-side header validation; returns (status, head, body)."""
    host, p = "127.0.0.1", int(port or url.rsplit(":", 1)[1])
    s = socket.create_connection((host, p), timeout=10)
    headers = dict(headers or {})
    req = f"{method} {path} HTTP/1.1\r\nHost: {headers.pop('Host', f'{host}:{p}')}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
    for k, v in headers.items():
        req += f"{k}: {v}\r\n"
    s.sendall(req.encode("latin-1") + b"\r\n" + body)
    out = b""
    while True:
        r = s.recv(65536)
        if not r: break
        out += r
    s.close()
    head, _, b = out.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), head.decode("latin-1"), b

s3.create_bucket(Bucket="metab")
STD = dict(CacheControl="max-age=60", ContentDisposition='attachment; filename="r.txt"',
           ContentEncoding="gzip", ContentLanguage="ro-RO",
           Expires=datetime.datetime(2030, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc))
META = {"color": "red", "mtime": "1700000000.123", "Mixed-Case": "Value With Spaces"}

# --- PUT round-trip ----------------------------------------------------------
s3.put_object(Bucket="metab", Key="k", Body=b"hello", Metadata=META, ContentType="text/x-fs3", **STD)
h = s3.head_object(Bucket="metab", Key="k")
check("user metadata on HEAD", h["Metadata"], {"color": "red", "mtime": "1700000000.123", "mixed-case": "Value With Spaces"})
check("content-type", h["ContentType"], "text/x-fs3")
for k in ("CacheControl", "ContentDisposition", "ContentEncoding", "ContentLanguage"):
    check(k, h.get(k), STD[k])
check("Expires", h.get("ExpiresString") or str(h.get("Expires")), "Wed, 02 Jan 2030 03:04:05 GMT")
g = s3.get_object(Bucket="metab", Key="k")
check("metadata on GET", g["Metadata"]["color"], "red")
g = s3.get_object(Bucket="metab", Key="k", Range="bytes=0-1")
check("metadata on 206", (g["Metadata"]["color"], g["CacheControl"]), ("red", "max-age=60"))
s3.put_object(Bucket="metab", Key="plain", Body=b"x")
h = s3.head_object(Bucket="metab", Key="plain")
check("object without metadata", (h["Metadata"], h.get("CacheControl")), ({}, None))

# Connection: close is honoured (raw() relies on it).
st, head, _ = raw("GET", "/metab/nokey")
check("Connection: close echoed", "connection: close" in head.lower(), True)

# --- limits ------------------------------------------------------------------
check("2 KiB exactly", code(lambda: s3.put_object(Bucket="metab", Key="lim", Body=b"",
      Metadata={"k": "v" * 2047})), "ok")
check("one byte over → MetadataTooLarge", code(lambda: s3.put_object(Bucket="metab", Key="lim2", Body=b"",
      Metadata={"k": "v" * 2048})), "MetadataTooLarge")
check("over the limit stored nothing", code(lambda: s3.head_object(Bucket="metab", Key="lim2")), "404")
check("over the limit across names", code(lambda: s3.put_object(Bucket="metab", Key="lim3", Body=b"",
      Metadata={"a" * 10: "v" * 1000, "b" * 10: "v" * 1030})), "MetadataTooLarge")

# --- multipart -----------------------------------------------------------------
u = s3.create_multipart_upload(Bucket="metab", Key="mp", Metadata={"via": "mpu"}, CacheControl="no-store",
                               ContentType="application/x-mp")["UploadId"]
e1 = s3.upload_part(Bucket="metab", Key="mp", UploadId=u, PartNumber=1, Body=b"p" * 100)["ETag"]
s3.complete_multipart_upload(Bucket="metab", Key="mp", UploadId=u,
                             MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": e1}]})
h = s3.head_object(Bucket="metab", Key="mp")
check("multipart metadata applied at Complete", (h["Metadata"], h.get("CacheControl"), h["ContentType"]),
      ({"via": "mpu"}, "no-store", "application/x-mp"))

# --- versioned ---------------------------------------------------------------
s3.create_bucket(Bucket="metav")
s3.put_bucket_versioning(Bucket="metav", VersioningConfiguration={"Status": "Enabled"})
v1 = s3.put_object(Bucket="metav", Key="k", Body=b"1", Metadata={"gen": "one"})["VersionId"]
s3.put_object(Bucket="metav", Key="k", Body=b"2", Metadata={"gen": "two"})
check("latest version metadata", s3.head_object(Bucket="metav", Key="k")["Metadata"], {"gen": "two"})
check("old version metadata", s3.head_object(Bucket="metav", Key="k", VersionId=v1)["Metadata"], {"gen": "one"})

# --- copy --------------------------------------------------------------------
s3.copy_object(Bucket="metab", Key="c1", CopySource="metab/k")
h = s3.head_object(Bucket="metab", Key="c1")
check("COPY keeps metadata", (h["Metadata"]["color"], h["CacheControl"], h["ContentType"]),
      ("red", "max-age=60", "text/x-fs3"))
s3.copy_object(Bucket="metab", Key="c2", CopySource="metab/k", MetadataDirective="REPLACE",
               Metadata={"new": "yes"}, ContentType="text/plain")
h = s3.head_object(Bucket="metab", Key="c2")
check("REPLACE takes request metadata", (h["Metadata"], h.get("CacheControl"), h["ContentType"]),
      ({"new": "yes"}, None, "text/plain"))
check("self-copy without REPLACE → InvalidRequest",
      code(lambda: s3.copy_object(Bucket="metab", Key="k", CopySource="metab/k")), "InvalidRequest")
check("self-copy with REPLACE edits metadata", code(lambda: s3.copy_object(Bucket="metab", Key="k",
      CopySource="metab/k", MetadataDirective="REPLACE", Metadata={"color": "green"},
      ContentType="text/x-fs3")), "ok")
h = s3.head_object(Bucket="metab", Key="k")
check("edited metadata", h["Metadata"], {"color": "green"})
check("edited object keeps bytes", s3.get_object(Bucket="metab", Key="k")["Body"].read(), b"hello")
r = s3.copy_object(Bucket="metav", Key="k", CopySource="metav/k", MetadataDirective="REPLACE",
                   Metadata={"gen": "three"})
check("self-copy on versioned bucket makes a version",
      len(s3.list_object_versions(Bucket="metav", Prefix="k")["Versions"]), 3)
check("bad directive → InvalidArgument", code(lambda: s3.copy_object(Bucket="metab", Key="c3",
      CopySource="metab/k", MetadataDirective="MERGE")), "InvalidArgument")
check("tagging directive → NotImplemented", code(lambda: s3.copy_object(Bucket="metab", Key="c3",
      CopySource="metab/k", TaggingDirective="REPLACE")), "NotImplemented")

# --- injection attempts (raw sockets: no client-side sanitising) ---------------
signed = s3.generate_presigned_url("put_object", Params={"Bucket": "metab", "Key": "inj"}, ExpiresIn=60)
path = signed.split(url, 1)[1]
for name, hdr in (("CR LF in meta value", {"x-amz-meta-a": "x\rSet-Cookie: pwn"}),
                  ("bare LF in cache-control", {"Cache-Control": "a\nSet-Cookie: pwn"}),
                  ("ctl char in meta", {"x-amz-meta-a": "x\x01y"})):
    st, head, _ = raw("PUT", path, hdr, b"data")
    check(name + " refused", st in (400, 403), True)
check("nothing stored by the injection attempts", code(lambda: s3.head_object(Bucket="metab", Key="inj")), "404")

# --- response-* overrides ------------------------------------------------------
g = s3.get_object(Bucket="metab", Key="k", ResponseContentType="image/png",
                  ResponseContentDisposition="inline", ResponseCacheControl="no-cache",
                  ResponseContentLanguage="fr", ResponseExpires=datetime.datetime(2031, 1, 1, tzinfo=datetime.timezone.utc),
                  ResponseContentEncoding="identity")
check("response-* on signed GET", (g["ContentType"], g["ContentDisposition"], g["CacheControl"],
      g["ContentLanguage"], g["ContentEncoding"]), ("image/png", "inline", "no-cache", "fr", "identity"))
pu = s3.generate_presigned_url("get_object", Params={"Bucket": "metab", "Key": "k",
                               "ResponseContentDisposition": "attachment; filename=x.bin"}, ExpiresIn=60)
with urllib.request.urlopen(pu) as r:
    check("response-* on presigned GET", r.headers.get("Content-Disposition"), "attachment; filename=x.bin")
s3.put_bucket_policy(Bucket="metab", Policy='{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::metab/*"}]}')
st, head, _ = raw("GET", "/metab/k")
check("anonymous GET (public bucket) works", st, 200)
st, head, _ = raw("GET", "/metab/k?response-content-type=text/html")
check("response-* on anonymous GET → 400", st, 400)
check("… InvalidRequest", "InvalidRequest" in _.decode(errors="replace") if _ else False, True)
st, head, _ = raw("GET", "/metab/k?response-cache-control=a%0d%0aSet-Cookie:%20x")
check("CRLF in response-* never reaches the head", "set-cookie" in head.lower(), False)
inj = s3.generate_presigned_url("get_object", Params={"Bucket": "metab", "Key": "k",
                                "ResponseCacheControl": "a\r\nSet-Cookie: x"}, ExpiresIn=60)
st, head, _ = raw("GET", inj.split(url, 1)[1])
check("CRLF in signed response-* → 400", st, 400)
check("… and no injected header", "set-cookie" in head.lower(), False)

# --- website listener ------------------------------------------------------------
s3.put_bucket_website(Bucket="metab", WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}})
s3.put_object(Bucket="metab", Key="site.css", Body=b"body{}", ContentType="text/css", CacheControl="max-age=300",
              ContentDisposition="attachment", Metadata={"secret": "s"})
st, head, _ = raw("GET", "/site.css?response-content-type=text/html", {"Host": "metab.web.example.lan"},
                  port=wurl.rsplit(":", 1)[1])
hl = head.lower()
check("website: 200", st, 200)
check("website: Cache-Control served", "cache-control: max-age=300" in hl, True)
check("website: no user metadata", "x-amz-meta-" in hl, False)
check("website: no Content-Disposition", "content-disposition" in hl, False)
check("website: response-* ignored", "content-type: text/css" in hl, True)
check("website: nosniff kept", "x-content-type-options: nosniff" in hl, True)

# --- CORS: x-amz-meta-* visible only if exposed --------------------------------
s3.put_bucket_cors(Bucket="metab", CORSConfiguration={"CORSRules": [{"AllowedOrigins": ["https://app.example"],
    "AllowedMethods": ["GET"], "ExposeHeaders": ["x-amz-meta-color"]}]})
st, head, _ = raw("GET", "/metab/k", {"Origin": "https://app.example"})
hl = head.lower()
check("CORS exposes listed meta header", "access-control-expose-headers: x-amz-meta-color" in hl, True)

print(f"\nPYPASS={PASS} PYFAIL={FAIL}")
sys.exit(1 if FAIL else 0)
PY

# AWS CLI: --metadata / --cache-control.
export AWS_ACCESS_KEY_ID=$A AWS_SECRET_ACCESS_KEY=$AS AWS_DEFAULT_REGION=us-east-1
echo cli >"$DATA.f"
aws --endpoint-url "$URL" s3 cp "$DATA.f" s3://metab/cli --metadata a=b --cache-control max-age=60 >/dev/null
out=$(aws --endpoint-url "$URL" s3api head-object --bucket metab --key cli)
echo "$out" | grep -q '"a": "b"' || { echo "FAIL: aws s3 cp --metadata"; echo "$out"; exit 1; }
echo "$out" | grep -q '"CacheControl": "max-age=60"' || { echo "FAIL: aws s3 cp --cache-control"; exit 1; }
rm -f "$DATA.f"
echo "aws s3 cp --metadata/--cache-control ok"

# rclone keeps mtimes in x-amz-meta-mtime.
if command -v rclone >/dev/null; then
    mkdir -p "$DATA.rc"; echo one >"$DATA.rc/a"; touch -d '2001-02-03 04:05:06' "$DATA.rc/a"
    RC="--s3-provider Other --s3-endpoint $URL --s3-access-key-id $A --s3-secret-access-key $AS --s3-region us-east-1"
    rclone copy $RC "$DATA.rc" ":s3:metab/rc" 
    rclone check $RC --download "$DATA.rc" ":s3:metab/rc"
    m=$(rclone lsl $RC ":s3:metab/rc" | awk '{print $2}')
    [ "$m" = "2001-02-03" ] || { echo "FAIL: rclone mtime not preserved ($m)"; exit 1; }
    rm -rf "$DATA.rc"
    echo "rclone mtime round-trip ok"
elif [ "${FS3_TEST_STRICT:-0}" = "1" ]; then
    echo "FAIL: rclone not installed (FS3_TEST_STRICT=1)"; exit 1
else
    echo "SKIP: rclone not installed"
fi
echo "===== metadata e2e: done ====="
