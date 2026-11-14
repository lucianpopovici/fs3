#!/usr/bin/env bash
#
# tests/test_e2e_ssec.sh — round 2 item 8: SSE-C (customer-provided keys)
# over native TLS (fs3-tls), with boto3 SSECustomerKey as the oracle.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 27800 + RANDOM % 150 ))}
TPORT=$((PORT + 1)); MPORT=$((PORT + 2))
T=/tmp/fs3-ssec-$$
DATA=$T.data
LOG=$T.log
AK=AKIASSECALICE001; SK=ssecAliceSecret01234567890123456789012

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; [ $? -ne 159 ] || echo "FAIL: server died with SIGSYS (seccomp blocked a syscall; see --seccomp=log)" >&2; } || true
    rm -rf "$DATA" "$T".*
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3-tls >/dev/null 2>&1) || { echo "fs3-tls build failed" >&2; exit 1; }

openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=fs3 test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" -keyout "$T.cakey" -out "$T.ca" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" \
    -keyout "$T.key" -out "$T.csr" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\nbasicConstraints=CA:FALSE\n' > "$T.ext"
openssl x509 -req -in "$T.csr" -CA "$T.ca" -CAkey "$T.cakey" -CAcreateserial -days 1 \
    -extfile "$T.ext" -out "$T.crt" >/dev/null 2>&1
chmod 600 "$T.key"

${FS3_WRAP:-} "$ROOT/fs3-tls" -p "$PORT" -d "$DATA" --auth "$AK:$SK:alice" --require-auth \
    --tls-port "$TPORT" --tls-cert "$T.crt" --tls-key "$T.key" --metrics-port "$MPORT" \
    --mpu-min-part-size 0 --web-port $((PORT + 3)) --web-root-domain web.example.lan --allow-public \
    --audit-log "$T.audit" --admin-socket "$T.sock" --scrub-interval-days 0 >"$LOG" 2>&1 &
SP=$!
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/" && break; sleep 0.1; done
kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }

python3 -u - "$PORT" "$TPORT" "$AK" "$SK" "$T" "$DATA" <<'PY'
import sys, os, glob, json, hashlib, base64, subprocess, time, urllib.request, ssl, boto3, botocore
from botocore.config import Config
port, tport, ak, sk, T, data = sys.argv[1:7]
def mk(url):
    return boto3.client("s3", endpoint_url=url, verify=T + ".ca", aws_access_key_id=ak,
                        aws_secret_access_key=sk, region_name="us-east-1",
                        config=Config(signature_version="s3v4", retries={"max_attempts": 1}))
s3 = mk(f"https://127.0.0.1:{tport}")
plain = mk(f"http://127.0.0.1:{port}")
PASS = FAIL = 0
def check(name, got, want):
    global PASS, FAIL
    if got == want:
        PASS += 1; print(".", end="", flush=True)
    else:
        FAIL += 1; print(f"\nFAIL: {name}\n  want={str(want)[:200]!r}\n  got ={str(got)[:200]!r}")
def code(f):
    try:
        f(); return "ok"
    except botocore.exceptions.ClientError as e:
        return e.response["Error"]["Code"]
K1, K2 = os.urandom(32), os.urandom(32)
C1 = dict(SSECustomerAlgorithm="AES256", SSECustomerKey=K1)
C2 = dict(SSECustomerAlgorithm="AES256", SSECustomerKey=K2)
s3.create_bucket(Bucket="sseb")
body = os.urandom(3 * 65536 + 4321)

# --- round trip, HEAD, wrong / missing key -----------------------------------------
r = s3.put_object(Bucket="sseb", Key="k", Body=body, **C1)
check("PUT echoes algorithm", r.get("SSECustomerAlgorithm"), "AES256")
check("PUT echoes key MD5", r.get("SSECustomerKeyMD5"), base64.b64encode(hashlib.md5(K1).digest()).decode())
g = s3.get_object(Bucket="sseb", Key="k", **C1)
check("round trip", g["Body"].read(), body)
check("GET echoes key MD5", g.get("SSECustomerKeyMD5"), base64.b64encode(hashlib.md5(K1).digest()).decode())
check("Content-Length is the plaintext size", g["ContentLength"], len(body))
check("ETag is not the plaintext MD5", g["ETag"].strip('"') != hashlib.md5(body).hexdigest(), True)
check("HEAD with key", s3.head_object(Bucket="sseb", Key="k", **C1)["ContentLength"], len(body))
check("GET without key → InvalidRequest", code(lambda: s3.get_object(Bucket="sseb", Key="k")), "InvalidRequest")
check("HEAD without key → 400", code(lambda: s3.head_object(Bucket="sseb", Key="k")), "400")
check("wrong key → AccessDenied", code(lambda: s3.get_object(Bucket="sseb", Key="k", **C2)), "AccessDenied")
s3.put_object(Bucket="sseb", Key="plainobj", Body=b"p")
check("key on a plain object → InvalidRequest", code(lambda: s3.get_object(Bucket="sseb", Key="plainobj", **C1)),
      "InvalidRequest")
f = glob.glob(f"{data}/data/sseb/*/*/*")
raw = b"".join(open(x, "rb").read() for x in f)
check("plaintext never on disk", raw.find(body[:256]) == -1 and raw.find(body[-256:]) == -1, True)
check("key never on disk", raw.find(K1) == -1, True)

# --- ranges across segment boundaries --------------------------------------------------
for a, b in ((0, 0), (65530, 65545), (65536, 131071), (100, 3 * 65536 + 4000), (len(body) - 10, len(body) - 1)):
    got = s3.get_object(Bucket="sseb", Key="k", Range=f"bytes={a}-{b}", **C1)["Body"].read()
    check(f"range {a}-{b}", got, body[a:b + 1])
check("suffix range", s3.get_object(Bucket="sseb", Key="k", Range="bytes=-70000", **C1)["Body"].read(), body[-70000:])
s3.put_object(Bucket="sseb", Key="empty", Body=b"", **C1)
check("empty object", s3.get_object(Bucket="sseb", Key="empty", **C1)["Body"].read(), b"")
s3.put_object(Bucket="sseb", Key="exact", Body=body[:131072], **C1)
check("exact multiple of a segment", s3.get_object(Bucket="sseb", Key="exact", **C1)["Body"].read(), body[:131072])

# --- plain HTTP refused ---------------------------------------------------------------
check("SSE-C over plain HTTP → InvalidRequest", code(lambda: plain.put_object(Bucket="sseb", Key="x", Body=b"x", **C1)),
      "InvalidRequest")
check("…and nothing stored", code(lambda: s3.head_object(Bucket="sseb", Key="x")), "404")

# --- multipart -------------------------------------------------------------------------
p1, p2, p3 = os.urandom(5 * 65536 + 17), os.urandom(65536), os.urandom(999)
u = s3.create_multipart_upload(Bucket="sseb", Key="mp", **C1)["UploadId"]
check("UploadPart without key → InvalidRequest", code(lambda: s3.upload_part(Bucket="sseb", Key="mp", UploadId=u,
      PartNumber=1, Body=p1)), "InvalidRequest")
check("UploadPart with another key → AccessDenied", code(lambda: s3.upload_part(Bucket="sseb", Key="mp", UploadId=u,
      PartNumber=1, Body=p1, **C2)), "AccessDenied")
es = [s3.upload_part(Bucket="sseb", Key="mp", UploadId=u, PartNumber=i + 1, Body=p, **C1)["ETag"]
      for i, p in enumerate((p1, p2, p3))]
lp = s3.list_parts(Bucket="sseb", Key="mp", UploadId=u)["Parts"]
check("ListParts shows plaintext sizes", [x["Size"] for x in lp], [len(p1), len(p2), len(p3)])
s3.complete_multipart_upload(Bucket="sseb", Key="mp", UploadId=u,
    MultipartUpload={"Parts": [{"PartNumber": i + 1, "ETag": e} for i, e in enumerate(es)]})
whole = p1 + p2 + p3
check("multipart round trip", s3.get_object(Bucket="sseb", Key="mp", **C1)["Body"].read(), whole)
b1 = len(p1)
for a, b in ((b1 - 5, b1 + 5), (b1 + len(p2) - 3, b1 + len(p2) + 3), (65530, b1 + 70000)):
    check(f"multipart range {a}-{b} across parts", s3.get_object(Bucket="sseb", Key="mp", Range=f"bytes={a}-{b}",
          **C1)["Body"].read(), whole[a:b + 1])
check("multipart wrong key", code(lambda: s3.get_object(Bucket="sseb", Key="mp", **C2)), "AccessDenied")
u2 = s3.create_multipart_upload(Bucket="sseb", Key="mp2")["UploadId"]
check("key on a plain upload's part → InvalidRequest", code(lambda: s3.upload_part(Bucket="sseb", Key="mp2",
      UploadId=u2, PartNumber=1, Body=b"x", **C1)), "InvalidRequest")

# --- copy with re-keying -----------------------------------------------------------------
s3.copy_object(Bucket="sseb", Key="copy2", CopySource="sseb/k",
               CopySourceSSECustomerAlgorithm="AES256", CopySourceSSECustomerKey=K1, **C2)
check("copy re-keyed: new key", s3.get_object(Bucket="sseb", Key="copy2", **C2)["Body"].read(), body)
check("copy re-keyed: old key refused", code(lambda: s3.get_object(Bucket="sseb", Key="copy2", **C1)), "AccessDenied")
s3.copy_object(Bucket="sseb", Key="decrypted", CopySource="sseb/k",
               CopySourceSSECustomerAlgorithm="AES256", CopySourceSSECustomerKey=K1)
check("copy to plain", s3.get_object(Bucket="sseb", Key="decrypted")["Body"].read(), body)
check("copy without the source key → InvalidRequest", code(lambda: s3.copy_object(Bucket="sseb", Key="c3",
      CopySource="sseb/k")), "InvalidRequest")
s3.copy_object(Bucket="sseb", Key="k", CopySource="sseb/k",
               CopySourceSSECustomerAlgorithm="AES256", CopySourceSSECustomerKey=K1, **C2)
check("in-place re-key", s3.get_object(Bucket="sseb", Key="k", **C2)["Body"].read(), body)
u3 = s3.create_multipart_upload(Bucket="sseb", Key="pc", **C1)["UploadId"]
r = s3.upload_part_copy(Bucket="sseb", Key="pc", UploadId=u3, PartNumber=1, CopySource="sseb/mp",
                        CopySourceSSECustomerAlgorithm="AES256", CopySourceSSECustomerKey=K1,
                        CopySourceRange="bytes=0-99999", **C1)
s3.complete_multipart_upload(Bucket="sseb", Key="pc", UploadId=u3,
    MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": r["CopyPartResult"]["ETag"]}]})
check("UploadPartCopy between SSE-C objects", s3.get_object(Bucket="sseb", Key="pc", **C1)["Body"].read(), whole[:100000])

# --- presigned GET with signed SSE-C headers -----------------------------------------------
pu = s3.generate_presigned_url("get_object", Params={"Bucket": "sseb", "Key": "copy2", **C2}, ExpiresIn=60)
ctx = ssl.create_default_context(cafile=T + ".ca")
md5 = base64.b64encode(hashlib.md5(K2).digest()).decode()
req = urllib.request.Request(pu, headers={"x-amz-server-side-encryption-customer-algorithm": "AES256",
    "x-amz-server-side-encryption-customer-key": base64.b64encode(K2).decode(),
    "x-amz-server-side-encryption-customer-key-MD5": md5})
op = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
check("presigned GET with signed SSE-C headers", op.open(req).read(), body)

# --- tamper on disk: never returns bytes -------------------------------------------------------
f = [x for x in glob.glob(f"{data}/data/sseb/*/*/*") if b"exact" in open(x, "rb").read(4096)][0]
blob = bytearray(open(f, "rb").read())
blob[-5] ^= 1
open(f, "wb").write(bytes(blob))
try:
    s3.get_object(Bucket="sseb", Key="exact", Range="bytes=65536-131071", **C1)["Body"].read()
    tampered = "returned bytes"
except Exception:
    tampered = "refused"
check("tampered last segment: no bytes returned", tampered, "refused")
check("untouched segment of the tampered object still decrypts",
      s3.get_object(Bucket="sseb", Key="exact", Range="bytes=0-100", **C1)["Body"].read(), body[:101])

# --- website listener never serves SSE-C objects ---------------------------------------------
s3.put_bucket_website(Bucket="sseb", WebsiteConfiguration={"IndexDocument": {"Suffix": "index.html"}})
st = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-H", "Host: sseb.web.example.lan",
                     f"http://127.0.0.1:{int(port) + 3}/copy2"], capture_output=True, text=True).stdout
check("website: SSE-C object → 404", st, "404")

# --- scrub verifies ciphertext without a key ----------------------------------------------------
sock = T + ".sock"
subprocess.run(["curl", "-s", "--unix-socket", sock, "-X", "POST", "http://x/v1/scrub"], capture_output=True)
for _ in range(100):
    sj = json.loads(subprocess.run(["curl", "-s", "--unix-socket", sock, "http://x/v1/scrub"],
                                   capture_output=True, text=True).stdout)
    if not sj["running"] and sj["finished"] >= sj["started"] > 0: break
    time.sleep(0.1)
check("scrub finds exactly the tampered SSE-C object", sj["corrupt"], 1)
print(f"\nPYPASS={PASS} PYFAIL={FAIL}")
sys.exit(1 if FAIL else 0)
PY
grep -q '"ssec":true' "$T.audit" || { echo "FAIL: audit lacks ssec flag"; exit 1; }
if grep -qi 'customer-key"\|customer-key:' "$T.audit" "$LOG"; then echo "FAIL: key material in logs"; exit 1; fi
echo "audit log marks SSE-C requests and holds no key material"
echo "===== ssec e2e: done ====="
