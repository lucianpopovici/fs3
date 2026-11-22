#!/usr/bin/env bash
#
# tests/test_e2e_sse_s3.sh — SSE-S3 (fs3-managed keys): explicit
# x-amz-server-side-encryption: AES256, bucket default encryption,
# multipart, copies in and out, ranges, plaintext never on disk, ETag =
# plaintext MD5, refusal of customer keys on SSE-S3 objects, aws:kms,
# key-file permission checks, rotation on SIGHUP (new key for new objects,
# old objects still readable, removed or changed keys refused) and a
# restart without a needed key.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 24600 + RANDOM % 300 ))}
TPORT=$((PORT + 1))
T=/tmp/fs3-sses3-$$
DATA=$T.data
LOG=$T.log
AK=AKIASSES3TEST0001
SK=sseS3Secret012345678901234567890123456
SP=""
stop() { [ -n "$SP" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; }; SP=""; }
cleanup() { stop; rm -rf "$T".*; }
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3-tls >/dev/null 2>&1) || { echo "build failed" >&2; exit 1; }

printf '[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > "$T.cacnf"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=sse test CA" -config "$T.cacnf" \
    -keyout "$T.cakey" -out "$T.ca" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=fs3" \
    -keyout "$T.key" -out "$T.csr" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > "$T.ext"
openssl x509 -req -in "$T.csr" -CA "$T.ca" -CAkey "$T.cakey" -CAcreateserial -days 1 \
    -extfile "$T.ext" -out "$T.crt" >/dev/null 2>&1
chmod 600 "$T.key"

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}

K1=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
K2=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '# test keys\nk1 %s\n' "$K1" > "$T.keys"; chmod 600 "$T.keys"

start() {
    ${FS3_WRAP:-} "$ROOT/fs3-tls" -p "$PORT" -d "$DATA" --auth "$AK:$SK" --require-auth \
        --tls-port "$TPORT" --tls-cert "$T.crt" --tls-key "$T.key" "$@" >>"$LOG" 2>&1 &
    SP=$!
    for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/health" && return 0; sleep 0.1; done
    echo "server did not start" >&2; tail "$LOG" >&2; exit 1
}

# s3 <cmd> args... : boto3 driver (plain listener unless FS3_URL is set)
cat > "$T.py" <<'PY'
import sys, os, hashlib, json, base64
sys.modules["awscrt"] = None
import boto3, botocore
from boto3.s3.transfer import TransferConfig
url = os.environ.get("FS3_URL")
kw = {"verify": os.environ["FS3_CA"]} if url.startswith("https") else {}
s3 = boto3.client("s3", endpoint_url=url, aws_access_key_id=os.environ["AK"],
                  aws_secret_access_key=os.environ["SK"], region_name="us-east-1", **kw)
cmd, *a = sys.argv[1:]
def err(e): print("ERR", e.response["Error"]["Code"], e.response["ResponseMetadata"]["HTTPStatusCode"])
try:
    if cmd == "mb": s3.create_bucket(Bucket=a[0]); print("ok")
    elif cmd == "put":
        extra = json.loads(a[3]) if len(a) > 3 else {}
        r = s3.put_object(Bucket=a[0], Key=a[1], Body=a[2].encode(), **extra)
        print(r.get("ServerSideEncryption", "-"), r["ETag"].strip('"'))
    elif cmd == "get":
        extra = json.loads(a[2]) if len(a) > 2 else {}
        r = s3.get_object(Bucket=a[0], Key=a[1], **extra)
        print(r.get("ServerSideEncryption", "-"), r["Body"].read().decode())
    elif cmd == "head":
        r = s3.head_object(Bucket=a[0], Key=a[1])
        print(r.get("ServerSideEncryption", "-"), r["ContentLength"], r["ETag"].strip('"'))
    elif cmd == "mpu":            # bucket key size-MiB [sse]
        body = (b"0123456789abcdef" * 65536) * int(a[2])
        extra = {"ServerSideEncryption": "AES256"} if len(a) > 3 else {}
        up = s3.create_multipart_upload(Bucket=a[0], Key=a[1], **extra)
        parts = []
        for i in range(0, len(body), 5 << 20):
            r = s3.upload_part(Bucket=a[0], Key=a[1], UploadId=up["UploadId"],
                               PartNumber=len(parts) + 1, Body=body[i:i + (5 << 20)])
            parts.append({"PartNumber": len(parts) + 1, "ETag": r["ETag"]})
        r = s3.complete_multipart_upload(Bucket=a[0], Key=a[1], UploadId=up["UploadId"],
                                         MultipartUpload={"Parts": parts})
        g = s3.get_object(Bucket=a[0], Key=a[1])["Body"].read()
        print(up.get("ServerSideEncryption", "-"), "match" if g == body else "MISMATCH")
    elif cmd == "copy":           # bucket src dst [extra-json]
        extra = json.loads(a[3]) if len(a) > 3 else {}
        r = s3.copy_object(Bucket=a[0], Key=a[2], CopySource={"Bucket": a[0], "Key": a[1]}, **extra)
        print(r.get("ServerSideEncryption", "-"))
    elif cmd == "partcopy":       # bucket src dst
        up = s3.create_multipart_upload(Bucket=a[0], Key=a[2])
        r = s3.upload_part_copy(Bucket=a[0], Key=a[2], UploadId=up["UploadId"], PartNumber=1,
                                CopySource={"Bucket": a[0], "Key": a[1]})
        s3.complete_multipart_upload(Bucket=a[0], Key=a[2], UploadId=up["UploadId"],
            MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": r["CopyPartResult"]["ETag"]}]})
        print(s3.get_object(Bucket=a[0], Key=a[2])["Body"].read().decode())
    elif cmd == "putenc":
        s3.put_bucket_encryption(Bucket=a[0], ServerSideEncryptionConfiguration={"Rules": [
            {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": a[1]}}]}); print("ok")
    elif cmd == "getenc":
        r = s3.get_bucket_encryption(Bucket=a[0])
        print(r["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"])
    elif cmd == "delenc": s3.delete_bucket_encryption(Bucket=a[0]); print("ok")
    elif cmd == "ssecget":
        k = b"C" * 32
        r = s3.get_object(Bucket=a[0], Key=a[1], SSECustomerAlgorithm="AES256", SSECustomerKey=k)
        print(r["Body"].read().decode())
except botocore.exceptions.ClientError as e:
    err(e)
PY
export FS3_CA="$T.ca" AK SK
s3()  { FS3_URL="http://127.0.0.1:$PORT" python3 "$T.py" "$@" 2>&1 | tail -1; }
s3t() { FS3_URL="https://127.0.0.1:$TPORT" python3 "$T.py" "$@" 2>&1 | tail -1; }
md5() { printf '%s' "$1" | md5sum | cut -d' ' -f1; }
on_disk() { grep -rl --binary-files=text "$1" "$DATA/data" 2>/dev/null | wc -l | tr -d ' '; }

# ---- without a key file ---------------------------------------------------
start
s3 mb sseb >/dev/null
check_eq "AES256 without --sse-key-file refused" "$(s3 put sseb x hello '{"ServerSideEncryption":"AES256"}')" "ERR InvalidRequest 400"
check_eq "default encryption without keys refused" "$(s3 putenc sseb AES256)" "ERR InvalidRequest 400"
check_eq "plain PUT still works" "$(s3 put sseb plain hello | cut -d' ' -f1)" "-"
stop

# ---- key file permission checks -------------------------------------------
chmod 644 "$T.keys"
"$ROOT/fs3-tls" -p "$PORT" -d "$DATA" --sse-key-file "$T.keys" >"$T.out" 2>&1 && r=0 || r=$?
check_eq "group/world-readable key file refused" "$r/$(grep -c 'chmod 600' "$T.out")" "2/1"
chmod 600 "$T.keys"
printf 'k1 abcd\n' > "$T.bad"; chmod 600 "$T.bad"
"$ROOT/fs3-tls" -p "$PORT" -d "$DATA" --sse-key-file "$T.bad" >"$T.out" 2>&1 && r=0 || r=$?
check_eq "malformed key refused" "$r/$(grep -c '64 hex' "$T.out")" "2/1"

# ---- explicit SSE-S3 ------------------------------------------------------
start --sse-key-file "$T.keys"
SECRET="top-secret-plaintext-$$"
out=$(s3 put sseb enc "$SECRET" '{"ServerSideEncryption":"AES256"}')
check_eq "PUT answers ServerSideEncryption AES256" "$(echo "$out" | cut -d' ' -f1)" AES256
check_eq "ETag is the plaintext MD5" "$(echo "$out" | cut -d' ' -f2)" "$(md5 "$SECRET")"
check_eq "plaintext not on disk" "$(on_disk "$SECRET")" 0
check_eq "HEAD reports AES256 and the plaintext length" "$(s3 head sseb enc | cut -d' ' -f1,2)" "AES256 ${#SECRET}"
check_eq "GET decrypts" "$(s3 get sseb enc)" "AES256 $SECRET"
check_eq "ranged GET" "$(s3 get sseb enc '{"Range":"bytes=4-9"}')" "AES256 secret"
check_eq "aws:kms is not implemented" "$(s3 put sseb k x '{"ServerSideEncryption":"aws:kms"}')" "ERR NotImplemented 501"
check_eq "bad algorithm refused" "$(s3 put sseb k x '{"ServerSideEncryption":"ROT13"}' | cut -d' ' -f1,2)" "ERR InvalidArgument"
check_eq "customer key on an SSE-S3 object refused" "$(s3t ssecget sseb enc | cut -d' ' -f1,3)" "ERR 400"

# ---- bucket default encryption -------------------------------------------
check_eq "GET ?encryption before any" "$(s3 getenc sseb)" "ERR ServerSideEncryptionConfigurationNotFoundError 404"
check_eq "PUT ?encryption AES256" "$(s3 putenc sseb AES256)" ok
check_eq "PUT ?encryption aws:kms refused" "$(s3 putenc sseb aws:kms | cut -d' ' -f1,3)" "ERR 501"
check_eq "GET ?encryption" "$(s3 getenc sseb)" AES256
sleep 1.1    # the default is read through a 1 s cache
DSEC="default-encrypted-$$"
check_eq "plain PUT is sealed by default" "$(s3 put sseb dflt "$DSEC" | cut -d' ' -f1)" AES256
check_eq "default-sealed plaintext not on disk" "$(on_disk "$DSEC")" 0
check_eq "default-sealed GET" "$(s3 get sseb dflt)" "AES256 $DSEC"
check_eq "multipart under the default" "$(s3 mpu sseb big 12)" "AES256 match"
check_eq "multipart plaintext not on disk" "$(on_disk 0123456789abcdef0123456789abcdef)" 0
check_eq "multipart HEAD" "$(s3 head sseb big | cut -d' ' -f1)" AES256
check_eq "DELETE ?encryption" "$(s3 delenc sseb)" ok
sleep 1.1
check_eq "after delete, PUT is plain" "$(s3 put sseb plain2 hello | cut -d' ' -f1)" "-"
check_eq "explicit multipart" "$(s3 mpu sseb big2 6 sse)" "AES256 match"

# ---- copies ---------------------------------------------------------------
check_eq "copy SSE-S3 -> plain" "$(s3 copy sseb enc enc-plain)" "-"
check_eq "decrypted copy reads back" "$(s3 get sseb enc-plain)" "- $SECRET"
check_eq "decrypted copy is plaintext on disk" "$(on_disk "$SECRET")" 1
check_eq "copy plain -> SSE-S3" "$(s3 copy sseb plain plain-enc '{"ServerSideEncryption":"AES256"}')" AES256
check_eq "sealed copy reads back" "$(s3 get sseb plain-enc)" "AES256 hello"
check_eq "re-seal in place (REPLACE)" "$(s3 copy sseb enc enc '{"ServerSideEncryption":"AES256","MetadataDirective":"REPLACE"}')" AES256
check_eq "UploadPartCopy from an SSE-S3 source" "$(s3 partcopy sseb enc pc)" "$SECRET"

# ---- rotation -------------------------------------------------------------
printf 'k2 %s\nk1 %s\n' "$K2" "$K1" > "$T.keys"
kill -HUP "$SP"; sleep 1.5
check_eq "SIGHUP reload logged" "$(grep -c 'SSE key file reloaded (2 key' "$LOG")" 1
s3 put sseb new "fresh-$$" '{"ServerSideEncryption":"AES256"}' >/dev/null
check_eq "new object under the new key" "$(s3 get sseb new)" "AES256 fresh-$$"
check_eq "old object still readable" "$(s3 get sseb enc)" "AES256 $SECRET"
marker_count() {   # objects whose SSE-S3 TLV names key $1
    python3 - "$DATA/data/sseb" "$1" <<'PY'
import os, sys
root, kid = sys.argv[1], sys.argv[2].encode()
pat = b"\x07\x00" + bytes([2 + len(kid)]) + b"\x00\x00\x00\x01" + bytes([len(kid)]) + kid
print(sum(1 for d, _, fs in os.walk(root) for f in fs if pat in open(os.path.join(d, f), "rb").read(8192)))
PY
}
check_eq "exactly one object names k2" "$(marker_count k2)" 1
check_eq "the other five sealed objects name k1" "$(marker_count k1)" 5
printf 'k2 %s\n' "$K2" > "$T.keys"
kill -HUP "$SP"; sleep 1.5
check_eq "removing a key in use is refused" "$(grep -c 'was removed' "$LOG")" 1
check_eq "old object readable after the refused reload" "$(s3 get sseb enc)" "AES256 $SECRET"
printf 'k2 %s\nk1 %s\n' "$K1" "$K1" > "$T.keys"
kill -HUP "$SP"; sleep 1.5
check_eq "changing a key's value is refused" "$(grep -c 'changed value' "$LOG")" 1
stop

# ---- restart without a needed key ---------------------------------------
printf 'k2 %s\n' "$K2" > "$T.keys"
start --sse-key-file "$T.keys"
check_eq "object under a missing key: 500, nothing leaked" "$(s3 get sseb enc | cut -d' ' -f1,3)" "ERR 500"
check_eq "missing key logged" "$(grep -q 'not in the key file' "$LOG" && echo yes)" yes
check_eq "objects under present keys fine" "$(s3 get sseb new)" "AES256 fresh-$$"
stop

echo
echo "sse-s3 e2e: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
