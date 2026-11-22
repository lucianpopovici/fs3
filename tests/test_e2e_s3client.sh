#!/usr/bin/env bash
#
# tests/test_e2e_s3client.sh — the outbound S3 client used by replication
# (src/s3client.c), driven through tests/s3c_cli against a local fs3-tls:
# plain HTTP (payload SHA-256) and HTTPS (UNSIGNED-PAYLOAD), PUT/GET/HEAD/
# DELETE, keys that need encoding, user metadata, multipart create/part/
# complete and abort, keep-alive reuse, wrong secret, max-bytes on GET,
# and TLS verification failures (unknown CA, wrong host name, non-TLS
# build refusing https).
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 25300 + RANDOM % 300 ))}
TPORT=$((PORT + 1))
DATA=/tmp/fs3-s3c-e2e-$$
LOG=/tmp/fs3-s3c-e2e-$$.log
T=/tmp/fs3-s3c-$$
AK=AKIAS3CLIENTTEST01
SK=s3clientSecret01234567890123456789012345

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; [ $? -ne 159 ] || echo "FAIL: server died with SIGSYS" >&2; } || true
    rm -rf "$DATA" "$LOG" "$T".*
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3-tls tests/s3c_cli tests/s3c_cli_tls >/dev/null 2>&1) \
    || { echo "build failed" >&2; exit 1; }
# The driver exits 2 on a transport error; the tests check its output.
CLI=cli; CLIT=clit
cli()  { "$ROOT/tests/s3c_cli" "$@" 2>&1 || true; }
clit() { "$ROOT/tests/s3c_cli_tls" "$@" 2>&1 || true; }

# Test CA + a server cert for DNS:localhost only (so 127.0.0.1 is a name
# mismatch), and an unrelated CA.
printf '[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' > "$T.cacnf"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=fs3 test CA" \
    -config "$T.cacnf" -keyout "$T.cakey" -out "$T.ca" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=other CA" \
    -config "$T.cacnf" -keyout "$T.ocakey" -out "$T.oca" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=fs3" \
    -keyout "$T.key" -out "$T.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:localhost\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > "$T.ext"
openssl x509 -req -in "$T.csr" -CA "$T.ca" -CAkey "$T.cakey" -CAcreateserial \
    -days 1 -extfile "$T.ext" -out "$T.crt" >/dev/null 2>&1
chmod 600 "$T.key"

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}
field() { echo "$1" | tr ' ' '\n' | sed -n "s/^$2=//p" | head -1; }

${FS3_WRAP:-} "$ROOT/fs3-tls" -p "$PORT" -d "$DATA" --auth "$AK:$SK" --require-auth \
    --tls-port "$TPORT" --tls-cert "$T.crt" --tls-key "$T.key" >"$LOG" 2>&1 &
SP=$!
for _ in $(seq 50); do
    curl -s -o /dev/null "http://127.0.0.1:$PORT/health" && break
    sleep 0.1
done
kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }

FS3_AK=$AK FS3_SK=$SK python3 "$ROOT/tests/sign_request.py" --method PUT \
    --url "http://127.0.0.1:$PORT/dst" >/dev/null

head -c 300000 /dev/urandom > "$T.obj"
head -c 13000000 /dev/urandom > "$T.big"
MD5=$(md5sum < "$T.obj" | cut -d' ' -f1)
BIGMD5=$(md5sum < "$T.big" | cut -d' ' -f1)
PLAIN="http://127.0.0.1:$PORT"
TLS="https://127.0.0.1:$TPORT"
TLSH="https://localhost:$TPORT"

for mode in plain tls; do
    if [ $mode = plain ]; then run() { "$CLI" "$PLAIN" "$AK" "$SK" us-east-1 "$@"; }
    else run() { "$CLIT" --ca "$T.ca" "$TLSH" "$AK" "$SK" us-east-1 "$@"; }; fi

    out=$(run put dst "dir/a b+c%ü.bin" "$T.obj" application/x-test "x-amz-meta-origin=fs3 $mode")
    check_eq "$mode: PUT status" "$(field "$out" status)" 200
    check_eq "$mode: PUT etag is MD5" "$(field "$out" etag)" "$MD5"
    out=$(run head dst "dir/a b+c%ü.bin")
    check_eq "$mode: HEAD status" "$(field "$out" status)" 200
    check_eq "$mode: HEAD length" "$(field "$out" len)" 300000
    rm -f "$T.got"
    out=$(run get dst "dir/a b+c%ü.bin" "$T.got")
    check_eq "$mode: GET status" "$(field "$out" status)" 200
    check_eq "$mode: GET body" "$(md5sum < "$T.got" | cut -d' ' -f1)" "$MD5"
    meta=$(FS3_AK=$AK FS3_SK=$SK python3 - "$PLAIN" <<'PY'
import sys, os; sys.modules["awscrt"] = None; import boto3
s3 = boto3.client("s3", endpoint_url=sys.argv[1], aws_access_key_id=os.environ["FS3_AK"],
                  aws_secret_access_key=os.environ["FS3_SK"], region_name="us-east-1")
h = s3.head_object(Bucket="dst", Key="dir/a b+c%ü.bin")
print(h["ContentType"], h["Metadata"].get("origin"))
PY
)
    check_eq "$mode: content-type and metadata stored" "$meta" "application/x-test fs3 $mode"
    out=$(run get dst "dir/a b+c%ü.bin" "$T.got" 1000)
    check_eq "$mode: GET over max-bytes is a transport error" "$(echo "$out" | cut -c1-6)" "error:"
    out=$(run get dst nope "$T.got")
    check_eq "$mode: GET missing -> 404 NoSuchKey" "$(field "$out" status)/$(field "$out" code)" "404/NoSuchKey"
    out=$(run mpu dst big "$T.big" 5242880)
    check_eq "$mode: multipart complete" "$(field "$out" status)" 200
    check_eq "$mode: multipart ETag has part count" "$(field "$out" etag | sed 's/.*-//')" 3
    rm -f "$T.got"; run get dst big "$T.got" >/dev/null
    check_eq "$mode: multipart body" "$(md5sum < "$T.got" | cut -d' ' -f1)" "$BIGMD5"
    out=$(run mpu-abort dst aborted "$T.big" 5242880)
    check_eq "$mode: multipart abort" "$(field "$out" status)" 204
    out=$(run multi dst ka "$T.obj" 5)
    check_eq "$mode: 5 PUTs on one connection" "$(field "$out" status)/$(field "$out" connects)" 200/1
    out=$(run mpu dst big2 "$T.big" 5242880)
    check_eq "$mode: whole multipart upload on one connection" "$(field "$out" connects)" 1
    out=$(run delete dst "dir/a b+c%ü.bin")
    check_eq "$mode: DELETE" "$(field "$out" status)" 204
    out=$(run head dst "dir/a b+c%ü.bin")
    check_eq "$mode: HEAD after DELETE" "$(field "$out" status)" 404
done

out=$("$CLI" "$PLAIN" "$AK" wrongsecret us-east-1 head dst ka.0)
check_eq "wrong secret -> 403" "$(field "$out" status)" 403
out=$("$CLI" "$PLAIN" "$AK" wrongsecret us-east-1 put dst x "$T.obj")
check_eq "wrong secret PUT -> SignatureDoesNotMatch" "$(field "$out" code)" SignatureDoesNotMatch

out=$("$CLIT" "$TLSH" "$AK" "$SK" us-east-1 head dst ka.0)
check_eq "TLS: unknown CA refused" "$(echo "$out" | grep -c '^error: .*certificate' || true)" 1
out=$("$CLIT" --ca "$T.oca" "$TLSH" "$AK" "$SK" us-east-1 head dst ka.0)
check_eq "TLS: wrong CA refused" "$(echo "$out" | grep -c '^error: .*certificate' || true)" 1
out=$("$CLIT" --ca "$T.ca" "$TLS" "$AK" "$SK" us-east-1 head dst ka.0)
check_eq "TLS: IP not in certificate refused" "$(echo "$out" | grep -c '^error: .*mismatch' || true)" 1
out=$("$CLIT" --insecure "$TLS" "$AK" "$SK" us-east-1 head dst ka.0)
check_eq "TLS: --insecure skips verification" "$(field "$out" status)" 200
out=$("$CLI" --ca "$T.ca" "$TLS" "$AK" "$SK" us-east-1 head dst ka.0)
check_eq "non-TLS build refuses https" "$(echo "$out" | grep -c 'no TLS support' || true)" 1

out=$("$CLI" "ftp://x" a b c head d e || true)
check_eq "endpoint: bad scheme" "$(echo "$out" | cut -c1-12)" "bad endpoint"
out=$("$CLI" "http://h/path" a b c head d e || true)
check_eq "endpoint: path refused" "$(echo "$out" | cut -c1-12)" "bad endpoint"
out=$("$CLI" "http://h:99999" a b c head d e || true)
check_eq "endpoint: bad port" "$(echo "$out" | cut -c1-12)" "bad endpoint"
out=$("$CLI" "http://127.0.0.1:1" "$AK" "$SK" us-east-1 head dst x || true)
check_eq "connection refused is a transport error" "$(echo "$out" | grep -c 'connect' || true)" 1

echo
echo "s3client e2e: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
