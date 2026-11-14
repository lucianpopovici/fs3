#!/usr/bin/env bash
#
# tests/test_e2e_tls.sh — item 7: native TLS listener (fs3-tls build).
# boto3 over https with a test CA (put/get/multipart/list/large GET via
# the non-kTLS bounce path), protocol policy via openssl s_client,
# trickled handshake hitting the idle timeout, many concurrent TLS
# connections, pipelined requests in one TLS write, SIGHUP cert reload,
# --require-tls on the plain listener, and key-permission checks.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 24900 + RANDOM % 300 ))}
TPORT=$((PORT + 1))
DATA=/tmp/fs3-tls-e2e-$$
LOG=/tmp/fs3-tls-e2e-$$.log
T=/tmp/fs3-tls-$$
AK=AKIATLSTEST00001
SK=tlsTestSecret0123456789012345678901234567

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; [ $? -ne 159 ] || echo "FAIL: server died with SIGSYS (seccomp blocked a syscall; see --seccomp=log)" >&2; } || true
    rm -rf "$DATA" "$LOG" "$T".*
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3-tls >/dev/null 2>&1) || { echo "fs3-tls build failed" >&2; exit 1; }

# Test CA + server cert for 127.0.0.1/localhost.
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=fs3 test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" \
    -keyout "$T.cakey" -out "$T.ca" >/dev/null 2>&1
mkcert() {
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$1" \
        -keyout "$T.key" -out "$T.csr" >/dev/null 2>&1
    printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\nsubjectKeyIdentifier=hash\nbasicConstraints=CA:FALSE\n' > "$T.ext"
    openssl x509 -req -in "$T.csr" -CA "$T.ca" -CAkey "$T.cakey" -CAcreateserial \
        -days 1 -extfile "$T.ext" -out "$T.crt" >/dev/null 2>&1
    chmod 600 "$T.key"
}
mkcert fs3-one

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}

chmod 644 "$T.key"
${FS3_WRAP:-} "$ROOT/fs3-tls" -p "$PORT" -d "$DATA" --tls-port "$TPORT" --tls-cert "$T.crt" --tls-key "$T.key" \
    >"$LOG" 2>&1 && r=started || r=refused
check_eq "world-readable key refused" "$r" "refused"
chmod 600 "$T.key"

${FS3_WRAP:-} "$ROOT/fs3-tls" -p "$PORT" -d "$DATA" --auth "$AK:$SK" --require-auth --require-tls \
    --tls-port "$TPORT" --tls-cert "$T.crt" --tls-key "$T.key" --idle-timeout 2 \
    --tls-max-per-ip 256 >"$LOG" 2>&1 &
SP=$!
sleep 0.5
kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }

export FS3_TLS_URL="https://127.0.0.1:$TPORT" FS3_CA="$T.ca" FS3_AK="$AK" FS3_SK="$SK"
out=$(python3 - <<'PY'
import os, boto3, hashlib
from boto3.s3.transfer import TransferConfig
s3 = boto3.client("s3", endpoint_url=os.environ["FS3_TLS_URL"], verify=os.environ["FS3_CA"],
                  aws_access_key_id=os.environ["FS3_AK"], aws_secret_access_key=os.environ["FS3_SK"],
                  region_name="us-east-1")
s3.create_bucket(Bucket="tlsb")
s3.put_object(Bucket="tlsb", Key="small", Body=b"over tls")
print(s3.get_object(Bucket="tlsb", Key="small")["Body"].read().decode())
big = os.urandom(20 * 1024 * 1024 + 123)
open("/tmp/fs3-tls-big", "wb").write(big)
s3.upload_file("/tmp/fs3-tls-big", "tlsb", "big", Config=TransferConfig(multipart_threshold=8 << 20))
got = s3.get_object(Bucket="tlsb", Key="big")["Body"].read()
print(hashlib.md5(got).hexdigest() == hashlib.md5(big).hexdigest())
r = s3.get_object(Bucket="tlsb", Key="big", Range="bytes=1000-1999")["Body"].read()
print(r == big[1000:2000])
print(len(s3.list_objects_v2(Bucket="tlsb")["Contents"]))
os.remove("/tmp/fs3-tls-big")
PY
)
check_eq "boto3 put/get over TLS" "$(echo "$out" | sed -n 1p)" "over tls"
check_eq "20 MB multipart + GET over TLS" "$(echo "$out" | sed -n 2p)" "True"
check_eq "ranged GET over TLS" "$(echo "$out" | sed -n 3p)" "True"
check_eq "list over TLS" "$(echo "$out" | sed -n 4p)" "2"

sc() { echo | timeout 5 openssl s_client -connect "127.0.0.1:$TPORT" -CAfile "$T.ca" "$@" 2>&1; }
check_eq "TLS 1.3 accepted" "$(sc -tls1_3 | grep -c '^New, TLS' || true)" "1"
check_eq "TLS 1.2 accepted" "$(sc -tls1_2 | grep -c '^New, TLS' || true)" "1"
check_eq "TLS 1.1 refused" "$(sc -tls1_1 | grep -c '^New, TLS' || true)" "0"
check_eq "TLS 1.2 CBC suite refused" \
    "$(sc -tls1_2 -cipher ECDHE-RSA-AES128-SHA | grep -c '^New, TLS' || true)" "0"
check_eq "ALPN h2-only refused" "$(sc -alpn h2 | grep -c '^New, TLS' || true)" "0"
check_eq "ALPN http/1.1 negotiated" "$(sc -alpn http/1.1 | grep -c 'ALPN protocol: http/1.1' || true)" "1"

# Plain listener: --require-tls refuses signed requests from non-loopback;
# loopback (this test) is allowed, so check the header-based path.
check_eq "plain HTTP from loopback still allowed" \
    "$(FS3_AK=$AK FS3_SK=$SK python3 "$ROOT/tests/sign_request.py" --method GET --url "http://127.0.0.1:$PORT/tlsb" 2>&1 | head -1)" "STATUS=200"

# Trickled handshake: idle timeout closes it; no FD leak.
fds_before=$(ls /proc/$SP/fd | wc -l)
python3 - "$TPORT" <<'PY'
import socket, sys, time
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
hello = bytes.fromhex("16030100")  # start of a ClientHello record, never finished
for b in hello:
    try:
        s.send(bytes([b])); time.sleep(0.05)
    except OSError:
        break
deadline = time.time() + 6
s.settimeout(1)
closed = False
while time.time() < deadline:
    try:
        if s.recv(1) == b"":
            closed = True; break
    except socket.timeout:
        continue
    except OSError:
        closed = True; break
print("closed" if closed else "open")
PY
sleep 0.5
fds_after=$(ls /proc/$SP/fd | wc -l)
check_eq "no FD leak after stalled handshake" "$fds_after" "$fds_before"

# Many concurrent TLS connections.
conc=$(python3 - <<'PY'
import os, ssl, socket, threading
ctx = ssl.create_default_context(cafile=os.environ["FS3_CA"])
port = int(os.environ["FS3_TLS_URL"].rsplit(":", 1)[1])
ok = [0]; lock = threading.Lock()
def one():
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as s:
                s.sendall(b"GET /_health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                data = b""
                while True:
                    d = s.recv(4096)
                    if not d: break
                    data += d
                if b" 200 " in data.split(b"\r\n", 1)[0]:
                    with lock: ok[0] += 1
    except Exception:
        pass
ts = [threading.Thread(target=one) for _ in range(60)]
[t.start() for t in ts]; [t.join() for t in ts]
print(ok[0])
PY
)
check_eq "60 concurrent TLS connections (under the 64-handshake cap)" "$conc" "60"

# Per-IP cap: with the default (32) the 33rd concurrent connection from
# one address is refused before the handshake.
cap=$(python3 - <<'PY'
import os, socket, time
port = int(os.environ["FS3_TLS_URL"].rsplit(":", 1)[1])
socks = [socket.create_connection(("127.0.0.1", port)) for _ in range(300)]
time.sleep(0.5)
dead = 0
for s in socks:
    s.setblocking(False)
    try:
        if s.recv(1) == b"": dead += 1
    except BlockingIOError:
        pass
    except OSError:
        dead += 1
print("capped" if dead >= 44 else f"uncapped:{dead}")
for s in socks: s.close()
PY
)
check_eq "per-IP / handshake caps refuse a flood" "$cap" "capped"
sleep 0.5

# Two pipelined requests in one TLS write (exercises SSL_pending).
pipe=$(python3 - <<'PY'
import os, ssl, socket
ctx = ssl.create_default_context(cafile=os.environ["FS3_CA"])
port = int(os.environ["FS3_TLS_URL"].rsplit(":", 1)[1])
with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
    with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as s:
        s.sendall(b"GET /_health HTTP/1.1\r\nHost: x\r\n\r\nGET /_health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        data = b""
        while True:
            d = s.recv(4096)
            if not d: break
            data += d
print(data.count(b"HTTP/1.1 200"))
PY
)
check_eq "pipelined requests in one TLS record" "$pipe" "2"

# SIGHUP reloads the certificate.
serial1=$(sc | openssl x509 -noout -serial 2>/dev/null)
mkcert fs3-two
kill -HUP "$SP"; sleep 1.5
serial2=$(sc | openssl x509 -noout -serial 2>/dev/null)
[ "$serial1" != "$serial2" ] && r=reloaded || r=same
check_eq "SIGHUP reloads certificate" "$r" "reloaded"
echo "garbage" > "$T.crt"
kill -HUP "$SP"; sleep 1.5
check_eq "bad cert on reload keeps the live one" "$(sc -tls1_3 | grep -c '^New, TLS' || true)" "1"
check_eq "server alive" "$(kill -0 "$SP" && echo yes)" "yes"

echo
echo "===== tls e2e: $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
