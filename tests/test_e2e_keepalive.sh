#!/usr/bin/env bash
#
# tests/test_e2e_keepalive.sh — keep-alive edge cases at the socket level.
#
# Regression (found by restic in the backup-tool compatibility matrix):
# a client that sends its next request while the previous response is
# still being written (here: a large GET the client hasn't read yet) must
# get an answer. fs3 used to feed those bytes to the paused HTTP parser,
# which swallowed them, and the client waited for the 60 s idle timeout.
# Also covered: pipelined requests in one segment, a request split across
# writes, and a body still arriving after an early error.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 24100 + RANDOM % 400 ))}
DATA=/tmp/fs3-keepalive-$$
LOG=/tmp/fs3-keepalive-$$.log
cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; }
    rm -rf "$DATA" "$LOG"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1) || { echo "build failed" >&2; exit 1; }

${FS3_WRAP:-} "$ROOT/fs3" -p "$PORT" -d "$DATA" --max-body-size 24M >"$LOG" 2>&1 &
SP=$!
for _ in $(seq 50); do curl -s -o /dev/null "http://127.0.0.1:$PORT/health" && break; sleep 0.1; done

curl -s -X PUT "http://127.0.0.1:$PORT/kab" >/dev/null
head -c 20000000 /dev/urandom > "$DATA.small"
curl -s -X PUT --data-binary @"$DATA.small" "http://127.0.0.1:$PORT/kab/small" >/dev/null
rm -f "$DATA.small"

python3 - "$PORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
passed = failed = 0
def check(name, cond, detail=""):
    global passed, failed
    if cond: passed += 1; print(".", end="", flush=True)
    else: failed += 1; print(f"\nFAIL: {name} {detail}")

class Conn:
    def __init__(self, rcvbuf=None):
        self.s = socket.socket()
        if rcvbuf: self.s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        self.s.connect(("127.0.0.1", port)); self.s.settimeout(5); self.buf = b""
    def send(self, b): self.s.sendall(b)
    def _fill(self):
        d = self.s.recv(65536)
        if not d: raise EOFError
        self.buf += d
    def response(self, head=False):
        while b"\r\n\r\n" not in self.buf: self._fill()
        h, self.buf = self.buf.split(b"\r\n\r\n", 1)
        lines = h.decode().split("\r\n")
        status = int(lines[0].split()[1])
        hdr = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:]}
        n = 0 if head or status in (204, 304) else int(hdr.get("content-length", 0))
        while len(self.buf) < n: self._fill()
        body, self.buf = self.buf[:n], self.buf[n:]
        return status, hdr, body

def req(m, path, extra=""):
    return f"{m} {path} HTTP/1.1\r\nHost: x\r\n{extra}\r\n".encode()

# 1. Next request sent while a large GET is still being written.
for method in ("HEAD", "GET"):
    c = Conn(rcvbuf=4096)
    c.send(req("GET", "/kab/small"))
    time.sleep(0.4)                      # server is now blocked mid-sendfile
    c.send(req(method, "/kab/small", "Range: bytes=0-9\r\n" if method == "GET" else ""))
    t0 = time.time()
    try:
        st1, _, b1 = c.response()
        st2, h2, b2 = c.response(head=(method == "HEAD"))
        ok = st1 == 200 and len(b1) == 20000000 and st2 in (200, 206) and time.time() - t0 < 4
        check(f"{method} sent during a large GET is answered", ok, f"st1={st1} st2={st2}")
        if method == "GET": check("ranged GET body after it", len(b2) == 10)
    except (socket.timeout, EOFError) as e:
        check(f"{method} sent during a large GET is answered", False, f"({type(e).__name__})")
    c.s.close()

# 2. Several pipelined requests in one segment.
c = Conn()
c.send(req("HEAD", "/kab/small") + req("GET", "/kab/small", "Range: bytes=5-9\r\n") + req("HEAD", "/kab/nope"))
try:
    a = c.response(head=True); b = c.response(); d = c.response(head=True)
    check("pipelined: three answers in order", (a[0], b[0], len(b[2]), d[0]) == (200, 206, 5, 404),
          str((a[0], b[0], len(b[2]), d[0])))
except (socket.timeout, EOFError) as e:
    check("pipelined: three answers in order", False, type(e).__name__)
c.s.close()

# 3. A request split across writes, then another on the same connection.
c = Conn()
r = req("GET", "/kab/small", "Range: bytes=0-3\r\n")
c.send(r[:17]); time.sleep(0.2); c.send(r[17:])
try:
    st, _, b = c.response()
    c.send(req("HEAD", "/kab/small")); st2, _, _ = c.response(head=True)
    check("split request, then keep-alive", (st, len(b), st2) == (206, 4, 200))
except (socket.timeout, EOFError) as e:
    check("split request, then keep-alive", False, type(e).__name__)
c.s.close()

# 4. An early error (body too large) while the body is still arriving:
#    the error arrives and the connection is either reusable or closed,
#    never wedged.
c = Conn()
body = b"x" * 26_000_000
c.send(f"PUT /kab/huge HTTP/1.1\r\nHost: x\r\nContent-Length: {len(body)}\r\n\r\n".encode())
try:
    for i in range(0, len(body), 65536): c.send(body[i:i + 65536])
except (BrokenPipeError, ConnectionResetError):
    pass
try:
    st, h, _ = c.response()
    check("early 4xx while the body streams", 400 <= st < 500, f"status={st}")
except (socket.timeout, EOFError, ConnectionResetError) as e:
    check("early 4xx while the body streams", False, type(e).__name__)
c.s.close()
c = Conn(); c.send(req("HEAD", "/kab/small"))
check("server still answers afterwards", c.response(head=True)[0] == 200)

print(f"\nkeepalive e2e: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
PY
