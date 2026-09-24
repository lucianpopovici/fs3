#!/usr/bin/env python3
"""sign_slow_put.py — send a signed PUT in two halves with a pause in
between.

Used by tests/test_e2e_identity.sh's SIGHUP/ASan use-after-free
regression: the shell test rewrites the credentials file and sends
SIGHUP while this script is paused mid-body, then lets it finish, to
prove sigv4_verify_principal's captured principal (copied into conn_t
at verify time, never a pointer into the credential list) survives a
sigv4_swap_creds that lands mid-request.

Protocol on stdout:
    PAUSED           — first half of the body sent; now blocked reading
                        a line from stdin
    STATUS=<code>    — final response status line's code, after the
                        second half was sent and a response arrived
    STATUS=TIMEOUT   — no response within the read timeout (still not a
                        crash — the caller checks the server log for
                        ASan/UBSan output separately)

Environment: FS3_AK, FS3_SK (as sign_request.py).
"""
import argparse
import os
import socket
import sys

from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--bucket", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--size", type=int, default=4 * 1024 * 1024)
    args = p.parse_args()

    ak = os.environ.get("FS3_AK")
    sk = os.environ.get("FS3_SK")
    if not ak or not sk:
        print("FS3_AK and FS3_SK must be set", file=sys.stderr)
        sys.exit(2)

    body = b"y" * args.size
    host_header = f"{args.host}:{args.port}"
    url = f"http://{host_header}/{args.bucket}/{args.key}"

    creds = Credentials(ak, sk)
    req = AWSRequest(method="PUT", url=url,
                     headers={"Content-Type": "application/octet-stream"},
                     data=body)
    signer = S3SigV4Auth(creds, "s3", "us-east-1")
    signer.add_auth(req)

    lines = [f"PUT /{args.bucket}/{args.key} HTTP/1.1",
             f"Host: {host_header}"]
    for k, v in req.headers.items():
        lines.append(f"{k}: {v}")
    lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    request_head = "\r\n".join(lines) + "\r\n\r\n"

    s = socket.create_connection((args.host, args.port), timeout=10)
    s.sendall(request_head.encode())

    half = len(body) // 2
    s.sendall(body[:half])

    print("PAUSED")
    sys.stdout.flush()
    sys.stdin.readline()  # blocks until the shell test signals resume

    s.sendall(body[half:])

    s.settimeout(10)
    resp = b""
    try:
        while b"\r\n" not in resp:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
    except socket.timeout:
        pass
    s.close()

    status_line = resp.split(b"\r\n", 1)[0].decode(errors="replace")
    parts = status_line.split(" ", 2)
    code = parts[1] if len(parts) > 1 else "TIMEOUT"
    print(f"STATUS={code}")


if __name__ == "__main__":
    main()
