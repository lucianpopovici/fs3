#!/usr/bin/env python3
"""sign_trailer.py — send an aws-chunked PUT with a checksum trailer.

Exercises both trailer variants of streaming SigV4:

  --mode unsigned   x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER
                    <hex>\\r\\n<data>\\r\\n ... 0\\r\\n
                    x-amz-checksum-crc32:<b64>\\r\\n\\r\\n
  --mode signed     x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER
                    chunks carry ;chunk-signature= as usual, then
                    0;chunk-signature=<sig>\\r\\n
                    x-amz-checksum-crc32:<b64>\\r\\n
                    x-amz-trailer-signature:<sig>\\r\\n\\r\\n

Trailer string-to-sign (signed variant):
    AWS4-HMAC-SHA256-TRAILER\\n<date>\\n<scope>\\n<prev-sig>\\n
    hex(SHA256("x-amz-checksum-crc32:<b64>\\n"))

--split N sends the wire bytes in N-byte writes with a short pause, so
CRLFs and the trailer land across several on_body callbacks.

Prints STATUS=<code> then the response body.
"""
import argparse
import base64
import datetime
import hashlib
import hmac
import os
import socket
import sys
import time
import zlib
from urllib.parse import urlparse

EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def _crc32c(data):
    poly = 0x82F63B78
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (poly if c & 1 else 0)
        table.append(c)
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF


def _crc64nvme(data):
    poly = 0x9A6C9329AC4BC9B5            # reflected CRC-64/NVME
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ (poly if c & 1 else 0)
        table.append(c)
    crc = 0xFFFFFFFFFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ table[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFFFFFFFFFF


def checksum(algo, data):
    if algo == "crc32":
        return (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, "big")
    if algo == "crc32c":
        return _crc32c(data).to_bytes(4, "big")
    if algo == "crc64nvme":
        return _crc64nvme(data).to_bytes(8, "big")
    if algo == "sha256":
        return hashlib.sha256(data).digest()
    if algo == "sha1":
        return hashlib.sha1(data).digest()
    raise SystemExit("unsupported algo " + algo)


def sign(key, msg):
    return hmac.new(key, msg.encode() if isinstance(msg, str) else msg,
                    hashlib.sha256).digest()


def signing_key(secret, date, region, service):
    k = sign(("AWS4" + secret).encode(), date)
    k = sign(k, region)
    k = sign(k, service)
    return sign(k, "aws4_request")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--body", default=None)
    p.add_argument("--body-file", default=None)
    p.add_argument("--mode", choices=("signed", "unsigned"), default="unsigned")
    p.add_argument("--algo", default="crc32")
    p.add_argument("--chunk-size", type=int, default=64 * 1024)
    p.add_argument("--split", type=int, default=0)
    p.add_argument("--no-auth", action="store_true",
                   help="unsigned mode only: send without Authorization")
    p.add_argument("--malform", default="none",
                   choices=("none", "bad-cksum", "bad-trailer-sig",
                            "no-final-crlf", "unannounced", "no-trailer",
                            "long-trailer"))
    args = p.parse_args()

    ak = os.environ.get("FS3_AK", "")
    sk = os.environ.get("FS3_SK", "")
    if args.body_file:
        body = open(args.body_file, "rb").read()
    else:
        body = (args.body or "").encode()

    u = urlparse(args.url)
    host, path = u.netloc, u.path or "/"
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_only = amz_date[:8]
    scope = f"{date_only}/us-east-1/s3/aws4_request"
    payload = ("STREAMING-UNSIGNED-PAYLOAD-TRAILER" if args.mode == "unsigned"
               else "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER")
    trailer_name = f"x-amz-checksum-{args.algo}"

    ck = checksum(args.algo, body)
    if args.malform == "bad-cksum":
        ck = bytes([ck[0] ^ 0xFF]) + ck[1:]
    ck_b64 = base64.b64encode(ck).decode()

    hdrs = [
        ("host", host),
        ("content-encoding", "aws-chunked"),
        ("x-amz-content-sha256", payload),
        ("x-amz-date", amz_date),
        ("x-amz-decoded-content-length", str(len(body))),
        ("x-amz-trailer", trailer_name),
    ]
    hdrs.sort()
    signed = ";".join(k for k, _ in hdrs)
    key = signing_key(sk, date_only, "us-east-1", "s3") if sk else b""
    auth = None
    seed = ""
    if not args.no_auth:
        canon = "PUT\n%s\n\n%s\n%s\n%s" % (
            path, "".join(f"{k}:{v}\n" for k, v in hdrs), signed, payload)
        sts = "AWS4-HMAC-SHA256\n%s\n%s\n%s" % (
            amz_date, scope, hashlib.sha256(canon.encode()).hexdigest())
        seed = sign(key, sts).hex()
        auth = (f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
                f"SignedHeaders={signed}, Signature={seed}")

    prev = seed
    out = []
    chunks = [body[i:i + args.chunk_size]
              for i in range(0, len(body), args.chunk_size)]
    for chunk in chunks + [b""]:
        if args.mode == "signed":
            csts = "AWS4-HMAC-SHA256-PAYLOAD\n%s\n%s\n%s\n%s\n%s" % (
                amz_date, scope, prev, EMPTY_HASH,
                hashlib.sha256(chunk).hexdigest())
            sig = sign(key, csts).hex()
            out.append(f"{len(chunk):x};chunk-signature={sig}\r\n".encode())
            prev = sig
        else:
            out.append(f"{len(chunk):x}\r\n".encode())
        if chunk:
            out.append(chunk + b"\r\n")

    tname = trailer_name
    if args.malform == "unannounced":
        tname = "x-amz-checksum-sha1"
    tval = ck_b64
    if args.malform == "long-trailer":
        tval = "A" * 400
    if args.malform != "no-trailer":
        out.append(f"{tname}:{tval}\r\n".encode())
    if args.mode == "signed":
        th = hashlib.sha256(f"{tname}:{tval}\n".encode()).hexdigest()
        tsts = "AWS4-HMAC-SHA256-TRAILER\n%s\n%s\n%s\n%s" % (
            amz_date, scope, prev, th)
        tsig = sign(key, tsts).hex()
        if args.malform == "bad-trailer-sig":
            tsig = ("0" if tsig[0] != "0" else "1") + tsig[1:]
        out.append(f"x-amz-trailer-signature:{tsig}\r\n".encode())
    if args.malform != "no-final-crlf":
        out.append(b"\r\n")
    wire = b"".join(out)

    req = f"PUT {path} HTTP/1.1\r\nHost: {host}\r\n"
    if auth:
        req += f"Authorization: {auth}\r\n"
    for k, v in hdrs:
        if k != "host":
            req += f"{k}: {v}\r\n"
    req += f"Content-Length: {len(wire)}\r\nConnection: close\r\n\r\n"
    data = req.encode() + wire

    hp = host.split(":")
    s = socket.create_connection((hp[0], int(hp[1]) if len(hp) > 1 else 80),
                                 timeout=10)
    if args.split > 0:
        hlen = len(req)
        s.sendall(data[:hlen])
        for i in range(hlen, len(data), args.split):
            s.sendall(data[i:i + args.split])
            time.sleep(0.002)
    else:
        s.sendall(data)
    s.shutdown(socket.SHUT_WR)
    resp = b""
    while True:
        r = s.recv(65536)
        if not r:
            break
        resp += r
    s.close()
    head, _, rbody = resp.partition(b"\r\n\r\n")
    parts = head.split(b"\r\n", 1)[0].split(b" ", 2)
    print("STATUS=%d" % (int(parts[1]) if len(parts) >= 2 else 0))
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"x-amz-checksum"):
            print(line.decode())
    sys.stdout.flush()
    sys.stdout.buffer.write(rbody)


if __name__ == "__main__":
    main()
