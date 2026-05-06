#!/usr/bin/env python3
"""sign_chunked.py — send a streaming-chunked SigV4 PUT request.

Used by the e2e test suite to exercise fs3's chunked-SigV4 decoder.
Produces wire bytes manually rather than going through boto3/botocore's
full upload pipeline, which would either skip the chunked path entirely
or use multipart upload — neither tests our decoder.

The framing is the AWS-documented STREAMING-AWS4-HMAC-SHA256-PAYLOAD:

    Authorization: AWS4-HMAC-SHA256 Credential=.../aws4_request,
        SignedHeaders=...;x-amz-decoded-content-length;...,
        Signature=<seed_signature>
    x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD
    x-amz-decoded-content-length: <total decoded bytes>

    <hex_size>;chunk-signature=<sig>\\r\\n
    <data of hex_size bytes>\\r\\n
    ...
    0;chunk-signature=<final_sig>\\r\\n
    \\r\\n

Each per-chunk signature is HMAC(signing_key, string_to_sign) where
string_to_sign for chunk N is:
    AWS4-HMAC-SHA256-PAYLOAD\\n
    <amz_date>\\n
    <credential_scope>\\n
    <prev_signature>\\n
    <SHA256("") hex>\\n
    <SHA256(chunk_data) hex>

Usage:
    sign_chunked.py --url URL --body STR --chunk-size N [--malform=MODE]
"""
import argparse
import datetime
import hashlib
import hmac
import os
import socket
import sys
from urllib.parse import urlparse


EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def sign(key, msg):
    return hmac.new(key, msg.encode() if isinstance(msg, str) else msg,
                    hashlib.sha256).digest()


def derive_signing_key(secret, date, region, service):
    k = sign(("AWS4" + secret).encode(), date)
    k = sign(k, region)
    k = sign(k, service)
    k = sign(k, "aws4_request")
    return k


def hexd(b): return b.hex()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--body", default=None)
    p.add_argument("--body-file", default=None)
    p.add_argument("--chunk-size", type=int, default=64 * 1024)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--service", default="s3")
    p.add_argument("--malform",
                   choices=("none", "chunk-sig", "data-mismatch", "no-terminator",
                            "wrong-decoded-len", "trailer-sig", "no-trailer-sig",
                            "trailer-line"),
                   default="none",
                   help="Inject a fault for negative testing")
    p.add_argument("--trailer", action="store_true",
                   help="Use STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER form "
                        "(adds an x-amz-checksum-sha256 trailer with the "
                        "body's SHA-256 in base64).")
    args = p.parse_args()

    ak = os.environ["FS3_AK"]
    sk = os.environ["FS3_SK"]
    if args.body_file:
        body = open(args.body_file, "rb").read()
    elif args.body is not None:
        body = args.body.encode() if isinstance(args.body, str) else args.body
    else:
        sys.exit("--body or --body-file required")

    u = urlparse(args.url)
    host = u.netloc
    path = u.path or "/"

    # Fixed time for reproducibility (use real time so skew passes).
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_only = amz_date[:8]
    scope = f"{date_only}/{args.region}/{args.service}/aws4_request"

    # Split body into chunks
    chunks = [body[i:i + args.chunk_size]
              for i in range(0, len(body), args.chunk_size)]

    # Total decoded length (fs3 verifies via x-amz-decoded-content-length)
    decoded_len = len(body)
    if args.malform == "wrong-decoded-len":
        decoded_len = len(body) + 1

    # ----- Seed signature (header-mode SigV4) -----
    # Canonical request includes the literal streaming body-hash sentinel,
    # and signs host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length
    # plus x-amz-trailer when in trailer mode.
    if args.trailer:
        body_hash_sentinel = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
        trailer_names = "x-amz-checksum-sha256"
        signed_headers = ("host;x-amz-content-sha256;x-amz-date;"
                          "x-amz-decoded-content-length;x-amz-trailer")
        canonical_headers = (
            f"host:{host}\n"
            f"x-amz-content-sha256:{body_hash_sentinel}\n"
            f"x-amz-date:{amz_date}\n"
            f"x-amz-decoded-content-length:{decoded_len}\n"
            f"x-amz-trailer:{trailer_names}\n"
        )
    else:
        body_hash_sentinel = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
        trailer_names = None
        signed_headers = ("host;x-amz-content-sha256;x-amz-date;"
                          "x-amz-decoded-content-length")
        canonical_headers = (
            f"host:{host}\n"
            f"x-amz-content-sha256:{body_hash_sentinel}\n"
            f"x-amz-date:{amz_date}\n"
            f"x-amz-decoded-content-length:{decoded_len}\n"
        )
    canonical_request = (
        f"PUT\n"
        f"{path}\n"
        f"\n"
        f"{canonical_headers}\n"
        f"{signed_headers}\n"
        f"{body_hash_sentinel}"
    )
    cr_hash = hashlib.sha256(canonical_request.encode()).hexdigest()
    sts = (f"AWS4-HMAC-SHA256\n"
           f"{amz_date}\n"
           f"{scope}\n"
           f"{cr_hash}")

    signing_key = derive_signing_key(sk, date_only, args.region, args.service)
    seed_sig = hexd(sign(signing_key, sts))

    auth_header = (
        f"AWS4-HMAC-SHA256 "
        f"Credential={ak}/{scope}, "
        f"SignedHeaders={signed_headers}, "
        f"Signature={seed_sig}"
    )

    # ----- Build chunked body -----
    prev_sig = seed_sig
    body_pieces = []
    for chunk in chunks:
        data_hash = hashlib.sha256(chunk).hexdigest()
        chunk_sts = (
            f"AWS4-HMAC-SHA256-PAYLOAD\n"
            f"{amz_date}\n"
            f"{scope}\n"
            f"{prev_sig}\n"
            f"{EMPTY_HASH}\n"
            f"{data_hash}"
        )
        chunk_sig = hexd(sign(signing_key, chunk_sts))
        if args.malform == "chunk-sig":
            # Mangle the signature
            chunk_sig = chunk_sig[:-1] + ("0" if chunk_sig[-1] != "0" else "1")
            args.malform = "none"  # only do it once
        body_pieces.append(
            f"{len(chunk):x};chunk-signature={chunk_sig}\r\n".encode()
        )
        if args.malform == "data-mismatch":
            # Send different data than what we hashed
            mangled = b"X" * len(chunk)
            body_pieces.append(mangled)
            args.malform = "none"
        else:
            body_pieces.append(chunk)
        body_pieces.append(b"\r\n")
        prev_sig = chunk_sig

    if args.malform != "no-terminator":
        # Terminator chunk
        empty_hash = hashlib.sha256(b"").hexdigest()
        chunk_sts = (
            f"AWS4-HMAC-SHA256-PAYLOAD\n"
            f"{amz_date}\n"
            f"{scope}\n"
            f"{prev_sig}\n"
            f"{EMPTY_HASH}\n"
            f"{empty_hash}"
        )
        chunk_sig = hexd(sign(signing_key, chunk_sts))
        body_pieces.append(
            f"0;chunk-signature={chunk_sig}\r\n".encode()
        )

        if args.trailer:
            # Emit trailer headers, then x-amz-trailer-signature, then \r\n.
            import base64
            checksum_b64 = base64.b64encode(
                hashlib.sha256(body).digest()
            ).decode()
            trailer_pairs = [("x-amz-checksum-sha256", checksum_b64)]

            # canonical_trailer: "<lc-name>:<trimmed-value>\n" per trailer,
            # sorted by name. Value-trim mirrors canonical-headers.
            canon_trailer = "".join(
                f"{n}:{v}\n" for n, v in sorted(trailer_pairs)
            )
            canon_trailer_hash = hashlib.sha256(canon_trailer.encode()).hexdigest()

            # The trailer signature's "previous signature" is the
            # terminator chunk's signature (chunk_sig above).
            trailer_sts = (
                f"AWS4-HMAC-SHA256-TRAILER\n"
                f"{amz_date}\n"
                f"{scope}\n"
                f"{chunk_sig}\n"
                f"{canon_trailer_hash}"
            )
            trailer_sig = hexd(sign(signing_key, trailer_sts))
            if args.malform == "trailer-sig":
                trailer_sig = trailer_sig[:-1] + (
                    "0" if trailer_sig[-1] != "0" else "1")

            for n, v in trailer_pairs:
                if args.malform == "trailer-line" and n == "x-amz-checksum-sha256":
                    # Send a different value than what was signed.
                    body_pieces.append(f"{n}:tampered=\r\n".encode())
                else:
                    body_pieces.append(f"{n}:{v}\r\n".encode())
            if args.malform != "no-trailer-sig":
                body_pieces.append(
                    f"x-amz-trailer-signature:{trailer_sig}\r\n".encode()
                )

        body_pieces.append(b"\r\n")

    wire_body = b"".join(body_pieces)
    content_length = len(wire_body)

    # ----- Build and send HTTP request -----
    extra_headers = ""
    if args.trailer:
        extra_headers = f"x-amz-trailer: {trailer_names}\r\n"
    http_request = (
        f"PUT {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Authorization: {auth_header}\r\n"
        f"x-amz-content-sha256: {body_hash_sentinel}\r\n"
        f"x-amz-date: {amz_date}\r\n"
        f"x-amz-decoded-content-length: {decoded_len}\r\n"
        f"{extra_headers}"
        f"Content-Length: {content_length}\r\n"
        f"\r\n"
    ).encode() + wire_body

    # Open raw socket
    host_only = host.split(":")[0]
    port = int(host.split(":")[1]) if ":" in host else 80
    s = socket.create_connection((host_only, port), timeout=10)
    s.sendall(http_request)
    s.shutdown(socket.SHUT_WR)
    response = b""
    while True:
        chunk = s.recv(65536)
        if not chunk: break
        response += chunk
    s.close()

    # Parse response status line
    head, _, body_resp = response.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0]
    parts = status_line.split(b" ", 2)
    status = int(parts[1]) if len(parts) >= 2 else 0
    print(f"STATUS={status}")
    sys.stdout.flush()
    sys.stdout.buffer.write(body_resp)


if __name__ == "__main__":
    main()
