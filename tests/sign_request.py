#!/usr/bin/env python3
"""sign_request.py — sign and send an S3 request to fs3 for e2e testing.

This is a thin wrapper around botocore that lets the e2e shell tests
issue properly-signed requests without us having to implement SigV4 in
shell. All it does is:

    1. Build an AWSRequest with the given method/url/body/headers.
    2. Sign it with S3SigV4Auth using the credentials from env.
    3. Send the request via urllib.
    4. Print "STATUS=<code>" then the response body to stdout.

Environment:
    FS3_AK, FS3_SK   — credentials
    FS3_REGION       — defaults to us-east-1
    FS3_SERVICE      — defaults to s3

CLI args:
    --method METHOD
    --url    URL
    --body   STRING (optional; mutually-exclusive with --body-file)
    --body-file PATH
    --header K:V    (repeatable)
    --skew  SECONDS  (offset the signing timestamp by this many seconds —
                      useful for testing the skew check)
"""
import argparse
import datetime
import os
import sys
import urllib.request
import urllib.error

from botocore.auth import S3SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--method", required=True)
    p.add_argument("--url", required=True)
    p.add_argument("--body", default=None)
    p.add_argument("--body-file", default=None)
    p.add_argument("--header", action="append", default=[])
    p.add_argument("--skew", type=int, default=0)
    args = p.parse_args()

    ak = os.environ.get("FS3_AK")
    sk = os.environ.get("FS3_SK")
    region = os.environ.get("FS3_REGION", "us-east-1")
    service = os.environ.get("FS3_SERVICE", "s3")
    if not ak or not sk:
        print("FS3_AK and FS3_SK must be set", file=sys.stderr)
        sys.exit(2)

    body = None
    if args.body is not None:
        body = args.body.encode()
    elif args.body_file:
        with open(args.body_file, "rb") as f:
            body = f.read()

    headers = {}
    for h in args.header:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    if args.skew:
        # Sign at a time offset from now, to test skew-rejection paths.
        import botocore.compat
        import botocore.auth
        offset = datetime.timedelta(seconds=args.skew)
        def fixed_now():
            return datetime.datetime.now(tz=datetime.timezone.utc) + offset
        botocore.compat.get_current_datetime = fixed_now
        botocore.auth.get_current_datetime = fixed_now

    creds = Credentials(ak, sk)
    req = AWSRequest(method=args.method, url=args.url,
                     headers=headers, data=body)
    signer = S3SigV4Auth(creds, service, region)
    signer.add_auth(req)

    # Translate botocore's signed AWSRequest into a urllib Request.
    ur = urllib.request.Request(req.url, method=req.method,
                                data=req.body if req.body else None)
    for k, v in req.headers.items():
        ur.add_header(k, v)

    try:
        with urllib.request.urlopen(ur) as r:
            print(f"STATUS={r.status}")
            sys.stdout.flush()
            sys.stdout.buffer.write(r.read())
    except urllib.error.HTTPError as e:
        print(f"STATUS={e.code}")
        sys.stdout.flush()
        sys.stdout.buffer.write(e.read())


if __name__ == "__main__":
    main()
