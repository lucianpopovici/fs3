#!/usr/bin/env python3
"""boto_checksum.py — drive fs3 with boto3 in its *default* checksum
configuration (request_checksum_calculation=when_supported, the default
since boto3 1.36), i.e. with no AWS_REQUEST_CHECKSUM_CALCULATION
override. Each subcommand prints one line the e2e script compares."""
import os
import sys

import boto3
from botocore.config import Config


def client():
    for k in ("AWS_REQUEST_CHECKSUM_CALCULATION",
              "AWS_RESPONSE_CHECKSUM_VALIDATION"):
        os.environ.pop(k, None)
    return boto3.client(
        "s3", endpoint_url=os.environ["FS3_URL"],
        aws_access_key_id=os.environ["FS3_AK"],
        aws_secret_access_key=os.environ["FS3_SK"],
        region_name="us-east-1",
        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}))


def main():
    s3 = client()
    cmd = sys.argv[1]
    b = sys.argv[2]
    if cmd == "put":
        algo = sys.argv[5] if len(sys.argv) > 5 else None
        kw = {"ChecksumAlgorithm": algo} if algo else {}
        r = s3.put_object(Bucket=b, Key=sys.argv[3],
                          Body=open(sys.argv[4], "rb"), **kw)
        print(r["ResponseMetadata"]["HTTPStatusCode"])
    elif cmd == "head-checksum":
        r = s3.head_object(Bucket=b, Key=sys.argv[3], ChecksumMode="ENABLED")
        vals = [f"{k}={v}" for k, v in sorted(r.items()) if k.startswith("Checksum")]
        print(" ".join(vals) or "none")
    elif cmd == "get":
        r = s3.get_object(Bucket=b, Key=sys.argv[3], ChecksumMode="ENABLED")
        sys.stdout.buffer.write(r["Body"].read())
    elif cmd == "upload":
        from boto3.s3.transfer import TransferConfig
        algo = sys.argv[5] if len(sys.argv) > 5 else None
        extra = {"ChecksumAlgorithm": algo} if algo else None
        s3.upload_file(sys.argv[4], b, sys.argv[3], ExtraArgs=extra,
                       Config=TransferConfig(multipart_threshold=5 * 1024 * 1024,
                                             multipart_chunksize=5 * 1024 * 1024))
        print("ok")
    elif cmd == "download":
        s3.download_file(b, sys.argv[3], sys.argv[4])
        print("ok")
    elif cmd == "delete-objects":
        r = s3.delete_objects(Bucket=b, Delete={
            "Objects": [{"Key": k} for k in sys.argv[3:]]})
        print(len(r.get("Deleted", [])))


if __name__ == "__main__":
    main()
