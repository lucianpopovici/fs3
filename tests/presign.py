#!/usr/bin/env python3
"""presign.py — print a presigned URL from boto3.generate_presigned_url.

    presign.py get|put|head|delete BUCKET KEY [EXPIRES]
Env: FS3_URL, FS3_AK, FS3_SK."""
import os
import sys

import boto3
from botocore.config import Config

op, bucket, key = sys.argv[1:4]
expires = int(sys.argv[4]) if len(sys.argv) > 4 else 3600
s3 = boto3.client("s3", endpoint_url=os.environ["FS3_URL"],
                  aws_access_key_id=os.environ["FS3_AK"],
                  aws_secret_access_key=os.environ["FS3_SK"],
                  region_name="us-east-1",
                  config=Config(signature_version="s3v4",
                                s3={"addressing_style": "path"}))
method = {"get": "get_object", "put": "put_object", "head": "head_object",
          "delete": "delete_object"}[op]
print(s3.generate_presigned_url(method, Params={"Bucket": bucket, "Key": key},
                                ExpiresIn=expires))
