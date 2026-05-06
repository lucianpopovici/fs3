# fs3

A single-node S3-compatible object store in C. Phase 4 snapshot.

## Status

What's working end-to-end:

- **HTTP/1.1 server** — epoll loop, llhttp request parser, pipelined
  keep-alive, chunked transfer encoding. Clean under ASan + UBSan,
  handles 1000+ concurrent connections.
- **Filesystem-backed object store** — streaming PUT/GET, atomic
  rename + dirfsync durability, sendfile-backed reads, MD5 ETags,
  bucket creation with full S3-spec name validation, listing with
  prefix / delimiter rollup / marker / max-keys.
- **XML library** — your original library, hardened (proper escaping,
  OOM-safe builders, capacity-doubling growth) and extended with a
  recursive-descent parser, write-callback serializer, and helpers.
- **Wired together as an actual S3 server.** Handlers map HTTP requests
  to store operations, build proper S3 XML responses (`ListBucketResult`,
  `Error`), and stream large bodies via sendfile.

  - `PUT /bucket` — create bucket, returns 200 with Location header
  - `DELETE /bucket` — delete (only if empty), returns 204
  - `HEAD /bucket` — bucket existence check
  - `GET /bucket?prefix=…&delimiter=…&max-keys=…&marker=…` — list objects
  - `PUT /bucket/key` — streaming PUT, returns ETag header (MD5)
  - `GET /bucket/key` — streaming GET via sendfile, full S3 headers
  - `HEAD /bucket/key` — metadata only
  - `DELETE /bucket/key` — idempotent delete

  Responses larger than the 16 KB `wbuf` (long lists, long error messages)
  spill into a malloc'd `ext_body` buffer that the writable callback
  drains after the response head.

- **AWS Signature V4 verification** — header-mode SigV4 against
  configured `(access_key, secret_key)` pairs. Verifier matches AWS's
  S3SigV4Auth output byte-for-byte (verified against botocore-generated
  test vectors). Constant-time signature comparison via `CRYPTO_memcmp`.
  Skew check is ±15 minutes against `x-amz-date`.
- **Body-hash verification** — when the client declares a non-`UNSIGNED-PAYLOAD`
  `x-amz-content-sha256`, fs3 streams a SHA-256 over the body bytes as
  they arrive and compares against the declared value at end-of-body.
  Mismatch → abort the in-flight PUT (no object on disk) and return
  HTTP 400 `XAmzContentSHA256Mismatch`. Closes the gap that would
  otherwise let a malicious client lie about its body bytes.

- **Streaming chunked SigV4** (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`
  and `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`) — the framing the
  AWS CLI uses by default for any PUT. Per-chunk signatures are
  verified against the chained signing key (each chunk's signature
  feeds into the next chunk's string-to-sign). Bytes are streamed
  into the store writer only after their chunk signature has been
  verified, and any chunk-level failure aborts the in-flight PUT
  before commit. The decoder is a small state machine that handles
  arbitrarily-split feeds (a CRLF can land across two `on_body`
  callbacks). For the trailer form, post-body trailer headers
  (e.g. `x-amz-checksum-sha256`) are parsed and the
  `x-amz-trailer-signature` is verified against the canonical-trailer
  hash chained to the terminator chunk's signature; if the trailer
  signature fails, the PUT is aborted before commit.

- **Multipart upload** — `POST ?uploads`, `PUT ?partNumber=N&uploadId=ID`,
  `POST ?uploadId=ID` (Complete), `DELETE ?uploadId=ID` (Abort).
  Upload state lives at `<root>/mpu/<bucket>/<upload_id>/`: a small
  `meta` file plus one `part-NNNNN` file per uploaded part. Part
  uploads can come in any order and concurrently. CompleteMultipartUpload
  parses the XML body listing parts, validates part-number ordering
  and existence, then concatenates the part files into a single
  object atomically (tmp file → fsync → rename → fsync(parent_dir)).
  The completion ETag follows AWS's convention: `MD5(concat of
  raw 16-byte part-MD5s)` rendered as `"<hex>-<part_count>"`. On-disk
  schema bumped from 1 to 2 to carry `part_count` so subsequent GETs
  and listings return the suffixed ETag. The real AWS CLI
  (`aws s3 cp` of files >8 MB) round-trips byte-for-byte.

- **Service-level `ListAllMyBuckets`** — `GET /` returns a `<ListAllMyBucketsResult>`
  with all buckets sorted alphabetically, including their creation dates.
- **`ListMultipartUploads`** — `GET /bucket?uploads` lists all in-progress
  multipart uploads for a bucket, with key, upload ID, and initiation time.
- **Multipart upload GC** — `--mpu-gc-age <secs>` enables a periodic sweep
  (every 60 s) that removes abandoned uploads older than the configured age.
  Also runs once at startup to clean up leftovers from previous server runs.
  `604800` (7 days) is a reasonable production value; `0` disables (default).
- **HTTP `Range:` requests on GET** — `206 Partial Content` responses with
  `Content-Range:` header. Supports `bytes=start-end`, `bytes=start-`, and
  `bytes=-suffix` forms. Out-of-range requests return 416 with
  `Content-Range: bytes */total`.

What's *not* yet wired:

- The `STREAMING-UNSIGNED-PAYLOAD-TRAILER` variant (standard HTTP
  chunked + signed trailers, used by some clients when the body itself
  is unsigned but a checksum trailer is signed).
- Bucket subresources: location, versioning, lifecycle, CORS, etc.

## Layout

```
fs3/
├── Makefile
├── README.md
├── CLAUDE.md             implementation guidance for the SigV4 phase
├── include/
│   ├── conn.h            per-connection state machine
│   ├── log.h
│   ├── response.h        HTTP response builders (status, S3 errors, lists)
│   ├── route.h           request dispatcher
│   ├── s3.h              shared types (error codes, s3_str_t)
│   ├── server.h          epoll TCP server
│   ├── sigv4.h           SigV4 verifier API
│   └── store.h           object store interface
├── src/
│   ├── conn.c            llhttp glue, auth hookpoint, body streaming
│   ├── log.c
│   ├── main.c            argv parsing, signal handling, bootstrap
│   ├── response.c        response building (RFC 1123/ISO 8601/ETag/XML)
│   ├── route.c           HTTP method × path-shape → handler dispatch
│   ├── server.c          epoll accept + connection lifecycle
│   ├── sigv4.c           SigV4 canonical-request, signing-key, verify
│   └── store_fs.c        filesystem-backed object store
├── tests/
│   ├── test_e2e.sh       30 HTTP integration tests (no auth)
│   ├── test_e2e_auth.sh  35 SigV4 e2e tests (with auth, including chunked + trailer)
│   ├── test_e2e_mpu.sh   19 multipart upload e2e tests
│   ├── test_sigv4.c      34 SigV4 unit tests + AWS test vectors
│   ├── test_store.c      21 store-layer tests (incl. multipart)
│   ├── sign_request.py   botocore-based signing helper for e2e tests
│   └── sign_chunked.py   chunked-SigV4 signing helper
└── third_party/
    ├── llhttp/           vendored llhttp v9.3.0 (HTTP parser)
    └── xml/              extended XML library + tests
```

## Build

```
make                # release (-O2)
make DEBUG=1        # ASan + UBSan
make test           # build and run all tests (~115 tests + 50k fuzz iters)
make smoketest      # start server briefly, probe with curl
make clean
```

Dependencies: `gcc`, `libcrypto` (OpenSSL — `libssl-dev` on Debian/Ubuntu).

If `third_party/llhttp/` is empty, `make fetch-llhttp` retrieves the
sources via PyPI's `httptools` sdist (which vendors a stable llhttp
release). Network access required for that one target only.

The Makefile uses `-MMD -MP` to auto-generate header-dependency files,
so changing a header correctly invalidates the dependent object files.

## Run

```
./fs3                                        # listen on 127.0.0.1:9000, no auth
./fs3 -a 0.0.0.0 -p 9000 -d /var/lib/fs3 -v  # listen on all interfaces with logs

# With SigV4 auth (use real-looking credentials):
./fs3 --auth AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY \
      --auth AKIAOTHER:secretXXXXXXXXXXXX \
      --require-auth -d /var/lib/fs3
```

Then point any S3 client at the server. The AWS CLI and boto3 work
with `--endpoint-url http://127.0.0.1:9000`. Test e2e with curl
(unauthenticated mode) or with `tests/sign_request.py` (which uses
botocore to sign).

The AWS CLI defaults to virtual-hosted-style URLs in recent versions
(e.g. `http://bucket.s3.amazonaws.com/key`), which doesn't translate
to a host like `127.0.0.1`. Force path-style by adding to `~/.aws/config`:

```
[default]
region = us-east-1
s3 =
    addressing_style = path
```

With that in place, `aws s3 cp` of files large enough to trigger
multipart upload (default >8 MB) round-trips byte-for-byte against fs3.

## Tests

| target                   | what it covers                                                |
|--------------------------|---------------------------------------------------------------|
| `tests/test_store`       | bucket CRUD, streaming PUT/GET, sendfile, listing, persistence, multipart lifecycle, GC sweep, ListAllMyBuckets |
| `tests/test_xml`         | XML library: escaping, parsing, security limits, round-trips  |
| `tests/test_xml_legacy`  | original calling style still works                            |
| `tests/test_xml_fuzz`    | 50,000 random byte inputs into `parse_xml`, must not crash    |
| `tests/test_sigv4`       | 34 SigV4 tests: primitives, full verifier against botocore-generated test vectors, body-hash streaming verification |
| `tests/test_e2e.sh`      | 30 HTTP integration tests (auth disabled, incl. Range, ListBuckets, ListMPU) |
| `tests/test_e2e_auth.sh` | 35 SigV4 integration tests (botocore-signed requests, body-hash mismatch detection, streaming chunked SigV4 with happy path + failure modes, plus trailer-form happy path + 4 failure modes) |
| `tests/test_e2e_mpu.sh`  | 19 multipart upload e2e tests (full lifecycle, abort, missing parts, malformed XML, large multipart) |

The HTTP e2e suite covers: bucket create / duplicate / invalid name,
object PUT/GET (with ETag verification against known MD5), HEAD,
DELETE, overwrite, missing bucket/key 404s with proper S3 error XML,
listing (basic, truncated, prefix, delimiter rollup), XML escaping in
response bodies, HTTP/1.1 keep-alive pipelining, large-object
sendfile, content-type round-trip, path-traversal protection, and the
ext_body spillover path for responses > 16 KB.

The SigV4 e2e suite covers: valid signed PUT/GET/DELETE, missing
Authorization → AccessDenied, tampered signature →
SignatureDoesNotMatch, unknown access key → AccessDenied, skewed
clock → RequestTimeTooSkewed, malformed Authorization → AccessDenied.

All eight targets pass under both release (`-O2`) and DEBUG (ASan +
UBSan) builds with zero warnings, leaks, or sanitizer findings.

## What's next

The natural next pieces, in rough order:

1. **Bucket subresources**: location, versioning, lifecycle, CORS, etc.
2. **`STREAMING-UNSIGNED-PAYLOAD-TRAILER`** — closes the remaining
   chunked-SigV4 gap (the variant where chunks are unsigned but the
   trailer is, used by some clients with unsigned bodies and a signed
   checksum trailer).
