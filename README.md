# fs3

A single-node S3-compatible object store in C. Phase 3 snapshot.

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

- **Streaming chunked SigV4** (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) —
  the framing the AWS CLI uses by default for any PUT. Per-chunk
  signatures are verified against the chained signing key (each
  chunk's signature feeds into the next chunk's string-to-sign).
  Bytes are streamed into the store writer only after their chunk
  signature has been verified, and any chunk-level failure aborts
  the in-flight PUT before commit. The decoder is a small state
  machine that handles arbitrarily-split feeds (a CRLF can land
  across two `on_body` callbacks).

- **Trailer variants and additional checksums** — both
  `STREAMING-UNSIGNED-PAYLOAD-TRAILER` and
  `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` (trailer signature
  verified), which AWS SDKs send by default since early 2025 (boto3 ≥
  1.36, JS v3, Java v2, Go v2). `x-amz-checksum-{crc32,crc32c,sha1,
  sha256,crc64nvme}` is verified over the decoded body whether it comes
  as a header or a trailer, and `Content-MD5` is checked too; a mismatch
  aborts the upload before commit (`400 BadDigest`, nothing on disk). The
  checksum is stored in the object header (schema 3), echoed on the PUT
  response, and returned on GET/HEAD with `x-amz-checksum-mode: ENABLED`
  (never on ranged GETs). Multipart uploads created with
  `x-amz-checksum-algorithm` verify every part and store a COMPOSITE
  (`base64(algo(part digests))-N`) or FULL_OBJECT checksum (CRC64NVME is
  always full-object). CRC32/CRC32C/CRC64NVME are table-driven (no zlib;
  CRC32C uses SSE4.2 when the CPU has it). Decoder bounds: 16 hex digits
  per chunk size, 256-byte trailer lines, at most 4 trailers, only names
  announced in `x-amz-trailer`. In open mode (no auth) aws-chunked bodies
  are still de-framed, so chunk headers never end up in the object.

- **Presigned URLs** (query-string SigV4) — `X-Amz-Algorithm`,
  `-Credential`, `-Date`, `-Expires`, `-SignedHeaders`, `-Signature` in
  the query, as produced by `boto3.generate_presigned_url` and
  `aws s3 presign`; body hash `UNSIGNED-PAYLOAD` unless
  `X-Amz-Content-Sha256` is in the query. Lifetime is capped by
  `--presign-max-expires` (default 24 h; AWS's own 7-day ceiling always
  applies); expired URLs get `403 AccessDenied` "Request has expired".
  `--no-presign-admin` stops `--admin` identities from minting bearer
  URLs. A presigned URL never grants more than its signer has. Behind
  the DSM reverse proxy the client signs for the public host; the proxy
  preserves `Host`, so this works unchanged — but note that the DSM
  nginx access log records full presigned URLs, which are bearer
  credentials until they expire.
- **SigV4 hardening** (header and query mode) — `host` and every
  `x-amz-*` request header must be signed (an unsigned
  `x-amz-copy-source` on a presigned PUT is refused), the credential
  scope must be service `s3` with the date of `X-Amz-Date`, and
  duplicate `Authorization` / auth query parameters are rejected.

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

- **Service-level `ListAllMyBuckets`** (`GET /`) — enumerates the
  buckets directory under `<root>/buckets/`, emitting a
  `<ListAllMyBucketsResult>` with `<Owner>` (placeholder identity),
  `<Buckets>` and one `<Bucket>` per bucket with `<Name>` +
  `<CreationDate>` (the filesystem mtime). With auth on, only the
  caller's own buckets are listed (admins see all). Unblocks `aws s3 ls`
  without a bucket argument.

- **Per-user bucket isolation** — with auth configured, a bucket
  belongs to the user who created it, and only that user (or an
  `--admin`) can list, read, write, delete or copy from it; everyone
  else gets `403 AccessDenied`. A credential's user is the optional third
  field (`access_key:secret_key:user`), defaulting to the access key, so
  several keys can share a user and rotating a key keeps the user's
  buckets. Bucket names stay global: creating a name someone else owns is
  `409 BucketAlreadyExists`. Buckets created before isolation (or with
  auth off) have no owner and are admin-only until
  `--legacy-owner <user>` assigns them at startup. Anonymous requests
  (auth configured without `--require-auth`) own nothing and are refused.
  No auth configured means no identities and no isolation, as before.

- **Per-user bucket grants** (Garage-style) — `buckets/<b>/grants` holds
  one `user:perms` line per grantee, perms ⊆ `rwo`: `r` lists and reads,
  `w` writes, deletes and runs multipart uploads, `o` reads and changes
  bucket configuration. Deleting the bucket stays owner/admin-only.
  Granted buckets appear in the grantee's `ListAllMyBuckets`. Edits take
  effect on the next request (the parsed file is cached per bucket *id*
  and re-validated against its inode/mtime), and deleting and re-creating
  a bucket drops its grants. User names written by fs3 are restricted to
  `[A-Za-z0-9._@-]`; malformed lines are ignored, never widened. Grants
  are managed through the admin API (below) or by editing the file; S3
  ACL calls remain stubs.

- **`ListMultipartUploads`** (`GET /bucket?uploads`) — lists active
  multipart uploads in a bucket. Reads each upload's `meta` file
  on the fly rather than maintaining an in-memory index; for
  realistic homelab scales (hundreds of in-flight uploads at most)
  the per-listing cost is negligible. Supports `?prefix=` filtering
  on the key. `IsTruncated` is always `false` (no pagination yet —
  the practical cap is the directory entry limit, well above any
  realistic in-flight set).

- **Bucket policies** (strict IAM JSON subset) — `PUT/GET/DELETE
  /bucket?policy` (owner/admin only, ≤ 20 KB). Grammar: `Version`
  `2012-10-17`; statements with `Effect`, `Principal` (`"*"` or
  `{"AWS": user | arn:aws:iam:::user/<u> | "*"}`), `Action`/`NotAction`
  (`s3:*` patterns), `Resource` naming *this* bucket (`arn:aws:s3:::b`,
  `arn:aws:s3:::b/prefix*`) and `Condition` (`StringEquals`,
  `StringNotEquals`, `StringLike`, `IpAddress`, `NotIpAddress`, `Bool` on
  `aws:SourceIp`, `aws:SecureTransport`, `s3:prefix`, `aws:username`).
  Anything else — `NotPrincipal`, unknown keys or operators, duplicate JSON
  keys, other buckets — is `400 MalformedPolicy`. Evaluation: explicit
  Deny wins (owner and admins included); then owner, admin, grant or a
  matching Allow; otherwise deny. Anonymous requests get in only through
  an Allow with `Principal "*"` — that is how a public-read bucket works
  (fs3 must run without `--require-auth` for unsigned requests to reach
  the policy). Lockout rule: the owner and admins can always read,
  replace or delete the policy. Public policies need `--allow-public`;
  public *write* additionally needs `--allow-public-write`. Bulk delete
  evaluates each key. `aws:SourceIp`/`aws:SecureTransport` come from the
  connection, or from `X-Forwarded-For`/`X-Forwarded-Proto` only when the
  peer is listed in `--trusted-proxy` (e.g. `127.0.0.1` behind DSM).
  Behind the DSM proxy every peer is 127.0.0.1 and any local process or
  host-network container can forge those headers, so treat
  `aws:SourceIp` as advisory there.

- **Versioning** — `PUT/GET /bucket?versioning` (Enabled / Suspended;
  never back to Unset; MFA delete → 501). The current version stays at
  `data/...`, so unversioned GET and listing are as fast as before;
  superseded versions move to `versions/<b>/xx/yy/<hex>/<inv_ts>-<vid>`
  (newest first in directory order) through a hard link made under the
  key's stripe lock before the new current is renamed in — a crash in
  between leaves a duplicate link that startup recovery removes. DELETE
  writes a delete marker (`x-amz-delete-marker`, `x-amz-version-id`);
  `versionId` works on GET/HEAD/DELETE, copy sources and bulk delete;
  deleting the current version by id promotes the newest noncurrent one
  and deleting a marker undeletes. Suspended buckets write and overwrite
  the single null version. `GET /bucket?versions` (ListObjectVersions)
  paginates with `key-marker`/`version-id-marker` and supports
  prefix/delimiter. Every mutating response carries `x-amz-version-id`.
  A bucket can only be deleted once no current object, noncurrent
  version or marker is left; bucket stats report versions separately.
  Version ids are validated (32 hex or `null`) before any path is built.
- **`Expect: 100-continue`** is answered as soon as a request passes
  auth and routing. botocore sends it on every upload and used to wait
  its 1-second timeout per PUT.

- **Object Lock** — enabled only at bucket creation
  (`x-amz-bucket-object-lock-enabled: true`, which pins versioning to
  Enabled). `PUT/GET /bucket?object-lock` sets a default retention
  (GOVERNANCE/COMPLIANCE, Days/Years). Per-version retention and legal
  hold (`?retention`, `?legal-hold`, `versionId`, and the
  `x-amz-object-lock-*` PUT headers, which require Content-MD5 or an
  `x-amz-checksum-*`) live in sidecars under `locks/`, so retention can
  be extended without rewriting data. Enforcement is in the store: no
  path — S3 API, lifecycle, admin API — can permanently delete a version
  under legal hold or unexpired retention. COMPLIANCE can only be
  extended; GOVERNANCE can be shortened, removed or bypassed by an admin
  with `x-amz-bypass-governance-retention: true`. Overwriting or deleting
  the current key without a version id still works (it adds a version or
  marker). Setting retention needs the owner/`o` permission, not just
  `w`, and is capped by `--max-retention-days` (default 3650) so writers
  can't fill the volume with undeletable data. A missing lock record
  falls back to the bucket default; an unreadable one fails closed.
  Retention trusts the system clock; a backwards jump of more than an
  hour is logged. This is API-level WORM only: root on the NAS can still
  delete files (`FS_IMMUTABLE_FL` hardening is not implemented — it
  conflicts with the hard-link version scheme).

- **Static website hosting** (Garage's model) — `PUT/GET/DELETE
  /bucket?website` with `IndexDocument/Suffix`, `ErrorDocument/Key` or
  `RedirectAllRequestsTo` (`RoutingRules` → 501). A website config makes
  a bucket anonymously readable **only on a dedicated listener**
  (`--web-port 9080 --web-addr 127.0.0.1 --web-root-domain
  web.example.lan`); the S3 endpoint's auth model is untouched. The
  bucket comes from `Host`: `<bucket>.<root-domain>`, or a Host equal to
  a bucket name (custom domains through the DSM reverse proxy — one proxy
  entry per site hostname → `localhost:9080`). Only GET/HEAD; directory
  paths get the index suffix; `dir` without a slash redirects (302) to
  `dir/` when `dir/<index>` exists, with a normalised single-slash
  `Location` (no protocol-relative open redirect); misses serve the
  ErrorDocument with status 404, or a minimal HTML page. Range and
  sendfile work as on the S3 port. Authorization headers are ignored,
  subresource/`X-Amz-*` queries are refused, listing is never served, and
  errors are HTML, never S3 XML. Bucket CORS rules apply there too.
  **Block public access is on by default**: website configs are refused
  unless fs3 runs with `--allow-public`.

- **Lifecycle rules** — `PUT/GET/DELETE /bucket?lifecycle`:
  `Filter/Prefix` (also `Filter/And/Prefix` and the legacy `Rule/Prefix`),
  `Expiration/Days|Date`, `AbortIncompleteMultipartUpload/
  DaysAfterInitiation`, plus `NoncurrentVersionExpiration` and
  `ExpiredObjectDeleteMarker` for versioned buckets. Transitions and
  tag/size filters are refused with `501` rather than silently ignored.
  The sweeper runs on an I/O worker (never the event loop) once a day at
  `--lifecycle-hour` (default 03:00 local; `--lifecycle-now` adds a run at
  startup), deletes at most `--lifecycle-rate` objects per second
  (default 100), and goes through a guarded delete: the object's header
  is re-read under its stripe lock and left alone if a PUT replaced it
  mid-sweep. `--lifecycle-dry-run` logs instead of deleting. A rule
  whose `Expiration/Date` is already past (it would delete everything it
  matches at the next sweep) needs the header
  `x-fs3-confirm-immediate-expiry: true`. A bucket's
  `AbortIncompleteMultipartUpload` rule overrides the global MPU TTL for
  the keys it covers. Prometheus: `fs3_lifecycle_expired_total`,
  `fs3_lifecycle_aborted_mpu_total`, `fs3_lifecycle_runs_total`; every
  S3 error is also counted in `fs3_errors_total{error=…}`.

- **Multipart upload GC** — periodic in-process sweep, piggybacking
  on the event loop's 1-second `epoll_wait` timeout. Defaults to
  60-second sweep cadence and 24-hour TTL; tunable per CLI via
  `--mpu-gc-interval N` and `--mpu-gc-max-age N` (seconds). The
  sweep is conservative: staging dirs whose `meta` file is missing
  or has an unparseable `ctime_ms=` line are left alone.

- **CORS** — `PUT/GET/DELETE /bucket?cors` with a validated
  `CORSConfiguration` (≤ 100 rules, at most one `*` per origin, methods
  GET/PUT/POST/DELETE/HEAD), stored as `buckets/<b>/cors.xml`. Browser
  preflights (`OPTIONS`) are answered without SigV4; matching requests —
  including error responses — get `Access-Control-Allow-Origin`,
  `-Methods`, `-Expose-Headers` and `Vary: Origin`.
  `Access-Control-Allow-Credentials` is never sent. Preflights read the
  config through a 1-second cache, so they cause no per-request disk I/O
  and a missing bucket answers exactly like a bucket without a matching
  rule. Every response carries `X-Content-Type-Options: nosniff`, and
  anonymous or presigned GETs carry `Content-Security-Policy: sandbox`.
  Serve fs3 on its own hostname, never the DSM hostname on another port:
  cookies are not port-scoped.

- **Strict subresource routing** — every request is classified into one
  S3 operation from its method, path and query subresource. A recognised
  S3 subresource fs3 does not implement (`?tagging`, `?retention`,
  `?versionId=`, `?website`, …) answers `501 NotImplemented` and never
  reaches the store, so a client that thinks it is setting tags or
  retention cannot overwrite or delete the object by accident.

- **Multipart, round 2** — every part gets a record (MD5, size,
  checksum, CRC64) and Complete verifies the client's ETag list against
  it (`InvalidPart`, `InvalidPartOrder`, `EntityTooSmall` below
  `--mpu-min-part-size`, default 5 MiB). `ListParts` and UploadPartCopy
  (with `x-amz-copy-source-range` and the `x-amz-copy-source-if-*`
  conditionals, also honoured by CopyObject) are implemented.

- **User metadata and standard headers** — `x-amz-meta-*` (≤ 2 KiB,
  name + value bytes, else `MetadataTooLarge`), `Cache-Control`,
  `Content-Disposition`, `Content-Encoding` (minus `aws-chunked`),
  `Content-Language` and `Expires` are stored with the object (PUT and
  multipart) and returned on GET/HEAD. Values with CR, LF, NUL or other
  control bytes are refused, and re-validated when read back.
  CopyObject honours `x-amz-metadata-directive: COPY|REPLACE`; a
  self-copy needs `REPLACE`. `response-*` query overrides work on signed
  and presigned GET/HEAD and answer `400 InvalidRequest` on anonymous
  ones. The website listener serves the caching/encoding headers only.

- **Listing** — ListObjectsV2 (`continuation-token`, `start-after`,
  `fetch-owner`, `KeyCount`), `encoding-type=url` on both list versions,
  and ListMultipartUploads pagination (`key-marker`, `upload-id-marker`,
  `max-uploads`). A delimiter listing never repeats a CommonPrefix
  across pages.

- **Range requests** follow S3 and RFC 9110: one `bytes=` range → 206;
  multi-range requests (`bytes=0-1,5-9`) return the full object with 200,
  as S3 does; an invalid header (unknown unit, last < first) is ignored;
  an unsatisfiable one → 416 with `Content-Range: bytes */size`.

What's *not* yet wired:

- Per-bucket / per-user quotas, background integrity scrub, key expiry /
  disable, SSE-C, seccomp, `FS_IMMUTABLE_FL` for COMPLIANCE versions.
- Tag-based lifecycle filters, transitions, website routing rules (all
  refused with 501 rather than ignored).
- Replication, server-side encryption, STS.

**Upgrading:** the object header (schema 3), version and lock trees are
one-way migrations — an older fs3 cannot read data written by this one.
See `packaging/synology/CHANGELOG.md`.

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
│   ├── test_e2e.sh       21 HTTP integration tests (no auth)
│   ├── test_e2e_auth.sh  28 SigV4 e2e tests (with auth, including chunked)
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
make test           # build and run all tests (~160 tests + 50k fuzz iters)
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

# With SigV4 auth (use real-looking credentials). The optional third field
# is the user that owns the buckets that key creates:
./fs3 --auth AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY:alice \
      --auth AKIAOTHER:secretXXXXXXXXXXXX:bob \
      --admin alice \
      --require-auth -d /var/lib/fs3

# Tune the multipart-upload GC (defaults: 60s sweep, 24h TTL):
./fs3 --mpu-gc-interval 300 --mpu-gc-max-age 3600 -d /var/lib/fs3

# Commit fsync, server-side copy and multipart completion run on worker
# threads so they don't stall other clients (default 4; 0 = inline):
./fs3 --io-threads 2 -d /var/lib/fs3
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

Test dependencies: `pip install -r tests/requirements.txt` (boto3 ≥ 1.36,
`botocore[crt]` for CRC32C/CRC64NVME, AWS CLI) plus `curl` and
`openssl`. `make test` checks for them first (`make check-test-deps`) and
prints the install line instead of failing deep inside a suite. Without
`awscrt`, `test_e2e_checksum.sh` skips the boto3 CRC32C/CRC64NVME cases
and says so in its summary; `FS3_TEST_STRICT=1` turns those skips into
failures (use it in CI).

| target                   | what it covers                                                |
|--------------------------|---------------------------------------------------------------|
| `tests/test_store`       | bucket CRUD, streaming PUT/GET, sendfile, listing, persistence, multipart lifecycle |
| `tests/test_xml`         | XML library: escaping, parsing, security limits, round-trips  |
| `tests/test_xml_legacy`  | original calling style still works                            |
| `tests/test_xml_fuzz`    | 50,000 random byte inputs into `parse_xml`, must not crash    |
| `tests/test_sigv4`       | 34 SigV4 tests: primitives, full verifier against botocore-generated test vectors, body-hash streaming verification |
| `tests/test_e2e.sh`      | 21 HTTP integration tests (auth disabled)                     |
| `tests/test_e2e_auth.sh` | 28 SigV4 integration tests (botocore-signed requests, body-hash mismatch detection, streaming chunked SigV4 with happy path + 4 failure modes) |
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

## Synology deployment

fs3 ships as a Synology SPK (see `packaging/synology/`; build with
`make fs3-static && cd packaging/synology && ./build-spk.sh`). The
package runs fs3 as a dedicated DSM package user and stores its config
in `/var/packages/fs3/var/fs3.conf` (parsed `KEY=value` lines — the file
is data, never sourced as shell). SigV4 credentials live separately in
`/var/packages/fs3/var/credentials` (mode 0600, one
`access_key:secret_key[:user]` per line — the format `--credentials-file`
expects), so the secret never appears in the conf or on the command
line.

With auth on, each user sees only their own buckets. Buckets that
predate per-user isolation are given, at startup, to `FS3_LEGACY_OWNER`
in `fs3.conf` — by default the first user in the credentials file, so
an existing single-user install keeps access to everything after the
upgrade. `FS3_ADMIN=<user>` names a user who can see every bucket. The
DSM tile's credential form has an optional *User* field: to rotate a key
without losing access to your buckets, add the new key with the same user,
then remove the old one (replacing a key's secret keeps its user).

### Native TLS (optional)

The DSM reverse proxy (below) remains the recommended setup. To run fs3
standalone off DSM, build with `make TLS=1` (or `make fs3-tls` for a
separate binary; switching TLS on/off needs `make clean`, like DEBUG)
and start with `--tls-port 9443 --tls-cert chain.pem --tls-key key.pem`.
Plain and TLS listeners can coexist. Policy: TLS 1.2+ only, TLS 1.2
limited to ECDHE + AES-GCM/ChaCha20-Poly1305, groups X25519/P-256/P-384,
no renegotiation, server cipher preference, no session tickets, ALPN
`http/1.1` only. The key file must be mode 0600 and owned by the service
user. SIGHUP re-reads the certificate; a bad file keeps the live one and
existing connections keep theirs. Handshakes are bounded (64 in flight,
`--tls-max-per-ip`, default 32) and stalled handshakes hit
`--idle-timeout`. Bodies go through `SSL_sendfile` when the kernel has
kTLS, otherwise `pread` → `SSL_write` via a 64 KiB buffer — the path
used on the DS1515+ (kernel 3.10). `--require-tls` refuses signed
requests over plain HTTP except from loopback or a trusted proxy that
says https; `--require-signed-payload` refuses `UNSIGNED-PAYLOAD`,
unsigned-trailer and presigned uploads unless the request is over TLS.
Client-certificate (mTLS) authentication is intentionally not offered: a
certificate alone must not grant an S3 identity. The default and SPK
static builds stay libcrypto-only.

### HTTPS via the DSM reverse proxy

fs3 speaks plain HTTP only. SigV4 authenticates requests but does not
encrypt them — credentials in the `Authorization` header and object
payloads travel in the clear. The supported HTTPS setup is to put DSM's
built-in reverse proxy (which manages real certificates, including
Let's Encrypt) in front:

```
client --HTTPS--> DSM nginx (TLS termination) --HTTP--> fs3 on 127.0.0.1:9000
```

The SPK binds fs3 to `127.0.0.1` by default, so the proxy is the only
public face and no plaintext port is exposed. To set it up:

1. DSM Control Panel → Login Portal → Advanced → Reverse Proxy →
   Create.
2. Source: protocol HTTPS, your hostname (e.g. `s3.nas.example.com`),
   port 443 (or a dedicated port). Destination: protocol HTTP, hostname
   `localhost`, port 9000 (or whatever you chose at install).
3. Point clients at `https://s3.nas.example.com` instead of
   `http://NAS-IP:9000`.

**SigV4 host-header caveat:** clients sign the `Host` header they
connect to. The proxy must forward the original `Host` to fs3
(nginx's `proxy_set_header Host $host`), or signature verification
fails with `SignatureDoesNotMatch`. DSM's reverse proxy preserves the
original Host header by default; if signed requests fail through the
proxy but work directly, this is the first thing to check.

To skip the proxy and expose plain HTTP on the LAN instead, either
tick "Expose on the LAN" in the install wizard or set
`FS3_BIND=0.0.0.0` in `fs3.conf` and restart the package. Only do this
on a network where you trust every host.

### Admin API

`/v1` JSON endpoints for scripting keys, buckets and grants (one write
path for the DSM console and your scripts):

| method + path | what |
|---|---|
| `GET /v1/keys` | access keys and their users (never secrets) |
| `POST /v1/keys` `{"user":"bob"}` | new key, generated server-side; the secret is returned once |
| `DELETE /v1/keys/<ak>` | delete a key (the last one is refused) |
| `GET /v1/buckets` | buckets with owner, object count, bytes |
| `GET /v1/buckets/<b>` | plus id, grants, versioning, lock and config flags |
| `PUT /v1/buckets/<b>/owner` `{"owner":"bob"}` | change owner |
| `PUT /v1/buckets/<b>/grants/<user>` `{"perms":"rw"}` / `DELETE` | grants |

Prefer the Unix socket (`--admin-socket /var/run/fs3/admin.sock`: mode
0600, peer uid checked with `SO_PEERCRED`) — every local user and
container on the NAS can reach loopback. On the localhost metrics port
the API needs `Authorization: Bearer <token>` from `--admin-token-file`
(regular file, mode 0600, owned by the service user, else fs3 refuses to
start); requests with an `Origin` header or a non-loopback `Host` are
refused (DNS rebinding / CSRF), and failed tokens back off exponentially.
Key changes rewrite `--credentials-file` atomically and run the same
build-then-swap reload as SIGHUP, so a new key works on the next request
and a deleted one is refused immediately. User names are restricted to
`[A-Za-z0-9._@-]`.

### Audit log, throttling, hardening

- `--audit-log /var/log/fs3/audit.jsonl` appends one JSON line per
  request (time, client, user, access key, S3 action, path, status,
  bytes, duration, presigned/TLS/website flags) and one per admin-API
  change. Query strings are never logged, so presigned signatures and
  credentials stay out of it. The file is created 0600; SIGHUP reopens
  it for rotation.
- `--auth-fail-limit N` (default 20): after N failed authentications from
  one client address within a minute, that address gets `503 SlowDown`
  for an exponentially growing period (2 s … 5 min). Loopback is exempt
  unless `--trusted-proxy` resolves the real client — behind the DSM
  proxy, set `--trusted-proxy 127.0.0.1` for throttling to mean anything.
- Builds use `-fPIE -pie -D_FORTIFY_SOURCE=2 -Wl,-z,relro,-z,now` and
  non-executable stacks; at startup fs3 sets `PR_SET_NO_NEW_PRIVS` and
  disables core dumps (`PR_SET_DUMPABLE=0`) so secrets don't land in
  cores.

### Monitoring

The SPK starts fs3 with an admin listener on `127.0.0.1:9101`
(`FS3_METRICS_PORT` in `fs3.conf`; 0 disables) serving `/healthz` and
Prometheus-format `/metrics` — request counts by method/status, bytes
in/out, request durations, bucket and in-flight-multipart gauges, and
volume used/free. It is localhost-only by design; to scrape it from a
Prometheus host elsewhere on the LAN, add a DSM reverse-proxy entry for
it (same pattern as above) or use an SSH tunnel. The S3 port itself
answers `GET /_health` without credentials for simple liveness checks.

The package runs fs3 under a watchdog: if the process crashes, it is
restarted automatically with exponential backoff (1 s doubling to a
60 s ceiling). Credentials can be rotated without a restart: edit
`/var/packages/fs3/var/credentials` and `kill -HUP` the fs3 process —
a malformed file is rejected and the previous credentials stay active.

### Data folder permissions

By default objects are stored under `/var/packages/fs3/var/data`, which
the package user owns by construction. If you point the data folder at
a shared folder (e.g. `/volume1/fs3-data`), DSM does **not**
automatically grant the package user access: give it write permission
via Control Panel → Shared Folder → Edit → Permissions. The package
probes writability before starting and reports a clear error in the
DSM UI if it can't write, rather than crash-looping.

## What's next

The gap-closure plan is implemented. Candidates for the next round:
`ListParts`/UploadPartCopy, quotas (needed now that versioning, Object
Lock and anonymous access exist), an integrity scrub job, and key
hygiene (expiry, disable without delete, last-used).
