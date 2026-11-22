# fs3

A single-node, S3-compatible object store in C, built for a homelab NAS
(it ships as a Synology package and runs on a DS1515+). Each object is
one self-contained file on a normal filesystem, so data stays readable
and recoverable without fs3. On top of that it implements most of the S3
API that real clients use: SigV4 (header, streaming, trailer and
presigned), multipart, versioning, Object Lock, bucket policies, CORS,
lifecycle, static websites, SSE-C, and checksums.

About 20,000 lines of C. Its only dependency is libcrypto, plus vendored
llhttp and an XML library. Static builds run on DSM 7.1 (glibc 2.26,
kernel 3.10).

> **Maturity.** The feature set below is complete. The test suites pass
> on Linux and on a DS1515+ (DSM 7.1; see
> `docs/AGENT-BUILD-AND-DS1515-TEST.md`). Most of the code is new
> (November 2026), though, and has no long-running production history
> yet. Keep a backup of the data elsewhere, leave the scrub enabled, and
> read the [platform caveats](#platform-caveats).

## Contents

- [Quick start](#quick-start)
- [Features at a glance](#features-at-a-glance)
- [S3 API](#s3-api)
- [Authentication and access control](#authentication-and-access-control)
- [Storage](#storage)
- [Security and hardening](#security-and-hardening)
- [Operations](#operations)
- [Synology deployment](#synology-deployment)
- [Tools](#tools)
- [Platform caveats](#platform-caveats)
- [Upgrading](#upgrading)
- [Build](#build)
- [Tests](#tests)
- [Source layout](#source-layout)
- [Roadmap](#roadmap)

---

## Quick start

```sh
apt-get install -y build-essential libssl-dev   # gcc + libcrypto headers
make                                            # fs3, fs3-lockd, fs3-dedup-estimate
./fs3 -d /tmp/fs3-data                          # 127.0.0.1:9000, no auth
```

With SigV4 authentication (recommended for anything but a quick try):

```sh
cat > creds <<'EOF'
AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY:alice
EOF
chmod 600 creds
./fs3 -d /var/lib/fs3 --credentials-file creds --require-auth --admin alice \
      --metrics-port 9101 --admin-socket /run/fs3/admin.sock \
      --audit-log /var/log/fs3/audit.jsonl
```

Point any S3 client at it. The AWS CLI and boto3 need path-style
addressing (fs3 does not do virtual-hosted buckets on the S3 port):

```ini
# ~/.aws/config
[default]
region = us-east-1
s3 =
    addressing_style = path
```

```sh
aws --endpoint-url http://127.0.0.1:9000 s3 mb s3://photos
aws --endpoint-url http://127.0.0.1:9000 s3 cp big.iso s3://photos/   # multipart above 8 MB
```

On a Synology NAS, install the SPK instead
([Synology deployment](#synology-deployment)).

---

## Features at a glance

| Area | What fs3 does |
|---|---|
| Core S3 | Buckets, objects, CopyObject, DeleteObjects, ListObjects V1/V2, ListAllMyBuckets, Range, conditional requests, user metadata |
| Multipart | Create / UploadPart / UploadPartCopy / ListParts / Complete (ETags verified) / Abort / ListMultipartUploads, GC of stale uploads |
| Integrity | `Content-MD5`, `x-amz-content-sha256`, `x-amz-checksum-{crc32,crc32c,sha1,sha256,crc64nvme}` (header or trailer), payload CRC64 on disk, background scrub |
| Auth | SigV4 header, streaming chunked, trailer variants, presigned URLs; per-user isolation, grants, bucket policies, read-only and expiring keys |
| Data protection | Versioning, Object Lock (GOVERNANCE / COMPLIANCE / legal hold), optional `FS_IMMUTABLE_FL` through a root helper, lifecycle expiry |
| Web | CORS, static website hosting on a separate listener, block-public-access by default |
| Encryption | SSE-C (AES-256-GCM, chunked), native TLS (optional build) |
| Storage efficiency | Reflink fast paths, opt-in whole-object dedup, Btrfs transparent compression |
| Backup tools | restic, rclone, Kopia, Duplicati and AWS CLI v2 tested end to end (plain, TLS, versioning, Object Lock, crash mid-backup): [docs/compatibility.md](docs/compatibility.md) |
| Replication | Asynchronous one-way bucket replication to any S3 endpoint (another fs3, Garage, MinIO, B2, AWS) with a durable queue, backfill and a self-healing scrub |
| Operations | Quotas, admin API (Unix socket), Prometheus metrics, JSON audit log, auth-failure throttling, seccomp, Synology SPK with DSM tile |

Not implemented (all answer `501 NotImplemented`, never silently
ignored): object tagging and tag-based lifecycle filters, lifecycle
transitions, website routing rules, ACLs beyond stubs,
`GetObjectAttributes`, SSE-S3/SSE-KMS, STS, the S3 replication API
(`PutBucketReplication`; fs3 configures replication through its admin
API instead, see [Bucket replication](#bucket-replication)), browser POST
uploads.

---

## S3 API

### Requests and routing

- HTTP/1.1 server: epoll event loop, llhttp parser, pipelined keep-alive,
  chunked transfer encoding, `Expect: 100-continue` answered as soon as a
  request passes auth and routing (botocore sends it on every upload).
  Commit fsyncs, server-side copies and multipart completion run on
  worker threads (`--io-threads`, default 4), so other clients aren't
  stalled.
- **Strict subresource routing.** Each request is classified into exactly
  one S3 operation from its method, path and query. A recognised S3
  subresource that fs3 does not implement (`?tagging`, `?torrent`, …)
  answers `501` and never reaches the store. A client that believes it is
  setting tags therefore cannot overwrite or delete the object by
  accident.
- Bounds: `--max-body-size` (default 5 GiB, 413 above), `--max-conns`
  (default 512), `--idle-timeout` (default 60 s), `--min-free-bytes`
  (refuse uploads below a free-space floor).

### Objects

- Streaming PUT and GET. GET uses `sendfile` (zero copy) for plain objects.
- MD5 ETags; multipart ETags follow AWS (`MD5(part MD5s)-N`).
- CopyObject with `x-amz-metadata-directive: COPY|REPLACE`. A self-copy
  needs `REPLACE`, which is how metadata is edited. The
  `x-amz-copy-source-if-*` conditionals are honoured.
- DeleteObjects (bulk delete) evaluates authorization per key.
- **Range** follows S3 and RFC 9110. A single `bytes=` range gives 206.
  Multi-range requests return the full object with 200, as S3 does. An
  invalid header (unknown unit, last < first) is ignored. An
  unsatisfiable range gives 416 with `Content-Range: bytes */size`.
- **User metadata and standard headers:** `x-amz-meta-*` (at most 2 KiB
  of names plus values, else `MetadataTooLarge`), `Cache-Control`,
  `Content-Disposition`, `Content-Encoding` (minus `aws-chunked`),
  `Content-Language` and `Expires` are stored with the object and returned
  on GET/HEAD. Values containing CR, LF, NUL or other control bytes are
  refused on write and re-validated on read. `response-*` overrides work
  on signed and presigned GET/HEAD and answer `400` on anonymous requests.

### Multipart upload

- Parts can arrive in any order and concurrently. Each part gets a record
  (MD5, size, checksum, CRC64).
- Complete verifies the client's ETag list against those records:
  `InvalidPart` on a mismatch, `InvalidPartOrder` for out-of-order parts,
  and `EntityTooSmall` for any non-final part below `--mpu-min-part-size`
  (default 5 MiB). The final ETag is built from the stored MD5s, never
  from the request.
- `ListParts` and UploadPartCopy (`x-amz-copy-source-range` plus the copy
  conditionals) are supported.
- On Btrfs/XFS, Complete clones part extents instead of copying them
  (see [Reflink](#reflink-dedup-compression)).
- Stale uploads are garbage-collected: every `--mpu-gc-interval` seconds
  (default 60), uploads older than `--mpu-gc-max-age` (default 24 h) are
  removed. A bucket lifecycle `AbortIncompleteMultipartUpload` rule
  overrides that age for the keys it covers. The sweep is conservative:
  uploads with an unreadable `meta` file are left alone.

### Listing

- ListObjects V1 (`marker`) and V2 (`continuation-token`, `start-after`,
  `fetch-owner`, `KeyCount`), `prefix`/`delimiter` roll-up,
  `encoding-type=url`. A CommonPrefix is never repeated across pages.
- ListMultipartUploads with `key-marker`, `upload-id-marker` and
  `max-uploads`.
- ListObjectVersions (`?versions`) with `key-marker` and
  `version-id-marker`.
- `GET /` (ListAllMyBuckets) lists the caller's own and granted buckets.
  Admins see all.

### Checksums and body integrity

- `x-amz-content-sha256` (header mode) is streamed and compared at
  end-of-body. On mismatch the upload is aborted with nothing written
  (`XAmzContentSHA256Mismatch`).
- `x-amz-checksum-{crc32,crc32c,sha1,sha256,crc64nvme}` and `Content-MD5`
  are verified over the decoded body, whether sent as a header or a
  trailer. A mismatch gives `400 BadDigest` and nothing on disk. The
  checksum is stored, echoed on PUT, and returned on GET/HEAD with
  `x-amz-checksum-mode: ENABLED` (never on ranged GETs).
- Multipart uploads created with `x-amz-checksum-algorithm` verify every
  part and store a COMPOSITE (`base64(algo(part digests))-N`) or
  FULL_OBJECT checksum. CRC64NVME is always full-object.
- CRCs are table-driven, with no zlib. CRC32C uses SSE4.2 when the CPU
  has it.

### Versioning

- `PUT/GET ?versioning`: Enabled or Suspended, never back to Unset. MFA
  delete answers 501.
- The current version stays at `data/…`, so unversioned GETs and listings
  cost the same as before. Superseded versions move to
  `versions/<b>/xx/yy/<hex>/<inv_ts>-<vid>` (newest first in directory
  order) through a hard link made under the key's stripe lock. If a crash
  leaves a duplicate link, startup recovery removes it.
- DELETE writes a delete marker. `versionId` works on GET/HEAD/DELETE,
  copy sources and bulk delete. Deleting the current version promotes the
  newest noncurrent one, and deleting a marker undeletes the object.
  Suspended buckets read and write the single `null` version. Every
  mutating response carries `x-amz-version-id`.
- Version ids are validated (32 hex characters or `null`) before any path
  is built. A bucket can be deleted only when no current object,
  noncurrent version or marker remains.

### Object Lock

- Enabled only at bucket creation (`x-amz-bucket-object-lock-enabled:
  true`), which pins versioning to Enabled. `?object-lock` sets a default
  retention (mode plus Days or Years).
- Per-version retention and legal hold (`?retention`, `?legal-hold`, the
  `x-amz-object-lock-*` PUT headers, which require Content-MD5 or an
  `x-amz-checksum-*`) live in sidecars under `locks/`. Retention can
  therefore be extended without rewriting data.
- Enforcement is in the store. No path (S3 API, lifecycle or admin API)
  can permanently delete a version under legal hold or unexpired
  retention.
  - COMPLIANCE retention can only be extended.
  - GOVERNANCE retention can be shortened, removed or bypassed by an admin
    with `x-amz-bypass-governance-retention: true`.
  - Overwriting or deleting the current key without a version id still
    works: it adds a version or a marker.
- Setting retention requires the owner or `o` permission. It is capped by
  `--max-retention-days` (default 3650), so writers can't fill the volume
  with undeletable data. Locked versions count toward quotas.
- A missing lock record falls back to the bucket default. An unreadable
  one fails closed.
- Retention trusts the system clock; a backwards jump of more than an
  hour is logged.
- By default this is API-level WORM. For filesystem-level immutability,
  see [Immutable locks](#immutable-locks-fs3-lockd).

### Lifecycle

- `PUT/GET/DELETE ?lifecycle`. Supported rules: `Filter/Prefix` (also
  `And/Prefix` and the legacy `Rule/Prefix`), `Expiration/Days|Date`,
  `AbortIncompleteMultipartUpload`, `NoncurrentVersionExpiration` and
  `ExpiredObjectDeleteMarker`. Transitions and tag or size filters are
  refused with `501`.
- The sweeper runs on a worker thread once a day at `--lifecycle-hour`
  (default 03:00 local; `--lifecycle-now` adds a run at startup).
  `--lifecycle-rate` caps deletions (default 100 per second).
- Each deletion is guarded: the object's header is re-read under its
  stripe lock, and the object is left alone if a PUT replaced it
  mid-sweep. Object Lock vetoes deletions.
- `--lifecycle-dry-run` logs what would be deleted and deletes nothing. A
  rule whose `Expiration/Date` has already passed needs the header
  `x-fs3-confirm-immediate-expiry: true`, because it would delete
  everything it matches at the next sweep.

### CORS

- `PUT/GET/DELETE ?cors` with a validated `CORSConfiguration`: at most
  100 rules, at most one `*` per origin, methods GET/PUT/POST/DELETE/HEAD.
- Preflight `OPTIONS` requests are answered without SigV4. They are served
  from a 1-second cache, so they cost no disk I/O, and a missing bucket
  answers exactly like a bucket with no matching rule.
- Matching requests, including error responses, get
  `Access-Control-Allow-Origin`, `-Methods`, `-Expose-Headers` and
  `Vary: Origin`. `Access-Control-Allow-Credentials` is never sent.
  `x-amz-meta-*` headers are visible to browsers only if listed in
  `ExposeHeader`.

### Static website hosting

- `PUT/GET/DELETE ?website` with `IndexDocument`, `ErrorDocument` or
  `RedirectAllRequestsTo`. `RoutingRules` answers 501.
- A website config makes a bucket anonymously readable **only on a
  dedicated listener** (`--web-port 9080 --web-addr 127.0.0.1
  --web-root-domain web.example.lan`), as Garage does. The S3 port's auth
  model is untouched.
- The bucket comes from `Host`: either `<bucket>.<root-domain>`, or a Host
  equal to a bucket name (custom domains through a reverse proxy).
- Only GET and HEAD are served.
  - Directory paths get the index document appended.
  - `dir` without a trailing slash redirects (302) to `dir/` when
    `dir/<index>` exists, with a normalised `Location` (no open redirect).
  - Misses serve the ErrorDocument with status 404.
  - Range and sendfile work as on the S3 port.
  - Authorization headers are ignored, subresource and `X-Amz-*` queries
    are refused, listings are never served, errors are HTML, and SSE-C
    objects are never served.
- Website configs are refused unless fs3 runs with `--allow-public`.

---

## Authentication and access control

### SigV4

- Header-mode SigV4, matching botocore byte for byte (tested against
  botocore-generated vectors). Signatures are compared in constant time.
  Clock skew is allowed up to ±15 minutes.
- **Streaming chunked** (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`, the AWS CLI
  default). Each chunk is verified against the chained signature before
  its bytes reach the store, and any failure aborts the upload before
  commit. The decoder handles arbitrarily split feeds.
- **Trailer variants** (`STREAMING-UNSIGNED-PAYLOAD-TRAILER` and the
  signed `…-HMAC-SHA256-PAYLOAD-TRAILER`, whose trailer signature is
  verified). AWS SDKs send these by default since early 2025 (boto3 ≥
  1.36, JS v3, Java v2, Go v2).
  - Decoder bounds: 16 hex digits per chunk size, 256-byte trailer lines,
    at most 4 trailers, and only names announced in `x-amz-trailer`.
  - With auth off, aws-chunked bodies are still de-framed, so chunk
    headers never end up in the object.
- **Presigned URLs** (query-string SigV4), as produced by
  `generate_presigned_url` and `aws s3 presign`.
  - Lifetime is capped by `--presign-max-expires` (default 24 h; AWS's
    7-day ceiling always applies).
  - `--no-presign-admin` stops admin identities from minting bearer URLs.
  - A presigned URL never grants more than its signer has, dies with its
    key, and cannot be signed to outlive the key.
- **Hardening.** `host` and every `x-amz-*` header must be signed. The
  credential scope must be service `s3` with the date of `X-Amz-Date`.
  Duplicate `Authorization` headers or auth query parameters are
  rejected. SSE-C headers must be signed.

### Credentials and keys

- Credentials come from `--auth ak:sk[:user]` (repeatable) or
  `--credentials-file`, one line each:
  `access_key:secret_key[:user[:attributes]]`. The user owns the buckets
  created with that key; it defaults to the access key. Several keys can
  share a user, so a rotated key keeps the user's buckets.
- SIGHUP re-reads the file with a build-then-swap reload. A malformed file
  is rejected and the live keys stay active.
- **Attributes** (optional fourth field, strict: an unknown attribute
  refuses the whole file):
  `AKIA…:secret:alice:created=1763107200,expires=1794643200,ro,disabled`.
  - A disabled or expired key gets exactly the answer an unknown key gets,
    after the same HMAC work. The audit log records the real reason.
  - `ro` keys can read and list, including bucket config, but never write,
    delete, create buckets or change config, even for an admin user.
  - Last-used times are kept in `<data>/keys.state`, never in the
    credentials file.
- User names written by fs3 are restricted to `[A-Za-z0-9._@-]`.

### Isolation, grants and admins

- With auth configured, a bucket belongs to the user who created it. Only
  that user, a grantee or an `--admin` can use it; everyone else gets
  `403`. Bucket names stay global: creating a name someone else owns
  gives `409 BucketAlreadyExists`.
- `--require-auth` refuses unsigned requests. Without it, anonymous
  requests own nothing and reach data only through a public bucket
  policy.
- Buckets created before isolation existed, or with auth off, have no
  owner and are admin-only until `--legacy-owner <user>` assigns them at
  startup.
- **Grants** (Garage-style), in `buckets/<b>/grants`, one `user:perms`
  line each, with perms ⊆ `rwo`:
  - `r` lists and reads;
  - `w` writes, deletes and runs multipart uploads;
  - `o` reads and changes bucket configuration.

  Deleting the bucket stays owner/admin-only. Edits take effect on the
  next request, and deleting and re-creating a bucket drops its grants.
  Manage grants through the admin API.

### Bucket policies

- `PUT/GET/DELETE ?policy` (owner or admin only, at most 20 KB). fs3
  accepts a strict IAM JSON subset:
  - `Version` must be `2012-10-17`;
  - each statement has `Effect`, `Principal` (`"*"` or `{"AWS": …}`),
    `Action`/`NotAction` (`s3:*` patterns), and a `Resource` naming
    *this* bucket or a prefix in it;
  - `Condition` supports `StringEquals`, `StringNotEquals`, `StringLike`,
    `IpAddress`, `NotIpAddress` and `Bool`, on the keys `aws:SourceIp`,
    `aws:SecureTransport`, `s3:prefix` and `aws:username`.

  Anything else (`NotPrincipal`, unknown keys, duplicate JSON keys, other
  buckets) gives `400 MalformedPolicy`.
- Evaluation order:
  1. An explicit Deny wins, even for the owner and admins.
  2. Otherwise owner, admin, grant or a matching Allow lets the request
     through.
  3. Otherwise it is denied.

  The owner and admins can always read, replace or delete the policy, so
  a policy can't lock them out.
- **Block public access is on by default.** Policies with `Principal "*"`
  need `--allow-public`, and public *write* additionally needs
  `--allow-public-write`.
- `aws:SourceIp` and `aws:SecureTransport` come from the connection. They
  come from `X-Forwarded-For`/`-Proto` only when the peer is listed in
  `--trusted-proxy`. Behind the DSM proxy every peer is 127.0.0.1, and any
  local process can forge those headers, so treat `aws:SourceIp` as
  advisory there.

---

## Storage

### On-disk layout

```
<root>/
  buckets/<b>/meta            id=, owner=, versioning, object lock, layout
  buckets/<b>/{grants,policy.json,cors.xml,lifecycle.xml,website.xml,quota,usage}
  data/<b>/xx/yy/<sha256(b\0key)>          current object (or a layout-2 symlink)
  versions/<b>/xx/yy/<hex>/<inv_ts>-<vid>  noncurrent versions and markers
  locks/<b>/…                 Object Lock retention / legal-hold records
  mpu/<b>/<upload_id>/        meta + part-NNNNN + part-NNNNN.rec
  cas/<scope>/aa/bb/<sha256>  whole-object dedup pool (payload-only, optional)
  users/<hex(user)>.quota     per-user quota (file name is the hex-encoded user)
  scrub/                      scrub cursor (state), corrupt.log
  tmp/                        staging for atomic writes
  keys.state                  last-used time per access key
  .fs3-running                marker: present while running; tells startup whether to rebuild quota usage
```

- **Object file:** `[header][extensions][content-type][key][TLV metadata][padding][payload]`.
  The header carries size, mtime, ETag, checksum, version id, flags and a
  CRC64 of the payload as stored. On reflink-capable filesystems it is
  padded to 4 KiB, so payloads are block-aligned and can share extents.
  The current schema is 4. Schemas 2 and 3 are still read.
- **Durability:** every write goes tmp file → fsync → rename →
  fsync(parent). Committed object files are never modified in place.
  Readers always see one complete version, and the last writer wins.
- **Recovery:** each object file is self-describing (bucket, key, content
  type, metadata), so a small script can rebuild a bucket from `data/`
  and `versions/` without fs3. Startup recovery removes leftover temp
  files and duplicate version links.

### Quotas

- Hard limits on logical bytes and object count, per bucket and per user
  (summed over the buckets the user owns). Current objects, noncurrent
  versions, delete markers and in-flight multipart parts all count. They
  are charged to the bucket owner, whoever wrote them.
- Set quotas through the admin API (`/v1/buckets/<b>/quota`,
  `/v1/users/<u>/quota`, body `{"max_bytes":N,"max_objects":N}`, 0 =
  unlimited) or with the defaults `--default-bucket-quota` and
  `--default-user-quota`.
- A write that would cross a limit is refused with `403 QuotaExceeded`
  before any byte is stored. The check uses the declared length, or the
  running size as a chunked body streams in. An overwrite is checked
  against its full size.
- Lowering a quota below current usage blocks writes and never deletes
  data. Usage is kept in memory, saved at clean shutdown, rebuilt from
  disk after a crash, and reconciled by each scrub pass.

### Integrity scrub

- A background pass re-reads every object, noncurrent version and
  in-flight part. Each is checked against its payload CRC64, else its MD5
  ETag, else a stored full-object checksum. Multipart objects written
  before schema 4 count as "unverifiable". Lock records are checked for
  parseability.
- Runs every `--scrub-interval-days` (default 30), with `--scrub-now`, or
  through `POST /v1/scrub`.
- It is gentle on the NAS:
  - it runs on a worker thread at idle I/O priority;
  - reads are throttled by `--scrub-rate` (default 20 MiB/s) and back off
    while requests are queued;
  - what it reads is dropped from the page cache;
  - after a restart it resumes where it stopped.
- Corruption is never deleted. It goes to `scrub/corrupt.log`, the audit
  log and `fs3_scrub_corrupt_total`. If the bucket replicates, the current
  object is fetched back from the replica and swapped in, but only when
  those bytes verify against the local header (see
  [Bucket replication](#bucket-replication)); otherwise it stays as found. With
  `--scrub-fail-reads`, a GET of a corrupt version answers 500 instead of
  returning bad bytes.
- On a Btrfs volume with data checksums, DSM's own data scrubbing covers
  the same failures and can repair from RAID parity, where fs3 can only
  detect. fs3's scrub matters on ext4 and for logical damage (truncated
  files, bad headers).

### Reflink, dedup, compression

- **Reflink fast paths** (Btrfs/XFS; probed at startup, `--reflink off`
  to disable).
  - Multipart Complete clones each part's extents instead of copying them,
    so it needs no double disk space; the ETag and CRC come from the part
    records.
  - CopyObject and UploadPartCopy clone when both payloads are
    block-aligned. Anything misaligned falls back to a copy.
- **Whole-object dedup** (opt-in, needs reflink): `--dedup owner|global`.
  - PUT bodies are hashed with SHA-256, and identical objects of at least
    `--dedup-min-size` (default 1 MiB) share extents through `cas/`.
  - Every object file stays complete. Wiping `cas/` only loses future
    dedup, never data, and there are no refcounts to repair. The scrub
    removes pool entries nothing references.
  - `owner` scope is the safe default. `global` lets one user confirm that
    another stores a given file, so use it only on single-tenant installs.
  - Quotas still charge logical bytes. `--dedup-verify` byte-compares
    before sharing.
  - Block-level dedup is on the roadmap; measure first with
    [`fs3-dedup-estimate`](#fs3-dedup-estimate).
- **Filesystem compression:** `--fs-compress auto|all` sets Btrfs's
  `FS_COMPR_FL` on each new object file, so the filesystem compresses
  extents transparently. sendfile, Range, reflinks and the on-disk format
  are unaffected.
  - `auto` skips already-compressed types (images, video, audio, archives,
    PDF) and objects under 4 KiB.
  - On ext4, or a Btrfs that refuses the flag, fs3 logs a warning and
    stores data uncompressed.
  - Btrfs reports uncompressed sizes to `du`; use `compsize` to see the
    savings. On DSM, the shared folder's own compression setting may be
    simpler.
  - Don't combine with `--dedup` on DSM 7.1 (see
    [Platform caveats](#platform-caveats)).

### Immutable locks (fs3-lockd)

- Buckets created with Object Lock use **layout 2**. Every version,
  including the current one, is a file in `versions/`, and `data/…/<hex>`
  is a relative symlink to the current version, re-pointed atomically.
  No write ever links or renames a locked inode. A read follows such a
  link only if it points into that key's own version directory.
- With `--lock-immutable --lockd-socket PATH`, COMPLIANCE and legal-hold
  versions are made `FS_IMMUTABLE_FL` by **`fs3-lockd`**. It is a small
  root-run helper and the only holder of `CAP_LINUX_IMMUTABLE`; fs3
  itself runs without it.
- The helper:
  - keeps its own root-only, append-only journal (inode → retain-until,
    hold);
  - only ever extends retention;
  - releases a hold only on an explicit `HOLD_OFF`;
  - refuses to clear the flag early, whatever fs3 asks.

  Other share users, fs3 bugs and a compromised fs3 therefore can't delete
  such a version. GOVERNANCE versions stay bypassable and are not made
  immutable.
- fs3 refuses to start with `--lock-immutable` if the helper is
  unreachable or the filesystem refuses the flag. Root can still clear
  the flag, and retention still trusts the clock. Object Lock buckets
  created before layout 2 keep API-level WORM.
- Start the helper as root:
  `fs3-lockd --root <data dir> --socket <path> --journal <file> [--peer-uid <fs3 uid>]`.
  On DSM, see the SPK notes.

---

## Security and hardening

### Native TLS (optional)

The DSM reverse proxy is the recommended way to get HTTPS
([below](#https-via-the-dsm-reverse-proxy)). To run fs3 standalone, build
with `make TLS=1` (or `make fs3-tls` for a separate binary) and start it
with `--tls-port 9443 --tls-cert chain.pem --tls-key key.pem`. Plain and
TLS listeners can run together.

- Policy:
  - TLS 1.2 or later; TLS 1.2 limited to ECDHE with AES-GCM or
    ChaCha20-Poly1305;
  - groups X25519, P-256 and P-384;
  - no renegotiation and no session tickets, server cipher preference;
  - ALPN `http/1.1` only.
- The key file must be mode 0600 and owned by the service user. SIGHUP
  re-reads the certificate; a bad file keeps the live one.
- Handshakes are bounded: 64 in flight, `--tls-max-per-ip` (default 32),
  and stalled handshakes hit `--idle-timeout`.
- Bodies go through `SSL_sendfile` when the kernel has kTLS. Otherwise
  they are read and written through a 64 KiB buffer; that is the path on
  the DS1515+ (kernel 3.10).
- Related options:
  - `--require-tls` refuses signed requests over plain HTTP, except from
    loopback or a trusted proxy that says https.
  - `--require-signed-payload` refuses unsigned payloads, unsigned
    trailers and presigned uploads unless the request arrived over TLS.
- Client certificates (mTLS) are intentionally not supported: a
  certificate alone must not grant an S3 identity.

### SSE-C

- `x-amz-server-side-encryption-customer-*` works on PUT, GET, HEAD,
  CreateMultipartUpload, UploadPart, CopyObject and UploadPartCopy. The
  copy-source variants support re-keying and decrypt-on-copy.
- Accepted only over native TLS, or through a trusted proxy that says
  https (`400 InvalidRequest` otherwise). The three headers must be
  signed.
- The key is never stored:
  - each object gets a random salt, and
    `k_obj = HKDF-SHA256(key, salt, "fs3-ssec-v1")`;
  - the payload is sealed in 64 KiB AES-256-GCM segments (nonce = part
    number ‖ segment index, AAD = bucket id ‖ final flag);
  - ranges decrypt only the segments they touch, and truncation,
    reordering or splicing fail authentication.
- A wrong key is refused (`403`) before any data is read, using a key
  check value (an HMAC, not the key's MD5). A missing key gives `400`.
- ETags are MD5s of the ciphertext. Client checksums are verified over
  the plaintext but not stored.
- SSE-C objects are never deduplicated, compressed or served on the
  website listener. The scrub verifies their ciphertext without the key.

### Logs, audit log and throttling

- **Server log:** stderr by default. `--log-file <file>` writes it to a
  file instead (mode 0640).
  - Each line is formatted in full and written with one `write()`, so lines
    from worker threads never interleave or tear. A newline inside a
    message (for example from a client-supplied string) is replaced by a
    space, so it can't forge another log line.
- **Rotation** applies to both the log file and the audit log:
  - when a file reaches `--log-max-size` (default 10M; 0 = never), it
    becomes `<file>.1`, older ones shift up, and `--log-keep` of them are
    kept (default 5, max 50);
  - if a rotation fails (disk full, permissions), fs3 keeps writing to the
    current file and retries at most once a minute;
  - SIGHUP re-opens both files, so external rotation tools still work.

- `--audit-log <file>` appends one JSON line per request (time, client,
  user, access key, S3 action, path, status, bytes, duration, and
  presigned/TLS/website/SSE-C flags) and one per admin-API change.
  - Query strings and key material are never logged, so presigned
    signatures stay out of it.
  - The file is created with mode 0600 and rotated as above.
- `--auth-fail-limit N` (default 20): after N failed authentications from
  one client address within a minute, that address gets `503 SlowDown`
  for an exponentially growing period (2 s up to 5 min).
  - Loopback is exempt unless `--trusted-proxy` resolves the real client.
    Behind the DSM proxy, set `--trusted-proxy 127.0.0.1`, or throttling
    does nothing.

### Process hardening

- Built with `-fPIE -pie -D_FORTIFY_SOURCE=2 -fstack-protector-strong
  -Wl,-z,relro,-z,now` and a non-executable stack.
- At startup fs3 sets `PR_SET_NO_NEW_PRIVS` and disables core dumps
  (`PR_SET_DUMPABLE=0`), so secrets can't land in a core file.
- Every response carries `X-Content-Type-Options: nosniff`. Anonymous or
  presigned GETs carry `Content-Security-Policy: sandbox`. Serve fs3 on
  its own hostname, never on the DSM hostname with another port: cookies
  are not port-scoped.
- **seccomp:** once startup has finished (listeners bound, TLS and
  credentials loaded, store recovered, logs open) and before the worker
  threads exist, fs3 installs a hand-written seccomp-BPF allowlist that
  every thread inherits. No libseccomp is needed, and it works without
  TSYNC.
  - `clone` is allowed for threads only, `socket` for
    AF_UNIX/INET/INET6, and `ioctl` for the request numbers fs3 uses.
    `execve`, `fork`, `ptrace` and everything else kill the process.
  - `--seccomp off|log|enforce|require`, default `enforce`. `log` prints
    the blocked syscall number and exits with 159. `require` refuses to
    start without seccomp.
  - `make seccomp-profile` runs the e2e suites under `strace -f` and diffs
    the syscalls used against the compiled-in table (`fs3
    --seccomp-list`). Sanitizer builds compile the filter out.
  - **Not active on the DS1515+**; see
    [Platform caveats](#platform-caveats).

---

## Operations

### Admin API

`/v1` JSON endpoints, used by the DSM console and by scripts:

| method + path | what |
|---|---|
| `GET /v1/keys` | access keys with user, `created`, `expires`, `disabled`, `read_only`, `last_used` (never secrets) |
| `POST /v1/keys` `{"user":"bob","expires":N,"read_only":true}` | new key generated server-side; the secret is returned once (default expiry `--key-max-age-days`) |
| `PATCH /v1/keys/<ak>` `{"disabled":…,"read_only":…,"expires":…}` | change key attributes; takes effect on the next request |
| `DELETE /v1/keys/<ak>` | delete a key (the last one is refused) |
| `GET /v1/buckets`, `GET /v1/buckets/<b>` | owner, objects, bytes, quota; plus id, grants, versioning, lock and config flags |
| `PUT /v1/buckets/<b>/owner` `{"owner":"bob"}` | change owner |
| `PUT /v1/buckets/<b>/grants/<user>` `{"perms":"rw"}`, `DELETE` | grants |
| `GET/PUT/DELETE /v1/buckets/<b>/quota`, `/v1/users/<u>/quota` | quotas |
| `POST /v1/scrub`, `GET /v1/scrub` | start a scrub pass; progress and last result |
| `GET/PUT/DELETE /v1/buckets/<b>/replication` | replication rule (the secret is never returned) |
| `POST /v1/buckets/<b>/replication/sync`, `GET …/status` | backfill existing objects; queue, lag, counters, recent errors |

- **Prefer the Unix socket** (`--admin-socket PATH`). It is mode 0600 and
  the peer uid is checked with `SO_PEERCRED`; every local user and
  container on the NAS can reach loopback.
- The API is also served on the localhost metrics port, where it needs
  `Authorization: Bearer <token>` from `--admin-token-file`. The token file
  must be a regular file, mode 0600, owned by the service user, or fs3
  refuses to start. Requests with an `Origin` header or a non-loopback
  `Host` are refused (DNS rebinding, CSRF), and failed tokens back off
  exponentially.
- Key changes rewrite the credentials file atomically and reload it like
  SIGHUP does.

### Bucket replication

A bucket's changes can be copied, asynchronously and one way, to a bucket
on another S3 endpoint: a second fs3, Garage, MinIO, Backblaze B2, AWS
S3. fs3 stays single-node; the replica is its off-site copy.

```sh
curl --unix-socket /path/admin.sock -X PUT http://x/v1/buckets/photos/replication \
  --data '{"endpoint":"https://s3.eu-central-003.backblazeb2.com",
           "region":"eu-central-003","bucket":"nas-photos",
           "access_key":"…","secret_key":"…","deletes":false}'
curl --unix-socket /path/admin.sock -X POST http://x/v1/buckets/photos/replication/sync
curl --unix-socket /path/admin.sock http://x/v1/buckets/photos/replication/status
```

- **What is replicated:** the current state of each key. PUT, multipart
  completion, CopyObject, deletes (including delete markers and lifecycle
  expiry), content type, user metadata and the standard headers. Not
  replicated: version history, Object Lock settings, bucket configuration
  (policy, CORS, lifecycle). SSE-C objects are skipped and counted (fs3
  doesn't have the key).
- **Rule fields:** `endpoint` (`https://host[:port]`, no path), `bucket`,
  `access_key`, `secret_key`, and optionally `region` (default
  `us-east-1`), `prefix` (only keys under it), `addressing`
  (`path`, the default, or `virtual`), `deletes` (default `true`; `false`
  is the usual choice for a backup target), `storage_class`,
  `verify_tls` (default `true`) and `allow_plain_http`.
  - `http://` endpoints are accepted only for loopback and private
    addresses, and only with `"allow_plain_http": true`.
    `"verify_tls": false` is likewise limited to private addresses.
  - https needs a TLS build (`fs3 --build-info` shows `tls=yes`; the
    Synology package is one). Certificates are checked against the system
    CA bundle plus `--repl-ca-file`, and the host name or IP must match.
  - The rule is stored in `buckets/<b>/replication.json` (mode 0600). The
    secret is never returned by the API, logged or audited. A `PUT` that
    omits `secret_key` but keeps the same access key keeps the stored
    secret.
- **Durable queue:** every change appends a record to
  `repl/<bucket-id>/queue` while the key's lock is held, so records for
  one key are in commit order. Records are fdatasync'd in groups every
  10 ms. A record only says which key changed: the worker uploads the
  key's current local state, or deletes it remotely if it is gone, so a
  duplicated record costs an upload and a lost one only delays. After an
  unclean shutdown (no `clean` marker), a recovery scan re-queues every
  object newer than the queue's high-water mark.
- **Workers:** `--repl-workers` threads (default 2; 0 turns replication
  off) take one bucket at a time. They coalesce repeated changes to a key
  within a batch, so a burst of overwrites uploads once, and send over one
  keep-alive connection. Uploads are throttled by `--repl-rate` (default
  20 MiB/s across buckets). Objects larger than four `--repl-part-size`
  parts (default 16 MiB) go as multipart uploads, with per-part retries.
  Single-part objects carry `Content-MD5`, so the replica verifies them,
  and every object carries `x-amz-meta-fs3-source-etag` so backfills and
  the scrub can compare multipart objects.
- **Errors:** 5xx, timeouts, network errors and rule-level 4xx (bad
  credentials, missing remote bucket, clock skew, redirects) keep the
  record and back off from 1 s, doubling up to 10 minutes. Other 4xx
  (a remote quota, a policy denial) are permanent for that object: it is
  logged, audited, kept in the status's error ring and skipped.
- **Backfill:** `POST …/replication/sync` walks the bucket, `HEAD`s each
  key on the replica and queues what is missing or different. A new rule
  doesn't copy existing objects until you ask. An interrupted backfill
  starts over at the next start.
- **Self-healing scrub:** when the scrub finds a corrupt current object
  in a replicated bucket, fs3 fetches the key from the replica, checks it
  against the local header (payload CRC64, MD5 or a full-object
  checksum), and swaps it in under the key's lock if the object wasn't
  replaced meanwhile. A replica copy that doesn't verify is refused.
  Outcomes go to `scrub/corrupt.log`, the audit log and
  `fs3_scrub_repaired_total`. Object Lock buckets (layout 2), SSE-C and
  compressed objects are reported but not repaired.
- **Interactions:** lifecycle expirations are deletes and replicate
  unless `deletes` is false. Locked versions are never deleted locally, so
  never remotely. Quotas, dedup and reflink are unaffected (replication
  reads logical bytes).

### Metrics and health

`--metrics-port N` serves `/healthz` and Prometheus `/metrics` on
127.0.0.1. The S3 port answers `GET /_health` without credentials. Main
series:

| group | metrics |
|---|---|
| traffic | `fs3_requests_total`, `fs3_request_duration_seconds`, `fs3_bytes_in_total`, `fs3_bytes_out_total`, `fs3_errors_total{error}` |
| capacity | `fs3_buckets_total`, `fs3_mpu_inflight`, `fs3_storage_used_bytes`, `fs3_storage_free_bytes`, `fs3_bucket_bytes`, `fs3_bucket_quota_bytes`, `fs3_quota_rejections_total` |
| background | `fs3_lifecycle_{expired,aborted_mpu,runs}_total`, `fs3_scrub_{objects,bytes,unverifiable,corrupt,repaired}_total`, `fs3_scrub_last_success_timestamp` |
| replication | `fs3_repl_queue_depth{bucket}`, `fs3_repl_lag_seconds{bucket}`, `fs3_repl_bytes_total{bucket}`, `fs3_repl_ops_total{bucket,op,result}`, `fs3_repl_errors_total{bucket}` |
| storage efficiency | `fs3_reflink_clones_total`, `fs3_dedup_hits_total`, `fs3_dedup_pool_adds_total` |
| keys | `fs3_keys_expiring_soon`, `fs3_keys_unused_90d` |

### Command-line reference

`./fs3 --help` is authoritative. Main groups:

| group | options |
|---|---|
| listen | `-a/--addr`, `-p/--port`, `-d/--data`, `--max-conns`, `--idle-timeout`, `--max-body-size`, `--io-threads`, `-v` |
| auth | `--auth`, `--credentials-file`, `--require-auth`, `--admin`, `--legacy-owner`, `--key-max-age-days`, `--presign-max-expires`, `--no-presign-admin`, `--auth-fail-limit`, `--trusted-proxy` |
| public access | `--allow-public`, `--allow-public-write` |
| TLS | `--tls-port`, `--tls-addr`, `--tls-cert`, `--tls-key`, `--tls-max-per-ip`, `--require-tls`, `--require-signed-payload` |
| website | `--web-port`, `--web-addr`, `--web-root-domain` |
| capacity | `--min-free-bytes`, `--default-bucket-quota`, `--default-user-quota` |
| multipart | `--mpu-min-part-size`, `--mpu-gc-interval`, `--mpu-gc-max-age` |
| lifecycle | `--lifecycle-hour`, `--lifecycle-now`, `--lifecycle-rate`, `--lifecycle-dry-run` |
| Object Lock | `--max-retention-days`, `--lock-immutable`, `--lockd-socket` |
| storage efficiency | `--reflink`, `--dedup`, `--dedup-min-size`, `--dedup-verify`, `--fs-compress` |
| scrub | `--scrub-interval-days`, `--scrub-now`, `--scrub-rate`, `--scrub-fail-reads` |
| replication | `--repl-workers`, `--repl-rate`, `--repl-ca-file`, `--repl-part-size`, `--repl-timeout` |
| operations | `--metrics-port`, `--admin-socket`, `--admin-token-file`, `--audit-log`, `--log-file`, `--log-max-size`, `--log-keep`, `--seccomp`, `--seccomp-list`, `--build-info` |

Size options accept K/M/G suffixes. SIGHUP re-reads credentials, TLS
certificates and the audit log file.

---

## Synology deployment

Build the package with
`make fs3-tls-static fs3-lockd-static && cd packaging/synology && ./build-spk.sh`.
The package ships the static **TLS** build (libssl and libcrypto linked
in), so replication can reach HTTPS targets; `build-spk.sh` refuses a
non-TLS binary unless `FS3_SPK_ALLOW_NO_TLS=1`.
`docs/AGENT-BUILD-AND-DS1515-TEST.md` is the step-by-step build and test
runbook for a DS1515+, including a recorded run.

- The package runs fs3 as a dedicated, unprivileged DSM package user,
  under a watchdog that restarts it with exponential backoff (1 s, doubling
  to 60 s).
- Config lives in `/var/packages/fs3/var/fs3.conf`, as `KEY=value` lines
  that are parsed, never sourced as shell. Credentials are kept separately
  in `/var/packages/fs3/var/credentials` (mode 0600), so secrets never
  appear in the conf file or on the command line.
- The DSM tile (open it from the DSM main menu) is for DSM
  administrators only. It checks your DSM session with DSM's
  `authenticate.cgi` and membership of the `administrators` group on every
  request; everyone else gets a 403 with nothing in it. It shows buckets
  (objects, size, quota usage), manages credentials and replication rules,
  and edits the server settings.
- **Credentials:** add or replace keys, with an optional *User* field.
  Replacing a key's secret keeps its attributes (expiry, disabled,
  read-only). To rotate a key without losing access to your buckets, add
  the new key with the same user, then remove the old one. The first key
  turns authentication on and restarts fs3.
- **Settings:** network, access, limits and quotas, background jobs,
  storage efficiency, Object Lock, websites, replication, logging and
  hardening, about 45 options in all. Every value is validated before anything is written,
  and port clashes, an absent `fs3-lockd` helper or `--seccomp=require` on
  a kernel without seccomp are refused. Saving writes `fs3.conf` (only
  non-default values, previous file kept as `fs3.conf.bak`) and restarts
  fs3 through the watchdog within a few seconds. If fs3 then fails to
  start, the tile shows the end of the log and a *Restore previous
  settings* button. Files fs3 needs for a feature (audit log, admin
  socket, lock helper socket, replication CA bundle) always live in the package folder; the form
  can't point fs3 at other paths.
- **Replication:** the tile lists each replicating bucket with its
  target, queue, failures, lag and last error, with *Sync* (backfill) and
  *Remove* buttons, and has a form to add or replace a rule (endpoint,
  region, target bucket, keys, prefix, addressing, whether deletes are
  mirrored; the secret field is write-only and can be left empty to keep
  the stored one). It talks to fs3 through the admin API socket, which is
  now on by default. *Replication threads*, *Replication upload rate* and
  *Replication timeout* are under Settings. For an endpoint with a private
  CA, put the CA certificate (PEM) at
  `/var/packages/fs3/var/repl-ca.pem`; it is passed as `--repl-ca-file`
  at the next start.
- **`fs3.conf`:** the keys, their types, defaults and the fs3 flags they
  map to are defined once, in `packaging/synology/lib/fs3-conf.sh`, which
  both the start script and the tile use. You can still edit the file
  over SSH: unknown keys are ignored, and an invalid value falls back to
  its default with a line in `fs3.start.log`. The data folder (`FS3_DATA`) is
  not editable in the tile, since moving it means moving the data.
- **Logs:** fs3 writes and rotates `fs3.log` itself (*Rotate logs at* and
  *Rotated logs kept* in the tile; 10M × 5 by default), and the audit log
  the same way. `fs3.start.log` holds only the package script's
  messages, startup failures and crash output, and is trimmed to its
  last 128 KiB when it passes 256 KiB. The tile shows the end of both
  while fs3 is restarting or failing to start.
- `FS3_LEGACY_OWNER` (default: the first user in the credentials file)
  receives buckets that predate per-user isolation. `FS3_ADMIN=<user>`
  names an admin.
- An admin listener runs on `127.0.0.1:9101` (`FS3_METRICS_PORT`; 0
  disables it). To scrape it from elsewhere, use a reverse-proxy entry or
  an SSH tunnel.
- **Not configured by the package:** a native TLS listener. The binary
  supports it, but incoming HTTPS is the DSM reverse proxy's job. If you
  change the S3 port, also update the DSM firewall rule, which still
  lists the install-time port.
- **Data folder:** by default `/var/packages/fs3/var/data`. If you point
  it at a shared folder, grant the package user write permission in
  Control Panel → Shared Folder → Edit → Permissions. The package checks
  that it can write before starting and reports a clear error in DSM.

### HTTPS via the DSM reverse proxy

```
client --HTTPS--> DSM nginx (TLS termination) --HTTP--> fs3 on 127.0.0.1:9000
```

The SPK binds fs3 to `127.0.0.1`, so the proxy is the only public face.

1. Control Panel → Login Portal → Advanced → Reverse Proxy → Create.
2. Source: HTTPS, your hostname (e.g. `s3.nas.example.com`), port 443.
   Destination: HTTP, `localhost`, port 9000.
3. Point clients at `https://s3.nas.example.com`.

- Clients sign the `Host` header they connect to, so the proxy must
  forward it unchanged. DSM's proxy does by default; if signed requests
  fail through the proxy but work directly, check this first.
- The package trusts the proxy's `X-Forwarded-For`/`-Proto` by default
  (`FS3_TRUSTED_PROXY=127.0.0.1`), so throttling, `aws:SourceIp` and
  `aws:SecureTransport` see the real client.
- The DSM nginx access log records full presigned URLs, which are bearer
  credentials until they expire.
- To expose plain HTTP on the LAN instead, tick "Expose on the LAN" in
  the install wizard, or set the listen address to `0.0.0.0` in the
  tile's settings. Only do this on a network where you trust every host.

### Immutable locks on DSM

DSM 7 runs packages as an unprivileged user, and kernel 3.10 has no
ambient capabilities. `fs3-lockd` therefore has to be started as root
outside the normal package model, for example from a root-run boot task.
This is a manual, explicit opt-in; without it, Object Lock is API-level
WORM. Once the helper's socket exists at
`/var/packages/fs3/var/lockd.sock`, turn on *Immutable COMPLIANCE
versions* in the tile's settings.

---

## Tools

### fs3-dedup-estimate

A read-only estimate of what block-level dedup would save on an existing
data root. Use it to decide whether the
[block dedup roadmap item](#roadmap) is worth building for your data. It
is safe to run while fs3 is serving.

```sh
make fs3-dedup-estimate            # or fs3-dedup-estimate-static for the NAS
./fs3-dedup-estimate /volume1/fs3-data
./fs3-dedup-estimate --rate 20m --block-sizes 64k,128k,256k --json /volume1/fs3-data
```

- It walks `data/` and `versions/`, parses each object header, and hashes
  the payload in blocks aligned to the payload start, which is what a
  reflink-based design can share.
- It reports, per block size, the bytes already covered by whole-object
  dedup and the extra bytes block dedup could share, in owner scope and
  in global scope. A per-bucket table and a verdict follow; under 10%
  means probably not worth building.
- Skipped and counted separately: delete markers, SSE-C objects, malformed
  files, symlinks, and extra hard links of an inode already counted. Bytes
  in objects without a 4 KiB-aligned header (ext4, older schemas) are
  flagged, because they would need rewriting before their extents could
  be shared.
- Memory is capped by `--max-mem` (default 256 MiB). Beyond that it
  switches to content-based sampling, which keeps the duplicate ratio
  unbiased, and says so in the output. `--sample N` forces sampling for a
  quick first look.
- The figures are logical duplicate bytes. On Btrfs, space is freed per
  extent, so real savings also depend on extent layout (see
  `docs/block-dedup-plan.md`, section 3.4).

### Other helpers

- `tests/tools/seccomp_profile.sh` (via `make seccomp-profile`): builds
  the seccomp allowlist from evidence.
- `tests/sign_request.py`, `sign_chunked.py`, `sign_trailer.py`,
  `presign.py`: botocore-based signing helpers, also handy for manual
  testing with curl.

---

## Platform caveats

- **seccomp is not active on the DS1515+.** DSM 7.1's kernel (3.10.108)
  is built without `CONFIG_SECCOMP_FILTER` (`/proc/self/status` has no
  `Seccomp:` line), so the filter cannot be installed. With the default
  `enforce`, fs3 logs `seccomp: kernel refused the filter … running
  unfiltered` and carries on. The other hardening (no-new-privs,
  non-dumpable, PIE/RELRO/FORTIFY, unprivileged package user) still
  applies.
  - On hosts where the filter must be present (any modern distribution),
    run with `--seccomp=require`, so a missing filter stops the server
    instead of producing a log line.
  - Other Synology models may differ: check
    `grep Seccomp /proc/self/status` on the NAS.
- **Dedup together with compression on DSM 7.1.** On DSM's Btrfs (kernel
  3.10.108), enabling `--dedup` and `--fs-compress auto|all` together
  makes the clone into `cas/` fail: the clone runs before the object's
  compressed pages are flushed, and pool files don't carry `FS_COMPR_FL`.
  Nothing is lost, since objects are stored as normal copies, but
  `fs3_dedup_hits_total` stays at 0. Until this is fixed, pick one of the
  two on that kernel. It has only been observed on 3.10.
- **No kTLS on kernel 3.10.** Native TLS on the DS1515+ copies bodies
  through userspace instead of using sendfile, so expect higher CPU use
  than over plain HTTP behind the DSM proxy.
- **Single node.** Redundancy comes from RAID or Btrfs underneath, from
  [bucket replication](#bucket-replication) to another S3 endpoint, and
  from off-site backups. The plain-file layout makes those backups easy,
  because any file-level backup tool works.

---

## Upgrading

The object header (schema 4), layout-2 Object Lock buckets, credential
attributes, and the version and lock trees are **one-way migrations**:
an older fs3 cannot read data written by this one. Back up before
upgrading, and see `packaging/synology/CHANGELOG.md`.

---

## Build

```sh
make                 # release build (-O2): fs3, fs3-lockd, fs3-dedup-estimate
make DEBUG=1         # ASan + UBSan (switching needs `make clean`)
make TLS=1           # fs3 with native TLS (or `make fs3-tls` for a separate binary)
./fs3 --build-info   # tls=yes|no
make fs3-static fs3-tls-static fs3-lockd-static fs3-dedup-estimate-static   # for the SPK
make test            # all unit, fuzz and e2e suites
make smoketest       # start briefly and probe with curl
make seccomp-profile # diff used syscalls against the allowlist
make clean
```

Dependencies: a C11 compiler and libcrypto (`libssl-dev` on
Debian/Ubuntu). TLS builds also need libssl. If `third_party/llhttp/` is
empty, `make fetch-llhttp` retrieves it from PyPI's `httptools` sdist;
that is the only target that needs network access. Header dependencies
are tracked automatically (`-MMD -MP`).

---

## Tests

Install the test dependencies with `pip install -r tests/requirements.txt`
(boto3 ≥ 1.36, `botocore[crt]` for CRC32C/CRC64NVME, AWS CLI). You also
need `curl` and `openssl`.

- `make test` checks for these first (`make check-test-deps`) and prints
  the install line, rather than failing deep inside a suite.
- Some cases skip with a visible `SKIP` line instead of failing:
  - checksum cases need `awscrt`;
  - `test_e2e_reflink.sh` needs a Btrfs/XFS directory in
    `FS3_REFLINK_DIR` (a loopback image works);
  - `test_e2e_immutable.sh` needs root;
  - one metadata case needs rclone.
- Set `FS3_TEST_STRICT=1` in CI to turn skips into failures.

| kind | suites |
|---|---|
| C unit tests | `test_store`, `test_conn`, `test_sigv4`, `test_repl`, `test_checksum`, `test_objmeta`, `test_policy`, `test_json`, `test_ssec`, `test_sandbox`, `test_credfile`, `test_xml`, `test_xml_legacy` |
| fuzzers (50,000 iterations each) | `test_xml_fuzz`, `test_chunk_fuzz`, `test_config_fuzz`, plus fuzz passes in the policy, JSON and credentials suites |
| core e2e | `test_e2e`, `test_e2e_auth`, `test_e2e_mpu`, `test_e2e_parts`, `test_e2e_listing`, `test_e2e_metadata`, `test_e2e_phase9`–`12`, `test_e2e_subresources` |
| access control | `test_e2e_isolation`, `test_e2e_policy`, `test_e2e_keys`, `test_e2e_presign`, `test_e2e_admin`, `test_e2e_audit` |
| features | `test_e2e_checksum`, `test_e2e_versioning`, `test_e2e_objlock`, `test_e2e_immutable`, `test_e2e_lifecycle`, `test_e2e_cors`, `test_e2e_website`, `test_e2e_quota`, `test_e2e_scrub`, `test_e2e_ssec`, `test_e2e_tls`, `test_e2e_reflink` |
| logging | `test_log` (rotation, concurrency, failure handling), `test_e2e_logs` |
| replication | `test_repl` (journal records and rule parser, plus a 50,000-iteration fuzz), `test_sigv4` (outbound signer against the botocore vector), `test_e2e_s3client` (outbound client, plain and TLS), `test_e2e_repl` (two fs3 instances: arrival, coalescing, outage, backfill, permanent and rule-level errors, crash recovery, SSE-C, https, self-healing scrub) |
| keep-alive | `test_e2e_keepalive` (a request sent while a large response is still going out, pipelining, split requests, an early error mid-body) |
| backup tools (`make compat`, not in `make test`) | `tests/compat/`: restic, rclone, Kopia, Duplicati, AWS CLI v2 × plain / TLS / versioning / Object Lock / crash; see [docs/compatibility.md](docs/compatibility.md) |
| tools and packaging | `test_e2e_dedup_estimate`, `test_ui_cgi` (DSM tile: sign-in gate, credentials, settings), `test_spk_scripts` (start script, conf → flags, watchdog) |

All suites run under both the release and the ASan/UBSan builds. The
e2e suites use real clients (botocore, boto3, the AWS CLI, curl) as the
oracle. A server killed by seccomp is reported explicitly.

---

## Source layout

```
src/
  main.c          options, credentials file, signals, startup and shutdown
  server.c        epoll accept loop, listeners (S3, TLS, website, admin)
  conn.c          per-connection state machine, llhttp glue, body streaming, auth hook
  route.c         S3 operation classification and handlers
  action.c        operation → IAM action / permission table (exhaustive)
  response.c      response heads, S3 XML, errors
  sigv4.c         SigV4: header, chunked, trailer, presigned; key attributes
  store_fs.c      filesystem object store: objects, versions, MPU, locks, quotas, dedup
  objmeta.c       user metadata and standard headers (TLV)
  checksum.c      CRC32/CRC32C/CRC64NVME/SHA, streaming API
  policy.c        bucket policy parser and evaluator
  json.c          strict JSON parser and writer
  cors.c website.c lifecycle.c objlock.c scrub.c ssec.c
  admin.c         /v1 admin API
  repl.c          bucket replication: journal, workers, backfill, self-healing
  s3client.c      outbound S3 client (HTTP/1.1, optional TLS, SigV4 signing)
  audit.c         audit log, auth-failure throttling
  metrics.c       Prometheus metrics
  tls.c           native TLS (TLS=1 builds)
  sandbox.c       seccomp filter
  iopool.c        worker threads for fsync/copy/complete jobs
  lockc.c         client side of fs3-lockd
  lockd.c         fs3-lockd (separate binary)
  dedup_estimate.c  fs3-dedup-estimate (separate binary)
include/          one header per module
tests/            unit, fuzz and e2e suites, signing helpers, fixtures
packaging/synology/  SPK build, DSM tile, scripts, CHANGELOG
docs/             DS1515+ runbook, Synology readiness notes, block-dedup plan
third_party/      vendored llhttp and the XML library
```

`CLAUDE.md` holds the working rules for contributors and agents: lock
order, crash-safety pattern, test requirements, and a map of what each
feature added.

---

## Roadmap

Done: the gap-closure plan (versioning, Object Lock, policies, TLS,
presign, CORS, lifecycle, website, admin API, audit) and round 2 (part
records, ListParts, UploadPartCopy, metadata, quotas, scrub, key
hygiene, seccomp, reflink, dedup, compression, SSE-C, immutable locks),
log rotation and bucket replication (with backfill and a self-healing
scrub).

Next:

- **Block-level dedup through reflinks** (option 2 from the Garage
  comparison). A background, opt-in job hashes 128 KiB blocks of
  committed objects. It clones identical blocks between object files
  after a byte comparison, working one destination extent at a time so
  Btrfs actually frees space. Object files stay complete, and there is no
  chunk store or refcounting. Gated on `fs3-dedup-estimate` showing about
  10% or more savings on real data. Plan: `docs/block-dedup-plan.md`.
- **Verify the tile's DSM sign-in check on hardware** (DSM 7.1 on the
  DS1515+), including the SynoToken fallback; until then the settings
  can also be edited over SSH.
- **Dedup together with compression on DSM 7.1:** fsync the object, or
  set `FS_COMPR_FL` on pool files, before cloning into `cas/`.
- **Production soak:** long-running use on real data, plus a periodic
  restore drill from the plain object files.
- **Replication on hardware:** a DS1515+ run replicating to B2 or a second
  box, which also confirms the DSM CA bundle path
  (`docs/AGENT-REPLICATION-DS1515-TEST.md`).
- **Backup-tool matrix, GUI part:** recorded Hyper Backup and Veeam runs
  (`docs/AGENT-COMPAT-HYPERBACKUP-VEEAM.md`). The scripted part is done:
  `make compat`, results in `docs/compatibility.md`.
- **An offline converter** from layout 1 to layout 2 for existing Object
  Lock buckets.
- **Application-level zstd** for ext4 volumes, only if needed.
- **A more visible seccomp state** in the DSM tile (the filter can't run
  on DSM's kernel).

Out of scope by design: multi-node clustering and two-way replication,
content-addressed chunk
storage, SSE-S3/KMS, STS, object tagging.
