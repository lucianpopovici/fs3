# fs3 SPK changelog

## Unreleased (round 2)

- New read-only tool `fs3-dedup-estimate` (`make fs3-dedup-estimate[-static]`)
  that measures how much block-level dedup would save on an existing data
  root. Not shipped in the SPK yet; copy the static binary to the NAS to
  run it.
- Known limitation: `fs3.conf` only exposes the basic keys (bind, port,
  data, auth, legacy owner, admin, metrics port, MPU GC). The newer
  options (trusted proxy, audit log, admin socket, scrub, quotas, dedup,
  compression, lock helper, TLS) can't be set through the package yet.

- Multipart: part records + ETag verification at Complete (InvalidPart,
  InvalidPartOrder, EntityTooSmall below `--mpu-min-part-size`, default
  5 MiB), ListParts, UploadPartCopy; `x-amz-copy-source-if-*` honoured.
- Multi-range GETs return the whole object (200) as S3 does; invalid
  Range headers are ignored.
- User metadata and standard object headers are stored and returned;
  `response-*` overrides; `x-amz-metadata-directive`. A self-copy
  without `REPLACE` is now `400 InvalidRequest` (S3 behaviour).
- Fix: `Connection: close` from a client was ignored (wrong llhttp flag).
- Quotas per bucket and per user (admin API, `--default-bucket-quota`,
  `--default-user-quota`), `403 QuotaExceeded`, Prometheus gauges, quota
  column in the DSM console. New files: `buckets/<b>/quota`,
  `buckets/<b>/usage`, `users/<hex>.quota`, `<root>/.fs3-running`.
- Background integrity scrub (`--scrub-interval-days`, `--scrub-rate`,
  `--scrub-now`, `--scrub-fail-reads`, admin `POST/GET /v1/scrub`, new
  `scrub/` dir with `state` and `corrupt.log`, `fs3_scrub_*` metrics).
- Key expiry, disable, read-only keys and last-used times (fourth field
  of a credentials line, `PATCH /v1/keys/<ak>`, `--key-max-age-days`,
  `keys.state`). **No downgrade** once a credentials line carries
  attributes: an older fs3 refuses the file (`:` in the user field).
- seccomp-BPF syscall filter, on by default (`--seccomp=off|log|enforce|require`).
- Reflink fast paths on Btrfs for multipart Complete, CopyObject and
  UploadPartCopy (`--reflink auto|off`, `fs3_reflink_clones_total`).
- Opt-in whole-object dedup on Btrfs (`--dedup owner|global`, new `cas/` pool dir).
- Btrfs transparent compression of objects (`--fs-compress auto|all`).
- SSE-C (customer-provided keys; TLS only).
- Object-lock buckets created from now on use **layout 2** (versions/ +
  data/ symlinks); one-way: an older fs3 cannot read them. Existing
  lock buckets are unchanged.
- Optional `FS_IMMUTABLE_FL` for COMPLIANCE / legal-hold versions via the
  new root helper `fs3-lockd` (`--lock-immutable --lockd-socket`). **Manual
  opt-in on DSM:** DSM 7 runs packages as an unprivileged user and kernel
  3.10 has no ambient capabilities, so the helper cannot run inside the
  package. Start it as root yourself (e.g. a root "Triggered task" at boot
  in Task Scheduler running
  `/var/packages/fs3/target/bin/fs3-lockd --root <data dir> --socket
  /var/packages/fs3/var/lockd.sock --journal /var/packages/fs3/var/lockd.journal`),
  then add `--lock-immutable --lockd-socket /var/packages/fs3/var/lockd.sock`
  to the fs3 command line. `fs3.conf` has no key for these yet, so that
  means editing `scripts/start-stop-status`, and a package upgrade
  overwrites the edit. Without it the status stays "API-level WORM".
- Audit log lines carry the S3 error code (`"error":"…"`).
- Fix: a request refused before `100 Continue` now closes the connection
  (botocore stalled 60 s on the next request).
- ListObjectsV2 pagination (was capped at the first 1000 keys),
  `encoding-type=url`, ListMultipartUploads pagination; delimiter
  listings no longer repeat a CommonPrefix on the next page.

- Object files are now written in on-disk **schema 4** (adds stored size,
  a CRC64NVME over the on-disk payload, a TLV area for metadata, and
  4 KiB header padding on reflink-capable volumes). Schemas 2 and 3 are
  still read. One-way: an older fs3 answers `InternalError` for schema-4
  objects — **no downgrade after upgrade**.

## Previous release

**One-way on-disk migrations — no downgrade after upgrade.** Once this
version has written data, an older fs3 package cannot read it. Back up
the data folder before upgrading if you might need to roll back.

- Object files are now written in on-disk schema 3 (adds checksum,
  version-id and flag fields). Objects written by earlier versions
  (schema 2) are still read; they are rewritten as schema 3 only when
  overwritten. An older binary answers `InternalError` for any schema-3
  object.
- New on-disk trees `versions/` (noncurrent object versions) and
  `locks/` (object-lock records), and bucket sidecars (`grants`,
  `cors.xml`, `lifecycle.xml`, `website.xml`, `policy.json`,
  `object-lock.xml`). Older versions ignore them — which for a versioned
  or locked bucket means silently losing those semantics. Do not
  downgrade.
- Added: trailer checksums, presigned URLs, grants, CORS, lifecycle,
  static websites, versioning, bucket policies, Object Lock, admin API,
  audit log, auth throttling, optional native TLS (not in the SPK build).
- Unimplemented S3 subresources (`?tagging`, `?retention`, `?versionId`,
  …) now answer `501 NotImplemented` instead of falling through to a
  plain PUT/DELETE of the object.
