# fs3 SPK changelog

## Unreleased (round 2)

- Multipart: part records + ETag verification at Complete (InvalidPart,
  InvalidPartOrder, EntityTooSmall below `--mpu-min-part-size`, default
  5 MiB), ListParts, UploadPartCopy; `x-amz-copy-source-if-*` honoured.
- Multi-range GETs return the whole object (200) as S3 does; invalid
  Range headers are ignored.
- User metadata and standard object headers are stored and returned;
  `response-*` overrides; `x-amz-metadata-directive`. A self-copy
  without `REPLACE` is now `400 InvalidRequest` (S3 behaviour).
- Fix: `Connection: close` from a client was ignored (wrong llhttp flag).

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
