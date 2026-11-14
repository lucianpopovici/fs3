# fs3 SPK changelog

## Unreleased

**One-way on-disk migrations — no downgrade after upgrade.** Once this
version has written data, an older fs3 package cannot read it. Back up
the data folder before upgrading if you might need to roll back.

- Object files are now written in on-disk schema 3 (adds checksum,
  version-id and flag fields). Objects written by earlier versions
  (schema 2) are still read; they are rewritten as schema 3 only when
  overwritten. An older binary answers `InternalError` for any schema-3
  object.
- Unimplemented S3 subresources (`?tagging`, `?retention`, `?versionId`,
  …) now answer `501 NotImplemented` instead of falling through to a
  plain PUT/DELETE of the object.
