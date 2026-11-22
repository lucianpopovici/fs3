# Test fixtures

- `obj_v2_legacy.bin` — an object file written in on-disk schema 2
  (pre-v3: 60-byte header, no extension block) for bucket `buk`, key
  `legacy.txt`, content-type `text/plain`, body
  `"hello from schema 2\n"`, mtime 1700000000123 ms. `test_store`
  installs it under the hashed path and checks that the current reader
  still serves it.
- `obj_v3.bin` — schema 3 (60-byte header + 64-byte v3 extension, no v4
  block / TLV) for bucket `buk`, key `legacy3.txt`, content-type
  `text/plain`, body `"hello from schema 3\n"`, version id 01..10, a
  CRC32 checksum `deadbeef`. Read by `test_store` (schema 4 reads 2, 3, 4;
  writes only 4).
