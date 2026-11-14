# Test fixtures

- `obj_v2_legacy.bin` — an object file written in on-disk schema 2
  (pre-v3: 60-byte header, no extension block) for bucket `buk`, key
  `legacy.txt`, content-type `text/plain`, body
  `"hello from schema 2\n"`, mtime 1700000000123 ms. `test_store`
  installs it under the hashed path and checks the schema-3 reader still
  serves it (F1: read v2 + v3, write v3 only).
