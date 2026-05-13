# CLAUDE.md — orientation for the next session

This file is the bridge from "I just unpacked the tarball" to "I know
where the load-bearing parts are." Read the README first for what fs3
is. This file is the working notes — the *don't relearn these* facts.

The project has been built up across ten phases. Current state: a
~10,200-line single-node S3-compatible server in C, with header-mode +
streaming-chunked SigV4, multipart upload, service-level listing,
periodic GC of abandoned multipart uploads, HTTP Range requests,
bulk-delete (`?delete`), bucket subresources (location/versioning
stubs), server-side object copy, and ACL stubs. 233 explicit tests +
50K fuzz iterations green under both `-O2` and ASan + UBSan.

## First five minutes on a fresh box

The sandbox doesn't persist between sessions, so you'll restore from
the latest tarball under `/mnt/user-data/outputs/`. After
`tar xzf` + `cd fs3`:

```sh
apt-get install -y libssl-dev          # for openssl/evp.h
pip install --break-system-packages botocore boto3 awscli
                                        # for tests/sign_request.py and aws cli
chmod +x tests/*.sh                     # tar may not preserve +x in this env
mkdir -p ~/.aws && cat > ~/.aws/config <<EOF
[default]
region = us-east-1
s3 =
    addressing_style = path
EOF
                                        # AWS CLI v-host default doesn't work
                                        # against 127.0.0.1

make test                               # ~3 min for the full pyramid
```

If `make test` fails on `test_e2e_auth.sh` with no output, 9 times out
of 10 it's the botocore install missing. Run
`bash -x tests/test_e2e_auth.sh 2>&1 | head -30` to confirm.

## Working directory conventions

- Working tree lives at `/home/claude/fs3/`. It usually persists across
  turns within a session; never across sessions.
- Output artifacts go to `/mnt/user-data/outputs/`. The most recent
  tarball name is `fs3-phase8-listing-and-gc.tar.gz`.
- Don't trust the `fs3` binary across sessions — always `make clean
  && make` after a restore. The release and sanitizer builds use the
  same object files, so mixing them silently links wrong code.

## What is wired

```
src/main.c          CLI parsing, server bring-up
src/server.c        accept/epoll loop, MPU GC scheduling
src/conn.c          per-conn state machine, llhttp callbacks, SigV4 invoke
src/route.c         path parse, dispatch, all S3 handlers
src/response.c      response builders, XML rendering, error mapping, ETag fmt
src/store_fs.c      filesystem-backed store: PUT/GET/HEAD/DELETE/LIST/MPU/GC
src/sigv4.c         header-mode + streaming-chunked SigV4 verifier
src/log.c           leveled logger
include/*.h         public APIs
tests/              test_store.c, test_sigv4.c, three .sh suites
third_party/llhttp/ vendored llhttp v9.3.0 (parser, MIT)
third_party/xml/    extended XML library (parsing + rendering + fuzz tests)
```

The protocol surface covered today:

- Bucket: PUT / GET (list objects, paginated, with prefix/delimiter) /
  DELETE / HEAD
- Object: PUT (single + streaming) / GET (full body, sendfile) / HEAD
  / DELETE
- Multipart: initiate / upload-part / complete / abort, plus the AWS-
  style `"<md5-of-md5s>-<n>"` ETag carried through to GETs and listings
- Service: ListAllMyBuckets (`GET /`)
- Bucket: ListMultipartUploads (`GET /bucket?uploads`) with optional
  `prefix` filter
- Background: 60s-cadence MPU GC with 24h TTL (both flag-tunable)
- Auth: SigV4 header mode AND streaming chunked mode
  (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`), per-chunk signature chaining
  verified before bytes hit the store writer
- Range GET: `Range: bytes=A-B/A-/-N` → 206 Partial Content with
  `Content-Range`; invalid ranges → 416
- Bulk delete: `POST /<bucket>?delete` with `<Delete>` XML body,
  returns `<DeleteResult>` with `<Deleted>`/`<Error>` elements, supports
  `<Quiet>true</Quiet>` mode
- Bucket subresources: `?location` and `?versioning` stubs return
  sensible empty XML (no-region, no versioning)
- Server-side copy: `PUT /<bucket>/<key>` with
  `x-amz-copy-source: [/]src-bucket/src-key`, returns
  `<CopyObjectResult>` with ETag + LastModified; preserves source
  content-type; URL-decodes the source path
- ACL stub: `GET /<bucket>?acl` and `GET /<bucket>/<key>?acl` return a
  static FULL_CONTROL ACL; `PUT` accepts and discards the body → 200

What we *don't* do:
- HTTP `Range:` multi-range (`bytes=A-B,C-D`; only single-range spec)
- SigV4 trailer variants (`STREAMING-...-TRAILER`)
- Bucket subresources: `?lifecycle`, `?cors` (location + versioning are stubs)
- Pagination on ListMultipartUploads (always `IsTruncated=false`)
- Any kind of IAM beyond static `access_key:secret_key` pairs from the
  CLI. No policies, no STS, no console.
- Replication, versioning, lifecycle rules, server-side encryption

## On-disk layout

```
<root>/
  buckets/<bucket>/                 # one empty dir per bucket
  data/<bucket>/<NN>/<NN>/<hex>     # objects, sharded by hash prefix
                                    # file = obj_header_t + content_type
                                    # + key + body
  mpu/<bucket>/<upload_id>/         # one dir per in-flight multipart upload
    meta                            # key, ct, ctime_ms (one per line)
    part-00001, part-00002, ...     # each part's bytes verbatim, named
                                    # with MD5 in the dir
  tmp/                              # staging area for atomic renames
```

Object header is `obj_header_t`, schema 2 (bumped from 1 when we added
`part_count` for multipart-ETag preservation across GETs). All fields
little-endian, packed, with a magic prefix `YS3OBJ\0\0`. If you change
the on-disk format again, bump the schema and reject mismatches at
read time — the read path already does this.

## Tests and what each covers

| target | language | what it exercises |
|---|---|---|
| `tests/test_store` | C | 27 unit tests: bucket CRUD, single PUT/GET round-trip, sendfile, listing with prefix/delimiter, persistence across `store_open`/`store_close`, multipart lifecycle, list_buckets, list_mpu_uploads (with prefix filter), mpu_gc reaping behavior |
| `tests/test_xml` | C | 25 tests of the extended XML library (escaping, parsing, security limits) |
| `tests/test_xml_legacy` | C | one round-trip showing the original calling style still works |
| `tests/test_xml_fuzz` | C | 50,000 random inputs through the parser, must not crash |
| `tests/test_sigv4` | C | 34 unit tests of canonical request, string-to-sign, signing key derivation, against AWS test vectors |
| `tests/test_e2e.sh` | bash + curl | 23 integration tests: every bucket/object verb, listing edge cases, keep-alive pipelining, large objects, ext_body spillover, ListAllMyBuckets |
| `tests/test_e2e_auth.sh` | bash + python | 28 integration tests of SigV4 with real signatures from botocore (header mode + streaming chunked) |
| `tests/test_e2e_mpu.sh` | bash + curl | 26 integration tests of the full multipart lifecycle including ListMultipartUploads, prefix filter, abort, malformed XML, large parts |
| `tests/test_e2e_phase9.sh` | bash + curl | 45 integration tests of Range GET (206/416), bulk delete (`?delete`), and bucket subresources (`?location`, `?versioning`) |
| `tests/test_e2e_phase10.sh` | bash + curl | 27 integration tests of server-side object copy and `?acl` stub |

All eight targets pass under both `-O2` and DEBUG (ASan + UBSan).

`make test` runs everything sequentially; each suite is also runnable
standalone. The auth suite is the slowest (~30s; chunked SigV4 tests
upload real payloads).

## Architecture choices to keep in mind

These are decisions made early that the rest of the code depends on.
Don't quietly undo them.

- **Single-threaded epoll event loop.** No worker threads. No locks.
  All I/O is non-blocking. The store's filesystem operations are
  synchronous and that's accepted — the per-request latency budget
  is determined by `fsync()`, not by CPU.

- **`s3_str_t` is the universal string type.** `(const char *p, size_t
  n)`. Length-bounded, no NUL terminator required. Don't strdup unless
  the lifetime needs to outlive the request. Macros:
  `S3_STR_LIT("x")`, `S3_STR_FMT` / `S3_STR_ARG(s)` for printf,
  `s3_str_eq` / `s3_str_eq_lit` for comparisons. All in `include/s3.h`.

- **Per-request bump arena.** `c->req_scratch` is a 4 KB arena reset
  between requests. Use `scratch_alloc(c, n)` for short-lived
  allocations during request handling (decoded query values, parsed
  Authorization fields, etc.). Falls back to `malloc` when needed.

- **The on-disk format is the persistence story.** No database, no
  index. Listing iterates `readdir()`. This is fine for homelab scale
  (≪10⁶ objects per bucket). At larger scale we'd want an index, but
  that's a different project.

- **Atomic writes via tmp + fsync + rename + fsync(parent_dir).** Every
  PUT and every CompleteMultipartUpload follows this discipline. Test
  failures involving "object missing after PUT returned 200" almost
  always trace back to a missing `fsync` somewhere.

- **The XML library is in `third_party/xml/`.** It's the same library
  used by yours3 phase 0; it has its own tests and fuzz suite. Don't
  inline XML generation; use `create_node`/`xml_text_child`/etc., then
  `xml_render_with_decl`.

- **`conn_t` and `s3_store_t` are *not* the same lifetime.** `conn_t`
  is per-connection; `s3_store_t` is server-lifetime. Same for
  `sigv4_verifier_t`. Don't free `c->store` in `conn_destroy`.

## Sandbox / tooling gotchas

These are environment artifacts that have bitten me, not project
issues:

- **`pkill -9 -f "fs3 -p"` sometimes hangs the shell** for unknown
  reasons. When it does, the previous tool call returns with empty
  output and the next one needs to be a `echo a` canary to confirm
  the shell is still alive. Avoid `pkill` if there are no fs3
  processes around; check with `ps aux | grep fs3 | grep -v grep`
  first.

- **Backgrounded servers and `aws cli` invocations in the same cell
  can race.** If you start a server with `&` and then run `aws s3 mb`
  immediately, sometimes the server hasn't bound the port yet. Sleep
  0.4s. If it still fails, do it in two separate cells.

- **`make test` output sometimes gets truncated** when one suite hangs
  but eventually returns. Run suites individually
  (`./tests/test_e2e.sh`, `./tests/test_e2e_auth.sh`, etc.) to confirm
  green if `make test` looks weird.

- **`set -eu` in bash scripts will kill the script** when
  `grep -c PATTERN` returns 0 matches (exit 1). Append `|| true` to
  count expressions in test scripts; we hit this twice while writing
  `test_e2e_mpu.sh`.

- **A leftover `./fs3` from a previous session may be the sanitizer
  binary**, which is slower and pulls in `libasan.so`. Always
  `make clean && make` after restoring from tarball.

## How to extend

Common patterns for adding a new feature:

**Adding a new HTTP endpoint:**
1. Add the handler in `src/route.c`. Existing handlers are good
   templates — `handle_service`, `handle_bucket`, `handle_object_get`,
   etc.
2. Add response builders in `src/response.c` and declare them in
   `include/response.h`. Use `ship_xml_200(c, body, blen)` for the
   ext_body spill case.
3. Wire it into `route_dispatch_headers` or a query-param branch.
4. Add e2e tests to the appropriate `tests/test_e2e*.sh`.

**Adding a new store operation:**
1. Add to `include/store.h` with a doc comment.
2. Implement in `src/store_fs.c`. The header has `s3_err_t` returns
   and `s3_str_t` inputs; don't deviate.
3. Add to `tests/test_store.c` with the `t_xxx()` + register-in-main
   pattern.

**Adding a new error code:**
1. Add to the enum in `include/s3.h`.
2. Add to `ERR_TABLE` in `src/response.c` (HTTP status + S3 code + msg).
3. That's it — `rsp_build_s3_error` handles the rest.

**Adding a new on-disk field:**
1. Bump `OBJ_SCHEMA` in `src/store_fs.c`.
2. Add the field to `obj_header_t`. Use `reserved[]` padding if
   possible, otherwise grow it.
3. Update `read_header` to populate the new `s3_obj_meta_t` field.
4. Update `_Static_assert(sizeof(obj_header_t) == N)` to the new size.
5. Old objects on disk won't parse anymore. This is fine for a homelab
   pre-1.0 server; document it as a schema bump in the README.

## Phase history

For when "wait, what was I doing in phase 5?" is the question:

- **Phase 0** — HTTP server skeleton: epoll, llhttp, per-conn state
  machine, write response back. No store, no S3 protocol.
- **Phase 1** — Filesystem store: bucket and object CRUD on disk with
  atomic-rename discipline. Tests in C.
- **Phase 2** — S3 protocol: PUT/GET/HEAD/DELETE/list of objects,
  XML responses. AWS CLI works without auth.
- **Phase 3** — SigV4 header mode: canonical request, string-to-sign,
  signing key. AWS test vectors. End-to-end with botocore.
- **Phase 4** — Body-hash verification: streaming SHA-256 of the body,
  compare against `x-amz-content-sha256`. Closes the "client can lie
  about body" hole.
- **Phase 5** — Streaming chunked SigV4: `aws-chunked` decoder with
  per-chunk signature chaining, integrated with the existing PUT
  writer path. AWS CLI's default-mode uploads now work.
- **Phase 6** — Skipped/folded into 5.
- **Phase 7** — Multipart upload: initiate / upload-part / complete /
  abort. On-disk staging under `mpu/`. Multipart ETag carried through
  to GET via schema-2 `part_count` field. 16 MB AWS CLI round-trip.
- **Phase 8** — Service-level listing (`ListAllMyBuckets`),
  in-bucket listing of in-flight uploads (`ListMultipartUploads`
  with prefix filter), and periodic GC of abandoned multipart
  staging dirs (60s sweep, 24h TTL, both flag-configurable).
- **Phase 9** — HTTP Range requests (`Range: bytes=A-B/A-/-N`,
  206 Partial Content / 416 Range Not Satisfiable), bulk object
  delete (`POST /<bucket>?delete` with `<Delete>` XML body, including
  Quiet mode), and bucket subresource stubs (`?location`,
  `?versioning`).
- **Phase 10** — Server-side object copy (`PUT` with
  `x-amz-copy-source`), and `?acl` stub for both bucket and object
  level (GET returns static FULL_CONTROL ACL, PUT discards body).
  The current state.

## Decisions for next phase

When picking up phase 11, in rough order of value:

1. **`?lifecycle` / `?cors` stubs** — clients sometimes probe these
   before operating on a bucket. Empty XML response, ~20 lines each.
2. **Multi-range `Range:` support** — `bytes=A-B,C-D`. Returns
   `multipart/byteranges` MIME body. Rarely needed by S3 clients.
3. **Object copy with metadata replace** — honour
   `x-amz-metadata-directive: REPLACE` to take the new request's
   `Content-Type` instead of copying the source's. Currently always
   copies the source content-type.
4. **Copy source range** — `x-amz-copy-source-range: bytes=A-B` for
   partial object copies (copy only a byte slice of the source).

Don't tackle erasure coding, distributed mode, or IAM. Those aren't
"the next phase of fs3" — those would be a different project (and
the answer to that project is rustfs, not fs3).
