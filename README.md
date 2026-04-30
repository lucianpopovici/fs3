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

What's *not* yet wired:

- SigV4 signature verification — the hookpoint exists in
  `cb_on_headers_complete`; the verifier is the next piece.
- Multipart upload (`?uploads`, `?uploadId=`, `?partNumber=`).
- Service-level `ListAllMyBuckets` (`GET /`).
- Bucket subresources: location, versioning, lifecycle, CORS, etc.

## Layout

```
fs3/
├── Makefile
├── README.md
├── include/
│   ├── conn.h        per-connection state machine
│   ├── log.h
│   ├── response.h    HTTP response builders (status, S3 errors, lists)
│   ├── route.h       request dispatcher
│   ├── s3.h          shared types (error codes, s3_str_t)
│   ├── server.h      epoll TCP server
│   └── store.h       object store interface
├── src/
│   ├── conn.c        llhttp glue, header accumulation, body streaming
│   ├── log.c
│   ├── main.c        argv parsing, signal handling, bootstrap
│   ├── response.c    response building (RFC 1123/ISO 8601/ETag/XML)
│   ├── route.c       HTTP method × path-shape → handler dispatch
│   ├── server.c      epoll accept + connection lifecycle
│   └── store_fs.c    filesystem-backed object store
├── tests/
│   ├── test_e2e.sh   21 HTTP integration tests
│   └── test_store.c  17 store-layer tests
└── third_party/
    ├── llhttp/       vendored llhttp v9.3.0 (HTTP parser)
    └── xml/          extended XML library + tests
```

## Build

```
make                # release (-O2)
make DEBUG=1        # ASan + UBSan
make test           # build and run all tests (~70 tests + 50k fuzz iters)
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
./fs3                                      # listen on 127.0.0.1:9000
./fs3 -a 0.0.0.0 -p 9000 -d /var/lib/fs3 -v
```

Then point any S3 client at the server. The AWS CLI works with
`--endpoint-url http://127.0.0.1:9000` once SigV4 is in place; for now,
unauthenticated curl/`mc` against the wire protocol works.

## Tests

| target              | what it covers                                                    |
|---------------------|-------------------------------------------------------------------|
| `tests/test_store`  | bucket CRUD, streaming PUT/GET, sendfile, listing, persistence    |
| `tests/test_xml`    | XML library: escaping, parsing, security limits, round-trips      |
| `tests/test_xml_legacy` | original calling style still works                            |
| `tests/test_xml_fuzz`   | 50,000 random byte inputs into `parse_xml`, must not crash    |
| `tests/test_e2e.sh` | 21 HTTP integration tests against the actual server binary        |

The e2e suite covers: bucket create / duplicate / invalid name, object
PUT/GET (with ETag verification against known MD5), HEAD, DELETE,
overwrite, missing bucket / key 404s with proper S3 error XML,
listing (basic, truncated, prefix, delimiter rollup), XML escaping in
response bodies, HTTP/1.1 keep-alive pipelining, large-object
sendfile, content-type round-trip, path-traversal protection, and the
ext_body spillover path for responses > 16 KB.

All five targets pass under both release (`-O2`) and DEBUG (ASan +
UBSan) builds with zero warnings, leaks, or sanitizer findings.

## What's next

SigV4 verification slots into `cb_on_headers_complete` in `src/conn.c`
just before the `route_dispatch_headers(c)` call. The verifier needs
canonical-request construction (URI/query/header normalization), the
four-step derived signing key chain, and a credential lookup. AWS
publishes test vectors which let the verifier be unit-tested in
isolation before plumbing through the request path. Streaming SigV4
chunked uploads (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) are a follow-up
once the basic header-mode signature works.
