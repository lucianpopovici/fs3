# CLAUDE.md — working notes for contributors and agents

Read `README.md` first for what fs3 is and what it supports. This file
holds the facts you shouldn't have to relearn: the rules the code depends
on, where things live, how to extend it safely, and environment gotchas.

Current state (November 2026): about 24,000 lines of C. The original
twelve phases, the gap-closure plan (Garage comparison and security
addendum) and round 2 are all implemented. Everything passes `make test`
under both `-O2` and ASan + UBSan, and on a DS1515+ (recorded run in
`docs/AGENT-BUILD-AND-DS1515-TEST.md`). Open work is in the README's
"Roadmap" and in `docs/synology-readiness/CLAUDE.md`.

## First five minutes

```sh
git clone https://github.com/lucianpopovici/fs3 && cd fs3
apt-get install -y build-essential libssl-dev curl openssl
pip install --break-system-packages -r tests/requirements.txt   # boto3, botocore[crt], awscli
mkdir -p ~/.aws && cat > ~/.aws/config <<EOF
[default]
region = us-east-1
s3 =
    addressing_style = path
EOF
make && make test
```

- The AWS CLI's virtual-hosted default doesn't work against `127.0.0.1`,
  which is why the config sets path-style.
- `make test` stops early with an install hint if a test dependency is
  missing (`make check-test-deps`).
- The release and sanitizer builds share object files: `make clean`
  whenever you switch `DEBUG` or `TLS`, or mixed objects link silently.
- A few cases skip unless their environment is there (see README,
  "Tests"). Set `FS3_TEST_STRICT=1` to make skips fail.

## Where things are

The module list is in README, "Source layout". Feature → code → tests:

| feature | code | tests |
|---|---|---|
| request classification, `authz()` | `route_classify`, `authz` in `src/route.c`; action table in `src/action.c` (exhaustive; the server refuses to start if an action is unmapped) | `test_e2e_subresources.sh` |
| SigV4 header / chunked / trailer / presigned, key attributes | `src/sigv4.c` (`extract_auth_params`, `verify_params`, chunk decoder, `sigv4_cred_attrs_t`) | `test_sigv4`, `test_chunk_fuzz`, `test_e2e_auth.sh`, `test_e2e_presign.sh`, `test_e2e_keys.sh` |
| checksums | `src/checksum.c`; `checksum_setup`/`checksum_finish` in `src/conn.c` | `test_checksum`, `test_e2e_checksum.sh` |
| object format (schema 4, TLV, padding, payload CRC) | `obj_read_hdr4` and friends in `src/store_fs.c`; metadata TLVs in `src/objmeta.c` | `test_store`, `test_objmeta`, `tests/fixtures/` |
| multipart, part records, ListParts, UploadPartCopy | MPU section of `src/store_fs.c`, handlers in `src/route.c` | `test_e2e_mpu.sh`, `test_e2e_parts.sh` |
| listing | lister in `src/store_fs.c`, list handlers in `src/route.c` | `test_e2e_listing.sh` |
| grants, config sidecars, id-keyed cache | `store_bucket_sidecar_*`, `store_sidecar_get[_ttl]` | `test_store`, `test_e2e_isolation.sh` |
| versioning | versioning section of `src/store_fs.c` | `test_e2e_versioning.sh` |
| Object Lock, layout 2, fs3-lockd | `src/objlock.c`, lock sidecars, version guard; `l2_publish`/`l2_point`/`resolve_current`; `src/lockd.c`, `src/lockc.c` | `test_e2e_objlock.sh`, `test_e2e_immutable.sh` |
| bucket policies | `src/policy.c`, `src/json.c` | `test_policy`, `test_json`, `test_e2e_policy.sh` |
| CORS, website, lifecycle | `src/cors.c` (`route_cors_decorate`), `src/website.c` + `web_dispatch`, `src/lifecycle.c` | `test_e2e_cors.sh`, `test_e2e_website.sh`, `test_e2e_lifecycle.sh` |
| quotas | `q_*` in `src/store_fs.c` | `test_e2e_quota.sh` |
| scrub | `src/scrub.c`, `store_scrub_file` | `test_e2e_scrub.sh` |
| reflink, dedup, compression | `clone_range`, `store_writer_clone`, `dedup_commit` (`cas/`), `set_compr_flag` | `test_e2e_reflink.sh` |
| SSE-C | `src/ssec.c`, writer/reader transform in `src/store_fs.c` | `test_ssec`, `test_e2e_ssec.sh` |
| native TLS | `src/tls.c`, `conn_io_*` in `src/conn.c` | `test_e2e_tls.sh` |
| admin API | `src/admin.c` | `test_e2e_admin.sh` |
| audit log, throttling | `src/audit.c` | `test_e2e_audit.sh` |
| logging, rotated log files | `src/log.c` (`log_msg`, `logfile_t`: one `write()` per line, size rotation, SIGHUP reopen) | `test_log`, `test_e2e_logs.sh` |
| replication | `src/repl.c` (journal, workers, admin endpoints, backfill, `repl_scrub_repair`); store hook `store_set_change_hook`; `store_repair_object` | `test_repl`, `test_e2e_repl.sh` |
| outbound S3 client, SigV4 signing | `src/s3client.c`; `sigv4_sign` / `req_view_t` in `src/sigv4.c` (shared canonicalisation with the verifier) | `test_sigv4`, `test_e2e_s3client.sh` (driver `tests/s3c_cli.c`) |
| seccomp | `src/sandbox.c` (`ALLOW[]`), `tests/tools/seccomp_profile.sh` | `test_sandbox`, every e2e suite (a SIGSYS is reported) |
| credentials file | `parse_and_add_cred`, `load_credentials_file` in `src/main.c` | `test_credfile` (seam: `FS3_MAIN_TESTING`) |
| dedup estimator | `src/dedup_estimate.c` (standalone; mirrors the header format, keep in sync) | `test_e2e_dedup_estimate.sh` |
| Synology package and tile | `packaging/synology/`; conf schema in `lib/fs3-conf.sh` (shared by `scripts/start-stop-status` and `ui/index.cgi`) | `test_ui_cgi.sh`, `test_spk_scripts.sh` |

## Rules the code depends on

Don't quietly undo these.

**Threads and locks**
- One event-loop thread owns every `conn_t`, all parsing, auth and
  routing. Socket I/O is non-blocking and epoll is level-triggered. Each
  readable event reads at most `CONN_READ_BUDGET` (256 KB) before
  yielding, so one fast uploader can't starve the others.
- Blocking store work (PUT/part commit, MPU complete, copies) runs as
  jobs on `src/iopool.c` (`--io-threads`, default 4; 0 runs them inline).
  - The conn parks in `CST_WAIT_JOB`.
  - A job's `run()` touches only what the job owns. Its `done()` runs back
    on the loop through an eventfd.
  - A disconnect orphans the job (`job->conn = NULL`), which still
    completes.
- Background passes (lifecycle, scrub) are scheduled from the loop's 1 s
  tick and run on a worker.
- **Lock order:** a key stripe lock (`key_lock(hex)`, 256 stripes) comes
  before `ns_mu`, and you never hold two stripe locks. Every multi-step
  mutation of one key holds its stripe.
  - `ns_mu` covers namespace steps (bucket create/delete, MPU directories,
    part renames).
  - `q_mu` (quota counters) and `cfg_mu` (sidecar cache) are leaves: take
    nothing while holding them.
  - Never hold a lock across fsync of object data.
- The store's change hook (replication) runs under the key's stripe
  lock: it appends one journal record with `write()` and takes only the
  replication mutex, a leaf. Nothing in it may take a store lock (it
  reads the bucket meta file, which needs none) or do network I/O. Any new path that changes a key's current state
  must call `notify_change()` before releasing the stripe.
- **Committed object files are never modified in place.** Writes go
  tmp → fsync → rename → fsync(parent). Versioning uses `link()`, and lock
  immutability only sets a flag. Readers rely on this and take no locks,
  and so will block dedup (`docs/block-dedup-plan.md`).

**Lifetimes**
- `conn_t` is per connection. `s3_store_t`, `sigv4_verifier_t` and the
  iopool live for the whole server. Never free `c->store` in
  `conn_destroy`.
- Shutdown order: `server_destroy` closes conns, then `iopool_destroy`
  (drains jobs), then `store_close`.
- Credential reloads build a new set and swap it in
  (`sigv4_swap_creds`). Identities are copied out at verify time
  (`sigv4_verify_id`), so a reload during a request can't free them.
- The seccomp filter is installed at the end of startup, and the worker
  pool and the replication threads are created *after* it (end of
  `server_create`) so they inherit it. Keep that order.
- Shutdown destroys replication after the iopool (its last commits still
  feed the journal) and before `store_close`.

**Request handling**
- `s3_str_t` (`p`, `n`) is the string type everywhere; helpers are in
  `include/s3.h`. Short-lived allocations go in the per-request arena
  (`scratch_alloc(c, n)`).
- Extra response headers go through `conn_add_header()`, and are spliced
  into whatever head is built. Don't add parameters to the head builders.
- `Expect: 100-continue` is answered in `cb_on_headers_complete`.
  Without it, botocore stalls 1 s per upload.
- Unauthenticated paths (CORS preflight, website) read bucket config
  with `store_sidecar_get_ttl` (1 s, negative entries cached), so there
  is no per-request disk I/O and no bucket enumeration by timing.
- Values that become paths are validated first: bucket names
  (`store_valid_bucket_name`), version ids (`store_vid_parse`), upload
  ids and user names (`[A-Za-z0-9._@-]`).
- Metadata values are echoed into response headers, so CR, LF and NUL
  are refused on write *and* re-checked on read.

**Store**
- **Quota accounting:** every key mutation measures `key_usage()` before
  and after, under its stripe, and charges the delta. A new path that
  adds or removes files in `data/`, `versions/` or `mpu/` must do the
  same, or go through `delete_locked` or a writer commit. Writers own
  their reservation, and `writer_free` releases it.
- **Writer byte counts:** `data_written` is plaintext (quota,
  `data_size`); `stored_written` is what's on disk (`stored_size`, part
  records). A new path that feeds a writer must advance both (see
  `writer_feed`, `store_writer_clone`).
- **Layout 2** (Object Lock buckets): `data/<hex>` is a symlink into
  `versions/`.
  - Open current objects with `open_cur()`, never plain `open()` on a data
    path.
  - `vdir_list()` leaves the current entry out, so "versions dir =
    noncurrent" holds in both layouts.
  - Version files are unlinked through `unlink_version_file()`, the
    fs3-lockd hook.
- Per-bucket caches are keyed by bucket **id**, not name, so a deleted
  and re-created bucket never inherits stale config or grants.
- Every sidecar is written tmp → fsync → rename → fsync(dir), and startup
  recovery removes its leftover temp files.
- No database, no index: the files are the source of truth, and listing
  walks the filesystem. That is fine well below 10⁶ objects per bucket.

## How to extend

**A new S3 operation**
1. Add an `s3_action_t` in `include/action.h` and its row in
   `src/action.c` (IAM name, permission, owner flag). The startup check
   fails if you forget.
2. Classify it in `route_classify` (method, path shape, subresource).
   Anything unrecognised must stay 501.
3. Write the handler in `src/route.c`, with response builders in
   `src/response.c`. Use `conn_add_header()` for extra headers.
4. Add e2e tests that use botocore or the AWS CLI as the oracle.

**A new store operation:** declare it in `include/store.h` with a doc
comment and implement it in `src/store_fs.c` (`s3_err_t` return,
`s3_str_t` inputs). Respect the lock order and quota accounting above.
Add a `t_xxx()` case to `tests/test_store.c`.

**A new error code:** add it to the enum in `include/s3.h` and to
`ERR_TABLE` in `src/response.c` (HTTP status, S3 code, message). It is
counted in `fs3_errors_total` automatically.

**A new per-object field:** add a TLV type (`[u16 type][u32 len][bytes]`)
rather than changing the fixed header. Readers skip unknown types and
copies preserve them, so this is not a migration. If the fixed header
really has to change, bump `OBJ_SCHEMA`, keep reading the old schemas,
add a fixture under `tests/fixtures/`, call it out as one-way in
`packaging/synology/CHANGELOG.md`, and update `src/dedup_estimate.c`,
which mirrors the header.

**A new parser** (XML config, JSON, header format, sidecar) gets a fuzz
target in the 50,000-iteration run.

**A new syscall at runtime:** add it to `ALLOW[]` in `src/sandbox.c`,
with argument filters where it makes sense, and run
`make seccomp-profile`. Build the profile from the static Synology binary
too; glibc versions differ (`open` vs `openat`, `stat` vs `newfstatat`).

**A new CLI option:** add it to `--help` and the README's command-line
reference. If it matters on a NAS, add one line to the schema in
`packaging/synology/lib/fs3-conf.sh` (key, type, default = fs3's default,
section, label, help) and its flag mapping in `fs3_conf_args`. The tile's
settings form and the start script pick it up from there. Never map a
conf value to a file path: features that need a file use a fixed name in
the package folder. Extend `tests/test_spk_scripts.sh`.

**The DSM tile** (`ui/index.cgi`) gates every request on DSM sign-in plus
the `administrators` group before anything else runs. Keep new output
and actions behind that gate, behind the CSRF token for POSTs, and use
fixed message codes (never reflect input).

## Gotchas

- `t_commit_races_bucket_delete` in `tests/test_store` (a tight
  two-thread race on `ns_mu`) occasionally flakes under DEBUG. It is
  known and reproduces on unmodified `main`. Rerun before chasing it.
- `set -eu` scripts die when `grep -c` finds no match (exit status 1).
  Append `|| true` to counting expressions.
- Start a server in the background, then poll until it answers before
  sending requests; the e2e scripts' `start()` helpers do this.
- If `make test` output looks truncated, run the suites individually.
  Each one is standalone.
- On DSM (kernel 3.10, no `getrandom`), importing `awscrt` can print an
  entropy warning to stdout and break test parsing. The signing helpers
  set `sys.modules["awscrt"] = None` there. More NAS-specific fixes are
  in the runbook's troubleshooting table.

## History, briefly

- **Phases 0–8:** epoll server, filesystem store, S3 protocol, SigV4
  header, body hash and chunked modes, multipart, service listing, MPU GC.
- **Phases 9–12:** Range, bulk delete, copy, ACL stubs, health, the
  credentials file, disk-full handling, startup recovery, resource
  bounds, metrics, the SPK watchdog, per-user isolation, the DSM tile.
- **Gap closure:** strict routing and `authz`, schema 3, trailer SigV4
  and checksums, presign, grants, CORS, lifecycle, website, native TLS,
  versioning, policies, Object Lock, admin API, audit log.
- **Round 2:** schema 4, part records and ETag checks, ListParts,
  UploadPartCopy, metadata, ListObjectsV2, quotas, scrub, key hygiene,
  seccomp, reflink, dedup, compression, SSE-C, layout 2 and fs3-lockd.
- **Since:** log rotation, the TLS build in the SPK, bucket replication
  (outbound S3 client, journal, backfill, self-healing scrub). Plan and
  deviations: `docs/plan-logs-replication-compat.md`.

The design plans for the last two rounds lived outside the repo. The
code and this file are the reference now.
