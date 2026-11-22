# Plan: log rotation, bucket replication, backup-tool compatibility

Status: item 1 (log rotation) **implemented**; items 2 and 3 are roadmap.
Each item is sized for its own branch and PR. Section 1.5 (the tile
sign-in check on hardware) is still open.

| # | Item | Size | Why first |
|---|---|---|---|
| 1 | Log rotation (+ verify the tile sign-in on hardware) | S | Unbounded logs eventually fill the volume; readiness brief 09 |
| 2 | Asynchronous bucket replication | L | The one capability Garage and MinIO have that fs3 lacks; enables self-healing scrub |
| 3 | Compatibility matrix with real backup tools | M | Most homelab S3 traffic is backups; finds the bugs users would hit |

House rules as always (`CLAUDE.md`): release and ASan/UBSan green, every
new parser fuzzed, every sidecar written tmp → fsync → rename →
fsync(dir), new options in `--help`, the README reference and the SPK
schema (`packaging/synology/lib/fs3-conf.sh`).

---

## 1. Log rotation

### 1.1 Current state

- `src/log.c` writes leveled lines to **stderr** only.
- The SPK's watchdog appends fs3's stderr to `fs3.log` (`watchdog "$@" >>
  "${LOG_FILE}"` in `start-stop-status`). Nothing ever truncates it.
- `src/audit.c` opens `--audit-log` with `O_APPEND` and reopens it on
  SIGHUP (`audit_reopen()` from the SIGHUP handler in `main.c`), but
  nothing triggers that rotation on DSM.
- Readiness brief 09 (log rotation) described the problem; it was removed
  once this item was implemented.

### 1.2 Design

Make fs3 own both of its log files, with size-based rotation inside the
process. No external `logrotate` dependency (DSM ships its own, but
configuring it from a package is fragile and unsupported).

- New options:
  - `--log-file PATH`: write leveled logs to this file instead of
    stderr. Opened `O_WRONLY|O_APPEND|O_CREAT|O_CLOEXEC`, mode 0640.
  - `--log-max-size SIZE` (default 10M) and `--log-keep N` (default 5):
    applies to both `--log-file` and `--audit-log`.
- `src/logfile.c` (new), used by `log.c` and `audit.c`:
  - `logfile_t { int fd; char *path; uint64_t size; uint64_t max; int keep; pthread_mutex_t mu; }`
  - `logfile_write(lf, buf, n)`: under `mu`, `write()` the whole line
    (lines are short; loop on partial writes), add to `size`; if
    `size >= max`, rotate.
  - Rotate: `rename(path.(N-1) → path.N)` … `path → path.1`, then open a
    fresh `path`, swap the fd, close the old one. Renames are cheap and
    atomic; no compression in v1 (gzip on a 2 GB Atom while serving is
    not worth it; a later `--log-compress` could hand old files to the
    iopool).
  - On `ENOSPC` or any open failure: keep writing to the old fd, log
    once to stderr, retry rotation at most once a minute.
  - `logfile_reopen(lf)` for SIGHUP (external rotation still works).
- `log.c`: when a log file is set, format the line into a stack buffer
  and call `logfile_write`; otherwise keep today's stderr path.
  The `flockfile(stderr)` interleave protection becomes the logfile mutex.
- `audit.c`: replace its raw fd with a `logfile_t`. Audit lines stay one
  `write()` each, so a reader never sees a torn line.
- Early startup errors (before options are parsed, or when the log file
  can't be opened) still go to stderr, so the watchdog's `fs3.log`
  capture keeps working for "fs3 failed to start".
- seccomp: `rename` and `openat` are already allowed; re-run
  `make seccomp-profile` to confirm.

### 1.3 SPK

- Pass `--log-file "${VAR_DIR}/fs3.log"` always (fixed path, as with the
  other feature files). The watchdog redirects fs3's stderr to
  `fs3.start.log`, which only catches startup failures and is truncated
  at each start. The tile's crash-loop log tail reads both.
- Schema keys: `FS3_LOG_MAX_SIZE` (size, 10M) and `FS3_LOG_KEEP`
  (int 1–50, 5), section `ops`.
- The watchdog's own messages ("restarting to apply new settings") go to
  `fs3.start.log` too.
- Remove the "not rotated yet; watch its size" warning from the audit-log
  help text.

### 1.4 Tests

- `tests/test_e2e_logs.sh`: `--log-max-size 4K --log-keep 3` with
  verbose logging and a request loop. Expect exactly `fs3.log` plus
  `.1`–`.3`, none above 4K plus one line, and the newest content in
  `fs3.log`. The audit log gets the same check.
- Rotation while iopool threads log concurrently (ASan/TSan clean, no
  torn or interleaved lines: every line parses).
- Log directory made read-only mid-run: fs3 keeps serving and keeps
  writing to the old fd.
- `test_spk_scripts.sh`: `--log-file` passed; `fs3.start.log` truncated
  per start.

### 1.5 Also in this item: verify the tile sign-in on the DS1515+

Before more UI is built on it (item 3's object browser is a later
candidate), run the PR #9 hardware checks: admin → page, non-admin → 403,
no session → 403. If the SynoToken fallback doesn't work on DSM 7.1, fix
it here.

---

## 2. Asynchronous bucket replication

### 2.1 Scope

One-way, asynchronous replication of a bucket's changes to a bucket on
another S3 endpoint: a second fs3, Garage, MinIO/AIStor, Backblaze B2,
AWS S3. fs3 stays single-node; the replica is its off-site copy.

In scope (v1):
- PUT, multipart Complete, CopyObject, DeleteObject/DeleteObjects, delete
  markers, metadata and content type.
- Per-rule prefix filter.
- Existing objects: one-time backfill ("initial sync") on request.
- Retry with backoff, durable across restarts and crashes.
- Status visible per bucket (backlog, last error, lag), metrics, audit.
- **Self-healing scrub:** a corrupt object is re-fetched from the replica,
  verified against the stored ETag/CRC, and restored.

Not in v1: two-way/active-active, replication of version history
(only the current state is replicated; the remote bucket may have its own
versioning), Object Lock settings propagation, SSE-C objects (skipped:
fs3 doesn't have the key), bucket configuration (policy, CORS, lifecycle).

### 2.2 Configuration

AWS's `PutBucketReplication` XML is built around IAM roles and ARNs that
don't exist here, so replication is configured through the **admin API**
(and the DSM tile), not the S3 API.

- `PUT /v1/buckets/<b>/replication` with JSON:
  ```json
  { "endpoint": "https://s3.eu-central-003.backblazeb2.com",
    "region": "eu-central-003", "bucket": "nas-photos",
    "access_key": "…", "secret_key": "…",
    "prefix": "", "addressing": "path", "verify_tls": true,
    "deletes": true }
  ```
  `GET` returns it without the secret; `DELETE` removes it (queued work
  is dropped). `POST /v1/buckets/<b>/replication/sync` starts a backfill.
  `GET /v1/buckets/<b>/replication/status`.
- Stored in `buckets/<b>/replication.json`, mode 0600, keyed by bucket
  id like every other sidecar. The remote secret is a credential: it is
  never logged, never returned, and excluded from the audit log.
- Validation: endpoint `http(s)://host[:port]` only, with no userinfo,
  path or query. `http://` is accepted only for RFC 1918/loopback hosts,
  and only with `"allow_plain_http": true`. Remote bucket names pass
  `store_valid_bucket_name`.

### 2.3 Durable queue

- One append-only journal per bucket: `repl/<bucket-id>/queue`, records
  `{seq u64, op u8 (PUT|DEL), key, version_id, size, etag, mtime}` with a
  CRC32C per record. Written **inside** the same key-stripe critical
  section as the mutation, after the object commit is durable and before
  the lock is released (an `fdatasync` on the journal is batched: group
  commit every 10 ms or 64 records, so the hot path doesn't pay one fsync
  per PUT).
  - If fs3 crashes after the object commit but before the journal record
    is durable, the object would be missed. Close that gap at startup:
    the journal header records the last sequence and a high-water mtime;
    recovery scans objects newer than that mark (bounded walk) and
    re-queues them.
- A `cursor` file (tmp → fsync → rename) holds the last acknowledged
  `seq`. When everything up to the end of a segment is acknowledged, the
  segment is deleted (segments rotate at 16 MiB).
- **Coalescing:** the worker reads ahead and drops a record if a later
  record for the same key exists; a burst of overwrites replicates once.
- Quotas: journal bytes are fs3 metadata and don't count against bucket
  quotas, but `--min-free-bytes` applies.

### 2.4 Outbound S3 client (`src/s3client.c`)

fs3 has no HTTP client today. Build a minimal one:

- HTTP/1.1 over a blocking socket on an iopool worker (never the event
  loop), keep-alive per endpoint, timeouts on connect/read/write,
  redirects not followed.
- **TLS:** OpenSSL `SSL_connect` with certificate and hostname
  verification (`SSL_set1_host`), the system CA bundle, TLS 1.2+.
  - This needs libssl, which the SPK's non-TLS static build doesn't link.
    Either ship the SPK with `fs3-tls-static` (bigger binary, already
    builds and passes the TLS suite), or build replication only with
    `TLS=1` and say so. **Recommendation: switch the SPK to the TLS
    build;** B2/AWS targets need TLS anyway.
  - The DS1515+'s DSM CA bundle path (`/etc/ssl/certs/ca-certificates.crt`
    or Synology's own) must be confirmed on hardware; allow
    `--repl-ca-file`.
- **SigV4 signing:** today's canonical-request code is built around
  `conn_t` (`build_canonical_request(const conn_t *c, …)`). Refactor it
  into conn-independent functions (method, canonical URI, query, header
  list, payload hash → string-to-sign → signature) used by both the
  verifier and the client. The existing botocore vectors in `test_sigv4`
  then cover the client too.
- Uploads: `UNSIGNED-PAYLOAD` over TLS, payload SHA-256 over plain HTTP.
  Objects > 64 MiB use multipart (part size 16 MiB) with per-part retry.
  Body is streamed from the object file (`pread` loop; SSE-C excluded).
  Metadata TLVs become `x-amz-meta-*` and standard headers; the object's
  checksum is sent as `x-amz-checksum-*` when present, so the remote
  verifies it.
- DNS resolution with `getaddrinfo` on the worker; seccomp profile and
  `make seccomp-profile` updated (connect, outbound sockets, reading the
  CA bundle).

### 2.5 Worker

- `src/repl.c`, scheduled from the 1 s tick like lifecycle and scrub:
  - one worker per bucket with a replication rule, at most
    `--repl-workers` (default 2) running at once;
  - `--repl-rate` (default 20 MiB/s) shared across buckets, plus the
    same load-based pause as the scrub.
- Per record:
  - PUT: open the current version by id; if it changed or vanished, skip
    (a later record covers it). Upload, then compare the remote ETag with
    the local one (or the checksum for multipart). Mismatch → retry.
  - DEL: `DELETE` remotely (404 counts as success). Skipped if
    `deletes: false`.
- Errors: 4xx (except 408/429) are permanent for that record; record it
  in `repl/<id>/errors` (bounded ring) and continue. 5xx, timeouts and
  network errors retry with exponential backoff (1 s → 10 min) without
  advancing the cursor.
- **Backfill** (`/sync`): walk the bucket like the scrub, `HEAD` each key
  remotely, and queue a PUT when the remote is missing or its ETag or size
  differs. Resumable cursor, same throttling.

### 2.6 Self-healing scrub

- When `store_scrub_file` reports corruption and the bucket has a
  replication rule:
  1. `GET` the key from the remote into `tmp/`.
  2. Verify it against the **local** header's ETag/payload CRC (never
     trust the remote blindly).
  3. Under the key stripe lock, re-check that the corrupt file is still
     current, then rename the repaired file into place, preserving
     version id and metadata.
- Logged in `scrub/corrupt.log` as `repaired`; metric
  `fs3_scrub_repaired_total`.
- Never repairs from the remote when the remote copy doesn't verify.

### 2.7 Interactions

| Feature | Rule |
|---|---|
| Versioning | Only the current state is replicated. Deleting a noncurrent version locally does nothing remotely. |
| Object Lock | Locked objects replicate normally; remote retention is the remote's business. Deletes of locked versions never happen locally, so never replicate. |
| Lifecycle | Expirations are deletes and replicate (unless `deletes: false`, the usual choice for a backup target). |
| SSE-C | Skipped and counted (`skipped_ssec`). |
| Quotas | Not affected. |
| Dedup/reflink | Not affected (replication reads logical bytes). |
| Website, CORS, policy | Not replicated. |

### 2.8 Observability and UI

- Metrics: `fs3_repl_queue_depth{bucket}`, `fs3_repl_lag_seconds{bucket}`,
  `fs3_repl_bytes_total`, `fs3_repl_ops_total{op,result}`,
  `fs3_repl_errors_total`.
- Audit: one line per configuration change (secret redacted); per-object
  replication is not audited (too noisy), errors are.
- DSM tile: a *Replication* column in the bucket table (target, backlog,
  last error) and a form per bucket (endpoint, region, bucket, keys,
  prefix, deletes). The secret field is write-only.

### 2.9 Security

- The replication secret is the most sensitive thing fs3 stores besides
  the credentials file: 0600 sidecar, never echoed, redacted everywhere.
- SSRF: only admins can configure endpoints, and endpoints can't carry
  paths or userinfo. Optionally `--repl-allow-hosts` to pin targets.
- TLS verification on by default; turning it off needs
  `"verify_tls": false` *and* a private-range host.

### 2.10 Phases and tests

| Phase | Deliverable | Exit |
|---|---|---|
| a | Conn-independent SigV4 signing + `s3client.c` (PUT/GET/HEAD/DELETE/multipart), against fs3 itself in tests | Signatures match botocore vectors; uploads to a second fs3 and to MinIO in CI |
| b | Journal, cursor, worker, admin API, metrics | e2e below green |
| c | Backfill, self-healing scrub | e2e below green |
| d | DSM tile, SPK on the TLS build, docs | DS1515+ run replicating to B2 or a second box |

`tests/test_e2e_repl.sh` runs two fs3 instances (source and replica):
- PUT, overwrite, multipart, copy and delete arrive.
- A burst of overwrites coalesces.
- The replica goes down → backlog grows → it comes back → backlog drains
  in order.
- `kill -9` of the source mid-stream → no record lost after restart (the
  recovery scan).
- A permanent 403 is recorded and skipped.
- Backfill of a pre-existing bucket.
- Corrupt a local object → the scrub repairs it from the replica; a
  corrupt replica is refused.
- SSE-C skipped.
- `deletes: false` honored.
- The secret never appears in logs, the audit log or GET responses.
- Fuzz the journal record parser and the JSON config.

---

## 3. Compatibility matrix with backup tools

### 3.1 Goal

Prove, and keep proving, that the clients homelab users actually point at
fs3 work: create, list, restore, prune, verify. Fix what breaks. This is
mostly test infrastructure plus whatever bugs it finds.

### 3.2 Tools and scenarios

| Tool | Scenario | S3 features exercised |
|---|---|---|
| restic | init, backup 2 snapshots, check --read-data, restore, forget --prune | many small PUTs, listing, DELETE, Range GETs |
| rclone | sync, check --download, mtime preservation, server-side copy, `--s3-upload-cutoff` small | metadata (`x-amz-meta-mtime`), CopyObject, multipart |
| Kopia | repo create, snapshot, verify, maintenance | listing, conditional requests, deletes |
| Duplicati | backup, verify, restore | multipart, ListObjectsV2 |
| AWS CLI v2 | `s3 sync`, `s3api` versioning, object lock, presign | trailer checksums (default since 2025) |
| Synology Hyper Backup | S3-compatible destination, backup, integrity check, restore | real-world DSM client; versioned rotation |
| Veeam B&R (Community) | object storage repository with immutability | Object Lock (COMPLIANCE), versioning, `ListObjectVersions`, SOSAPI capacity file |

### 3.3 How

- `tests/compat/` with one script per tool. Each script:
  - starts a scratch fs3 (auth on, versioning per scenario);
  - runs the scenario;
  - checks the tool's own verification (`restic check --read-data`,
    `rclone check --download`, `kopia snapshot verify`, …) plus a
    byte-for-byte restore comparison;
  - prints `SKIP (tool not installed)` when the tool is missing.
- `make compat` runs them; not part of `make test` (slow, needs tools).
  CI job (once CI exists): a container with restic, rclone, kopia,
  duplicati CLI and AWS CLI pinned to versions; nightly.
- Variants for each tool:
  - plain HTTP and native TLS;
  - versioning on and off;
  - a bucket with Object Lock where the tool supports it;
  - restore after a forced fs3 restart in the middle of a backup (crash
    consistency as seen by the client).
- **Manual, recorded runs** for the GUI tools: Hyper Backup on the
  DS1515+ (pointed at fs3 on the same NAS and on a second box), and Veeam
  from a Windows VM. Results go in a new section of
  `docs/AGENT-BUILD-AND-DS1515-TEST.md`, the same way as the existing
  hardware run.
- **Veeam specifics:** Veeam probes capabilities through its Smart Object
  Storage API (`.system-*` objects with `system.xml`/`capacity.xml`). fs3
  needs nothing special for this to work (they're ordinary objects), but
  the run should confirm immutability is detected and enforced
  (COMPLIANCE retention set by Veeam, deletes refused before expiry).
- **Hyper Backup specifics:** confirm which signature mode and addressing
  it uses against a custom endpoint, and whether it needs
  `GetBucketLocation` or virtual-hosted addressing (fs3 is path-style
  only; if Hyper Backup insists on virtual hosts, that becomes a feature
  request with a host-based bucket resolver like the website listener's).

### 3.4 Output

- `docs/compatibility.md`: a table of tool, version, fs3 version and
  result, plus known caveats and the exact settings that work (endpoint
  form, region, addressing, checksum flags).
- Linked from the README features section.
- Every bug found gets a regression test in the regular e2e suites, so
  `make test` keeps catching it without the external tool.

### 3.5 Exit criteria

- restic, rclone, Kopia, Duplicati and AWS CLI scripted and green.
- Hyper Backup and Veeam recorded on hardware.
- Each failure either fixed (with a regression test) or documented with
  a workaround.

---

## Order and dependencies

1. **Log rotation:** independent, do first. The tile hardware check runs
   in parallel.
2. **Compatibility matrix:** cheaper than replication and may find bugs
   in the core paths replication depends on. Run its scripted part before
   replication phase b.
3. **Replication:** phase a (signing refactor and client) can start any
   time. Switching the SPK to the TLS build is a decision for phase d,
   but it affects packaging size and the seccomp profile, so settle it
   early.
