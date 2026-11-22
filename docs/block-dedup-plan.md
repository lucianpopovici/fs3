# Block-level dedup through reflinks — implementation plan

Status: **roadmap, not implemented.** Decide with data first: run
`fs3-dedup-estimate` on the real data root (see README, "Tools"). If block
dedup saves less than about 10% beyond whole-object dedup, stop here.

This is "option 2" from the Garage comparison: share identical blocks
*between* object files through the filesystem, instead of adopting a
content-addressed block store. Every object file stays complete and
self-describing, sendfile and Range keep working, and recovery is still
"read the files".

---

## 1. Scope and non-goals

In scope:
- Background, opt-in job that finds identical blocks across committed
  object files and makes them share extents with `FICLONERANGE`.
- Btrfs (the DS1515+) and XFS. Nothing happens on ext4.
- Owner scope by default (as `--dedup owner`), optional global scope.

Not in scope:
- Inline (at PUT time) block dedup: would add hashing and index lookups to
  the hot path on a 2 GB Atom. Whole-object dedup stays inline.
- Content-defined chunking. Clones need 4 KiB-aligned offsets in both
  files, so cut points would have to land on block boundaries anyway and
  the shift resistance that makes CDC worthwhile is lost.
- A chunk store, manifests or refcounts in fs3.

What it can and cannot find (the estimator measures exactly this):
- Finds: near-identical VM images and ISOs, append-grown files, same-size
  in-place edits, multipart uploads that reuse parts, version histories
  of large files with local changes.
- Misses: data shifted by a non-multiple of 4 KiB, client-side encrypted
  or deduplicated archives (restic, kopia, borg), SSE-C objects (random
  salt per object), media.

---

## 2. The invariant this relies on

**Committed object files are never modified in place.** Every write
goes tmp → fsync → rename; the header `pwrite` happens before the rename;
versioning uses `link()`; lock immutability only sets a flag. Block dedup
rewrites *extents* of committed files but never their *bytes*, so readers
(sendfile, Range, scrub) see the same content before, during and after a
clone.

Make the invariant explicit before starting: a comment at the top of
`store_fs.c`, and a debug-build check in the store that no code path
opens a committed object with `O_WRONLY`/`O_RDWR`. Block dedup is the only
exception and opens files `O_WRONLY` solely as an ioctl target.

---

## 3. Design

### 3.1 Module and entry points

- `src/bdedup.c` / `include/bdedup.h`, modelled on `src/scrub.c`:
  `bdedup_create(cfg)`, `bdedup_tick(now)` from the 1 s loop tick,
  `bdedup_set_pool(iopool)`, `bdedup_request()`, `bdedup_status_json()`,
  `bdedup_metrics()`, `bdedup_stop()`.
- The pass runs on **one iopool worker**, never on the event loop.
- Same module also builds a standalone `fs3-bdedup` CLI
  (`--dry-run`, `--apply`, `--bucket`, `--json`) for one-off runs and for
  testing against a copy of a data root.

### 3.2 Eligibility (checked per file, cheap checks first)

- Regular file under `data/` or `versions/`; symlinks (layout 2) skipped,
  their targets are walked under `versions/`.
- One visit per inode (link-aside makes two names for one inode).
- Header parses; `header_size % 4096 == 0` (payload block-aligned).
- Not a delete marker; `S3_OBJF_SSEC` and `S3_OBJF_ZSTD` clear.
- Payload ≥ 2 blocks (smaller objects are whole-object dedup's job).
- Header `mtime_ms` older than `--bdedup-min-age` (default 1 h), so
  short-lived objects aren't worked on.
- `FS_IOC_GETFLAGS`: skip as **destination** if `FS_IMMUTABLE_FL` (COMPLIANCE
  under `--lock-immutable`) — it may still be a **source**. Skip entirely
  if `FS_COMPR_FL` (see 3.6).

### 3.3 Index: external sort, bounded memory

The DS1515+ cannot hold an in-memory index (1 TB at 128 KiB is ~8 M
blocks). Each pass:

1. **Scan:** hash every block of eligible files (xxHash64 over the block,
   length mixed in; block size `--bdedup-block`, default 128 KiB, power of
   two from 64 KiB to 1 MiB). Append fixed 16-byte records
   `{hash, file_no, block_no}` to run files under
   `<root>/bdedup/pass-<n>/run-NNNN` (each run sorted in memory before it is
   written, run size bounded by `--bdedup-mem`, default 64 MiB). A
   `files` table maps `file_no` → relative path, inode, size, header
   mtime, owner scope.
2. **Merge:** k-way merge of the runs, streaming groups of equal
   `(scope, hash)` to the apply step. Global scope just drops `scope` from
   the key.
3. **Apply:** for each group, the canonical copy is the oldest block
   (header mtime, then path). Others are clone candidates.
4. Delete `pass-<n>/` at the end; keep only a small `state` file (pass
   id, phase, cursor, counters) so a restart resumes the current phase.

Hashes only select candidates; bytes are always compared before cloning,
so a 64-bit collision costs one comparison, never data.

### 3.4 Apply step, per destination extent

On Btrfs, space is freed only when an **entire extent** is no longer
referenced. Cloning one 128 KiB block into the middle of a 100 MiB
extent saves nothing. So the unit of work is a destination extent, not a
block:

1. `FIEMAP` the destination file. For each extent, collect the candidate
   blocks that fall inside it.
2. Matched fraction ≥ `--bdedup-extent-threshold` (default 50%)?
   - **No:** skip the extent (no gain).
   - **Yes:** for the unmatched ranges of that extent, copy their bytes
     into a private temp file under `tmp/` and clone them back over the
     same ranges (identical content, new extents). Then clone each matched
     block from its canonical source. The old extent becomes unreferenced
     and is freed. (This is the technique bees uses.)
3. Every clone is preceded by:
   - open both files `O_NOFOLLOW`; `fstat` and compare inode, size and
     header mtime with the `files` table (a replaced object has a new
     inode: skip it);
   - byte-compare the source and destination ranges (`same_bytes()`
     already exists in the store for whole-object dedup).
4. No key stripe lock is needed: contents never change (section 2), and a
   file unlinked mid-way just loses its extents with its last reference.
   Holding the fds keeps both inodes alive during the operation.
5. A crash between clones leaves a mix of shared and unshared ranges with
   identical content. Recovery: nothing to repair; delete stale
   `bdedup/pass-*` and `tmp/` files at startup (extend the existing temp
   cleanup).

On XFS (per-block refcounts) steps 1–2 are unnecessary: clone matched
blocks directly. Detect with `statfs` (`XFS_SUPER_MAGIC`).

### 3.5 Throttling and resource use

- `--bdedup-rate` (default 20 MiB/s of reads), idle I/O priority for the
  worker (`ioprio_set`), `posix_fadvise(DONTNEED)` after each file, same
  load-based pause as the scrub.
- Schedule: `--bdedup-interval-days` (default 0 = off; suggest 7), never
  overlapping a scrub pass (one background pass at a time).
- Temp space: the scan runs need 16 bytes per block (≈ 128 MiB per TB at
  128 KiB). Refuse to start a pass if free space is below
  `min_free_bytes` plus the expected run size.

### 3.6 Interactions

| Feature | Rule |
|---|---|
| Whole-object dedup (`cas/`) | Unchanged. Pool files are not walked; objects already sharing a pool extent have identical blocks and are skipped by the inode/extent check (same physical extent → nothing to do). |
| `--fs-compress` | v1 skips `FS_COMPR_FL` files: compressed extents are ≤ 128 KiB but start at file offset 0, so payload blocks (offset 4096) straddle two extents and cloning pins both. Also the open DSM 3.10 dedup+compression issue. Revisit with FIEMAP-aligned matching later. |
| Object Lock / `fs3-lockd` | Immutable files are sources only. GOVERNANCE versions (not immutable) are fair game: content is unchanged. |
| SSE-C | Never eligible. |
| Quotas | Count logical bytes, as today; unchanged. |
| Scrub | Verifies logical content and payload CRC; unaffected. Add a check that a pass leaves every scrubbed object's CRC unchanged in tests. |
| Versioning | Noncurrent versions are the main win (large files with local edits). Link-aside inodes are visited once. |
| Lifecycle / delete | Can delete a file mid-pass; the fds keep the inode until the clone finishes. |
| seccomp | Add `FIEMAP`, `FS_IOC_GETFLAGS` and the clone ioctl to the argument filter; `ioprio_set` to the allowlist. Rerun `make seccomp-profile`. |
| Admin API | `POST /v1/bdedup` (start), `GET /v1/bdedup` (phase, progress, last result). |

### 3.7 Security

- Owner scope by default; `--bdedup-scope global` documented as
  single-tenant only. Background sharing gives clients no timing signal,
  and quotas stay logical, so neither is an oracle.
- The job never builds paths from object contents; paths come from the
  directory walk and are re-validated (`O_NOFOLLOW`, inode check).
- All new parsers (`files` table, run files, `state`) are fuzzed, and a
  malformed one aborts the pass instead of guessing.

### 3.8 Observability

Metrics: `fs3_bdedup_passes_total`, `fs3_bdedup_bytes_scanned_total`,
`fs3_bdedup_blocks_cloned_total`, `fs3_bdedup_extents_rewritten_total`,
`fs3_bdedup_bytes_freed_estimate`, `fs3_bdedup_skipped_total{reason}`,
`fs3_bdedup_last_success_timestamp`. One audit-log line per pass.
DSM console: last pass and estimated savings.

---

## 4. Phases

| Phase | Deliverable | Exit criterion |
|---|---|---|
| 0 | `fs3-dedup-estimate` (done) | ≥ 10% estimated saving on real data, else stop |
| 1 | Invariant check (section 2) + `fs3-bdedup --dry-run` (scan, sort, merge, report extents that would be freed) | Dry-run figures within 10% of the estimator on the same data; bounded memory on the NAS |
| 2 | `--apply` in the CLI on XFS and Btrfs, with the extent rewrite | All content byte-identical after a pass (SHA-256 of every object before/after); `btrfs filesystem du` shows the expected shared bytes |
| 3 | In-process scheduler, admin API, metrics, seccomp updates, DSM console | Full e2e suite green with a pass running concurrently |
| 4 | Optional: compressed files via FIEMAP-aligned matching | Only if phase 0 numbers justify it |

---

## 5. Tests

- `tests/test_e2e_bdedup.sh`, needs `FS3_REFLINK_DIR` (loopback Btrfs and
  XFS images in CI):
  - near-identical 64 MiB objects: after a pass, shared bytes reported by
    `btrfs filesystem du` match; free space increased;
  - every object's SHA-256 and payload CRC unchanged; scrub pass clean;
  - an object overwritten, deleted or version-promoted mid-pass: no error,
    no corruption;
  - `kill -9` in each phase, restart: pass resumes or restarts, no stray
    files after startup cleanup;
  - immutable (COMPLIANCE) file used as source, never as destination;
  - `FS_COMPR_FL` and SSE-C objects skipped; ext4: job refuses to start
    with a clear message;
  - owner vs global scope;
  - `--bdedup-mem 16m` on a data set needing several runs (external sort).
- Unit tests: run-file writer and merge (including equal hashes across
  runs), extent planning against synthetic FIEMAP results, threshold
  decisions.
- Fuzz: `files` table, run files, `state`.

---

## 6. Open questions

- Extent threshold default (50%) and block size default (128 KiB): pick
  from estimator runs at 64k/128k/256k on the real data.
- Whether DSM's Btrfs (3.10) handles `FICLONERANGE` into a file that
  another process is reading via sendfile without stalls; measure in the
  DS1515+ run (section D7 of `docs/AGENT-BUILD-AND-DS1515-TEST.md`).
- Whether to fold the existing whole-object pool into this job later
  (one mechanism instead of two). Not before phase 3 is stable.
