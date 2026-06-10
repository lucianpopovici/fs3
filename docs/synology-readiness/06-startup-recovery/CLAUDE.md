# CLAUDE.md — startup recovery scan

**Problem:** there's no integrity pass on startup. After an ungraceful
shutdown mid-write, two kinds of debris can remain:
1. Orphaned temp files under `ROOT/tmp/` (a PUT that wrote but never
   renamed).
2. Interrupted multipart staging dirs under `ROOT/mpu/<bucket>/<id>/`
   (uploads that never completed or aborted).

The periodic MPU GC (phase 8) eventually reaps stale uploads, but only
after the TTL (24h default) and only for multipart — not for orphaned
single-PUT temp files.

**Why it matters here specifically:** the DS1515+ uses an Intel C2538,
part of the C2000 series with the well-documented LPC clock erratum that
makes these boxes prone to *sudden* death (not graceful shutdown). So
"what's on disk after an unclean stop" is a more frequent question here
than on typical hardware.

## Current state

- `store_open` (`src/store_fs.c`, ~line 243) creates the directory tree
  but does **not** scan or clean anything existing.
- `tmp_open` uses `mkstemp` under `s->tmp_dir` (`ROOT/tmp`). A crash
  between `tmp_open` and `rename` leaves a file there forever.
- `writer_free` unlinks the temp file on the abort path, but a *crash*
  never calls `writer_free`.
- MPU GC (`store_mpu_gc`) handles stale staging dirs by TTL, on a timer
  — not at startup, and not for `tmp/`.

## Approach

Add a `store_recover(s3_store_t *s)` called once at the end of
`store_open`, before the server starts accepting:

1. **Sweep `ROOT/tmp/`.** Every file there is by definition an
   uncommitted write (commits rename *out* of tmp). Unlink them all.
   They can never be part of a live object. This is safe and
   unconditional.

2. **Optionally sweep very old MPU staging dirs immediately** rather
   than waiting for the first timer tick — call `store_mpu_gc` once at
   startup with the configured max-age. Not strictly recovery (those
   uploads aren't corrupt, just stale), but startup is a natural moment.
   Keep it optional/configurable; aborting in-flight uploads that a
   client is mid-way through resuming would be wrong if the TTL is
   short.

3. **Do NOT touch `data/`.** Committed objects are atomic by
   construction (fsync-before-rename). There is no such thing as a
   half-committed object in the live tree, so a data-tree scan would be
   pointless work and a chance to introduce bugs. Resist the urge to
   "verify" the data tree on every boot — it's potentially millions of
   files and the invariant already holds.

4. **Log what was reclaimed** at INFO level so the admin sees
   "recovered N orphaned temp files (M bytes)" after a crash.

## Hookpoints

- `src/store_fs.c`: new `store_recover`, called from `store_open` after
  the tree is created; reuse `rm_rf`/`unlink` helpers already present.
- `include/store.h`: declare `store_recover` (or keep it static and call
  internally — internal is cleaner since it's not part of the public
  contract).
- The `tmp_dir`, `mpu_dir` fields on the store struct.

## How to test

In `tests/test_store.c`:
- `t_recover_clears_orphan_tmp` — manually drop a file into `ROOT/tmp/`,
  call `store_open` (or the recover function), assert `tmp/` is empty and
  the live data tree is untouched.
- `t_recover_preserves_committed` — write and commit an object, drop an
  orphan temp file, recover, assert the committed object still reads back
  byte-for-byte and the orphan is gone.
- `t_recover_leaves_fresh_mpu` — start a multipart upload, recover with a
  long TTL, assert the staging dir survives (recovery must not nuke
  in-flight uploads).

Crash simulation for realism: spawn fs3, start a PUT, `kill -9` mid-body,
restart, assert `tmp/` was cleaned and no partial object appears in
listings.

## What "done" looks like

- Startup unconditionally clears `ROOT/tmp/` and logs the count.
- Committed data is never touched by recovery.
- In-flight (non-stale) multipart uploads survive a restart.
- Tests cover orphan-tmp cleanup, committed-data preservation, and
  fresh-MPU survival.
- Clean under ASan + UBSan.

## Traps

- **Don't conflate "stale" with "orphaned."** A tmp file is *always*
  orphaned (safe to delete). An MPU staging dir is only stale if older
  than TTL — a client may be actively uploading parts to it. Recovery
  must treat them differently.
- **Don't scan `data/`.** Millions of files, no benefit, real risk.
- **Concurrency:** recovery runs before `accept`, single-threaded, so
  there's no race with live writers — but only if you call it from
  `store_open` *before* the server's accept loop starts. Don't wire it
  to run on a timer alongside live traffic.
- **`mkstemp` temp names are unpredictable** — sweep by "everything in
  `tmp/`," not by a name pattern.
