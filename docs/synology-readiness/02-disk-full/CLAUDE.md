# CLAUDE.md — disk-full / ENOSPC handling

> **STATUS: DONE (2026-06-10).** ENOSPC/EDQUOT map to
> `S3_ERR_INSUFFICIENT_STORAGE` (507) via `map_io_err()` in
> `src/store_fs.c`, applied at every write/pwrite/fsync/mkdir/rename in
> the PUT, MPU-part, MPU-initiate, and MPU-complete paths. Temp cleanup
> audited; tested via `s3_store_write_hook`/`s3_store_fsync_hook` test
> seams (four new tests in `tests/test_store.c`). The early statvfs
> check exists as `--min-free-bytes` since Phase 11. Not done: the
> loopback-filesystem integration test (the unit-test seam was chosen
> instead, as suggested for portability).

**Problem:** fs3 does not distinguish "the disk is full" from "something
broke internally." Both surface as `S3_ERR_INTERNAL` → HTTP 500. Worse,
the behavior on a mid-PUT `ENOSPC` is untested: it may leave an orphaned
temp file, miscount sizes, or confuse the client into retrying forever.

**Why it matters here specifically:** a NAS is a finite volume that
*will* fill up — that's its job. A storage server that behaves
unpredictably when full is a data-integrity hazard, not a cosmetic bug.
This is the single highest-priority gap for the NAS context.

## Current state (real code)

The write loop is `store_put_write` in `src/store_fs.c` (~line 482):

```c
ssize_t r = write(w->fd, p, left);
if (r > 0) { ... continue; }
if (r < 0 && errno == EINTR) continue;
LOG_W("put_write: %s", strerror(errno));
return S3_ERR_INTERNAL;          // <-- ENOSPC lands here, undifferentiated
```

`store_put_commit` (~line 500) does the durable sequence: `fsync(fd)` →
`rename(tmp_path, path)` → `fsync_dir(parent)`. Each failure also returns
`S3_ERR_INTERNAL`. Note `fsync` can return `ENOSPC` too (delayed
allocation), so the commit path needs the same treatment as the write
path.

`writer_free` (~line 401) unlinks `tmp_path` if it's still set, so the
*happy* abort path already cleans up the temp file. The question is
whether every error path actually reaches `writer_free` — trace each
`return S3_ERR_*` in the writer functions and confirm.

Multipart parts go through the same writer (`store_mpu_part_begin` hands
back an `s3_writer_t`), so fixing the core write path fixes parts too.

## Approach

1. **Add `S3_ERR_INSUFFICIENT_STORAGE`** to the enum in `include/s3.h`
   and to `ERR_TABLE` in `src/response.c`. S3's wire code for this is
   `InsufficientStorage` / HTTP 507 (some clients expect 500 with a
   `ServiceUnavailable`-style body; check what botocore tolerates and
   pick the mapping that makes `aws s3 cp` retry sanely or fail clearly
   rather than hang).

2. **Map `errno == ENOSPC` (and `EDQUOT` for quota'd volumes)** in both
   `store_put_write` and `store_put_commit` to the new code. Everything
   else stays `S3_ERR_INTERNAL`.

3. **Audit temp-file cleanup on every error path.** The invariant to
   guarantee: if a PUT does not commit, no `tmp/` file survives. Add a
   test that fills a small loopback filesystem and confirms `tmp/` is
   empty afterward.

4. **Consider an early size check.** If the request carries
   `Content-Length` (`c->req.content_length_hint` in conn.c), fs3 can
   `statvfs` the data volume and reject up-front with the storage error
   instead of writing until it dies. This is an optimization, not a
   correctness requirement — the mid-write handling above is the real
   fix — but it gives a clean 507 before wasting I/O.

## Hookpoints

- `src/store_fs.c`: `store_put_write`, `store_put_commit`, `writer_free`,
  `fsync_dir`, `tmp_open`
- `include/s3.h`: error enum
- `src/response.c`: `ERR_TABLE`
- The store struct's `tmp_dir` field is `s->tmp_dir` (= `ROOT/tmp`)

## How to test

The robust way is a small full filesystem you control:

```sh
# 64 MB loopback ext4, mounted, used as fs3 root
dd if=/dev/zero of=/tmp/tiny.img bs=1M count=64
mkfs.ext4 -q /tmp/tiny.img
mkdir -p /tmp/tinymnt && mount -o loop /tmp/tiny.img /tmp/tinymnt   # needs privilege
./fs3 -p 19400 -d /tmp/tinymnt &
# PUT objects until it fills, assert the failing PUT returns the storage
# error (not 500/hang), then assert /tmp/tinymnt/tmp/ is empty.
```

If loopback mount isn't available in the sandbox, simulate by making the
write target a small `tmpfs` (`mount -t tmpfs -o size=8m`), or by a
unit-test seam: add a test-only hook that makes `write()` return ENOSPC
after N bytes (function pointer the test can override). The unit-test
seam is more portable across the sandbox's privilege limits.

Add to `tests/test_store.c`:
- `t_put_enospc_returns_storage_error` — writer hits ENOSPC, returns the
  new code, no temp file left behind
- `t_put_enospc_midstream_cleanup` — partial write then ENOSPC, `tmp/`
  empty after

## What "done" looks like

- A full volume produces a clear `InsufficientStorage`/507 (or chosen
  mapping), never a hang and never a silent partial object.
- After any failed PUT, `ROOT/tmp/` contains no orphan files.
- Multipart part uploads inherit the same behavior (same writer).
- Tests cover both the write-path and commit-path ENOSPC.
- Clean under ASan + UBSan.

## Traps

- **`fsync` is where delayed-allocation ENOSPC actually surfaces.** A
  `write()` into page cache can succeed; the ENOSPC appears only at
  `fsync`/`rename`. Don't fix only the write loop and call it done.
- **Don't leave a zero-length committed object.** If `fsync` fails after
  a successful rename, you have a live but empty/partial file. Order is:
  fsync the data *before* rename, so a failed fsync never reaches the
  live tree.
- **`EDQUOT` ≠ `ENOSPC`** but both mean "can't store this." Handle both.
- **Don't `statvfs` on every write** — only once up front if you add the
  early check. Per-write statvfs would wreck throughput.
