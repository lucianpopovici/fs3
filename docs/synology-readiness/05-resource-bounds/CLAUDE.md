# CLAUDE.md — resource bounds (body size, memory, concurrency)

**Problem:** fs3 caps concurrent connections but has no per-request
body-size limit and no bound on memory consumed by in-flight requests.
On a 2 GB-RAM box, a few large concurrent uploads — or one malicious
client — can exhaust memory or pin the single worker.

**Why it matters here specifically:** the DS1515+ ships with 2 GB RAM
(expandable to 6) and a 4-core 2.4 GHz Atom. Single-threaded epoll means
one slow or oversized request isn't parallelized away, and 2 GB is little
headroom for an unbounded number of buffered uploads.

## Current state (real code)

- **Connection cap exists.** `src/server.c` `accept_new` (~line 187)
  checks `s->n_conns >= s->cfg.max_conns` and rejects past the cap.
  Default `max_conns` is set in `main.c`'s `server_cfg_t` (4096 — which
  is itself high for a 2 GB box).
- **Fixed per-conn buffers.** `include/conn.h`: `CONN_RBUF_SZ` 16 KB,
  `CONN_WBUF_SZ` 16 KB, `CONN_HDR_SCRATCH_SZ` 16 KB, `CONN_MAX_HEADERS`
  64. So *header* bombs are already bounded — a request can't grow the
  header scratch arena without limit.
- **Bodies stream; they don't buffer** — for normal PUT, bytes go
  straight to the store writer via `store_put_write` and aren't held in
  memory. Good. **Exception:** anything that buffers a whole body. Check
  `route.c` for request bodies read into memory (CompleteMultipartUpload
  parses an XML body — is it bounded? grep for where that body is
  accumulated).
- **No `Content-Length` ceiling.** `c->req.content_length_hint` is
  captured but not checked against a max.

## Approach

1. **Add a max-object-size / max-body config** with a sane default
   (e.g. cap single PUT at something like the S3 single-PUT limit of
   5 GiB, or lower for a homelab). Plumb through `server_cfg_t` →
   wherever the writer or body handler can see it. Reject oversized with
   `S3_ERR_ENTITY_TOO_LARGE` (HTTP 413) — check if that code already
   exists in `include/s3.h`; add it if not.

2. **Bound any in-memory body buffer.** The CompleteMultipartUpload XML
   body must have a hard cap (a few MB is plenty — it's a list of part
   numbers + etags). If `route.c` accumulates it, ensure it can't grow
   unbounded; reject with 413 past the cap.

3. **Lower `max_conns` default for the NAS profile**, or make the SPK
   pass a NAS-appropriate value. 4096 connections × 16 KB rbuf +
   16 KB wbuf + scratch ≈ 200+ MB just in connection buffers at the cap,
   on a 2 GB box also running DSM. Something like 256–512 is more
   honest for this hardware. Consider exposing it as a wizard field or
   a conf value in the SPK.

4. **Optional: a simple per-request timeout.** A client that opens a
   connection and dribbles bytes ties up a slot. A read/idle timeout
   (close connections idle > N seconds) protects the slot pool. The
   epoll loop already wakes every 1 s (the GC tick) — piggyback an
   idle-connection sweep on the same cadence.

## Hookpoints

- `src/main.c`: `server_cfg_t` defaults; new max-body flag; possibly a
  lower `max_conns` default.
- `include/server.h`: config fields.
- `src/conn.c`: enforce body-size ceiling as bytes stream
  (`content_length_hint` check at headers-complete; running total in the
  body callback); idle-timeout bookkeeping (last-activity timestamp per
  conn).
- `src/server.c`: idle sweep in the event loop next to the GC tick.
- `src/route.c`: bound the buffered CompleteMultipartUpload body.
- `include/s3.h` / `src/response.c`: `S3_ERR_ENTITY_TOO_LARGE` (413).

## How to test

- `tests/test_e2e.sh`: PUT a body exceeding the configured max → expect
  413, and confirm no partial object is left (ties into the disk-full
  cleanup invariant).
- Oversized CompleteMultipartUpload body → 413, not OOM.
- Idle-timeout: open a raw socket, send headers, send nothing, assert the
  server closes the connection after the timeout.
- Memory ceiling sanity: with `max_conns` lowered, open the cap's worth
  of connections and watch RSS stay bounded.

## What "done" looks like

- A configurable max body size, enforced as bytes stream, returning 413.
- Buffered bodies (MPU complete) hard-capped.
- `max_conns` default appropriate for 2 GB hardware (or SPK overrides it).
- Optional idle timeout reclaims stuck slots.
- Tests for oversized body, oversized MPU XML, idle close.

## Traps

- **Enforce the body cap as you stream, not just from `Content-Length`.**
  A client can lie about or omit `Content-Length` (chunked). Track the
  running total in the body callback and abort when it exceeds the cap —
  don't trust the header alone.
- **Rejecting mid-stream must still clean up** the temp file (see the
  disk-full brief — same invariant: no orphan in `tmp/`).
- **Don't set `max_conns` so low it breaks legitimate parallel clients.**
  `aws s3 cp` of a big file opens ~10 parallel multipart connections; a
  cap below that throttles normal use. 256+ is fine; 8 is not.
- **The 16 KB rbuf is per-connection and fixed** — it's not the body
  buffer (bodies stream through it in chunks), so it does *not* need to
  grow for large objects. Don't "fix" a non-problem by enlarging it.
