# CLAUDE.md — metrics + health endpoint

> **STATUS: DONE (2026-06-10).** `--metrics-port` opens a localhost-only
> admin listener serving `/healthz` and Prometheus `/metrics`
> (`src/metrics.c`): requests by method × status class, bytes in/out,
> duration summary, and per-scrape gauges (buckets, in-flight MPUs,
> volume used/free). Counters are plain uint64 — single-thread
> invariant documented in `include/metrics.h`. The S3-port `/_health`
> (added in Phase 11; `_` can't collide with a bucket name) is now
> auth-exempt for credential-less liveness probes. SPK enables the
> listener on 127.0.0.1:9101 (`FS3_METRICS_PORT`). Not done:
> `fs3_objects_total` (needs tree walk or overwrite-aware incremental
> counting), duration histogram buckets (summary sum/count instead),
> and the optional Grafana panel JSON.

**Problem:** fs3 exposes no `/healthz` and no `/metrics`. There's no way
to see request rates, error rates, latency, or storage growth without
tailing and parsing `fs3.log`.

**Why it matters here specifically:** you run a Prometheus/Grafana stack
on a Raspberry Pi 4 (per the project history). fs3 currently gives that
stack nothing to scrape, so the one storage service on the NAS is the one
thing with no dashboard. A health endpoint also lets DSM's own
service-supervision and any uptime monitor check liveness cheaply.

## Current state

- All observability is `LOG_*` lines to stderr → `fs3.log`. Useful for
  forensics, useless for time-series.
- The router (`src/route.c`) dispatches on path; there's no reserved
  admin path. `GET /` is ListAllMyBuckets, so metrics can't live at root.
- No counters exist anywhere; they'd be new state.

## Approach

Two small, separable pieces.

### Health endpoint (trivial, do first)

A `GET /healthz` (or a configurable admin path) that returns `200 OK`
with a tiny body if the store is openable and the event loop is alive.
Cheap, no auth needed, used by DSM/monitors for liveness.

**Path collision:** `/healthz` as a bucket name is technically legal S3,
so reserving it in the main router is slightly impure. Cleaner: serve
metrics/health on a **separate listener** (a second port, admin-only,
bound to localhost) rather than mixing admin endpoints into the S3 path
namespace. This also means the metrics port can be firewalled separately
and never exposed to S3 clients. Recommend the separate-listener
approach.

### Prometheus metrics (the useful part)

Expose `GET /metrics` on that same admin listener in Prometheus text
format. Minimum useful set:
- `fs3_requests_total{method,status}` — counter
- `fs3_request_duration_seconds` — histogram (or at least a summary;
  histograms are more Prometheus-idiomatic)
- `fs3_bytes_in_total` / `fs3_bytes_out_total` — counters
- `fs3_objects_total`, `fs3_buckets_total` — gauges (cheap to compute or
  maintain incrementally)
- `fs3_storage_bytes` — gauge from `statvfs` on the data volume (used vs
  free — directly answers "is the NAS about to fill," which ties into
  the disk-full brief)
- `fs3_mpu_inflight` — gauge of active multipart uploads
- `fs3_up 1` — the trivial liveness gauge

Counters are just `uint64_t` fields incremented in the request path.
Single-threaded epoll means **no atomics or locks needed** — plain
increments are safe. That's a real simplification this architecture buys
you; don't reach for atomics.

## Hookpoints

- New small module `src/metrics.c` / `include/metrics.h`: counter struct,
  increment helpers, a `metrics_render(char *buf, size_t cap)` that emits
  Prometheus text.
- `src/server.c`: a second listener socket on the admin port, added to
  the same epoll set; a minimal handler that serves `/healthz` and
  `/metrics` (doesn't need full llhttp routing — it's two fixed paths).
- `src/conn.c` / `src/route.c`: increment counters at
  request-complete and on byte transfer. Keep the increments to a
  handful of well-chosen spots; don't sprinkle them everywhere.
- `src/main.c`: `--metrics-port` flag (0 = disabled); SPK can default it
  on, bound to `127.0.0.1`.
- `src/store_fs.c`: a cheap `store_stats(s, &used, &free, &nobj...)` for
  the gauges, or maintain `objects_total`/`buckets_total` incrementally
  on create/delete.

## How to test

- `tests/test_e2e.sh` (or a new `test_e2e_metrics.sh`): hit `/healthz`
  on the admin port → 200; hit `/metrics` → Prometheus text with the
  expected metric names; do some S3 ops, re-scrape, assert
  `fs3_requests_total` increased and `fs3_bytes_in_total` reflects the
  uploaded bytes.
- Confirm the admin listener is bound to localhost only and the S3 port
  does NOT serve `/metrics` (no namespace pollution).
- `promtool check metrics` (if available) on the output to validate
  format.

## What "done" looks like

- A localhost-bound admin listener serving `/healthz` and `/metrics`.
- Prometheus-format metrics covering requests, bytes, errors, storage
  used/free, in-flight MPUs, liveness.
- Counters are plain integers (no locks) — the single-thread invariant
  documented in the code so nobody "helpfully" adds atomics later.
- Tests scrape and validate; the S3 port stays clean.
- A starter Grafana panel JSON in `docs/` would be a nice extra given
  the existing Pi 4 stack, but isn't required.

## Traps

- **Don't put admin endpoints in the S3 path namespace.** `/metrics` and
  `/healthz` are legal bucket names; a client could create a bucket that
  shadows them. Separate listener avoids the whole class of problem.
- **Bind the admin port to localhost** (or behind the same proxy story
  as TLS). Metrics can leak information; don't expose them to the LAN by
  default.
- **No atomics needed — but say so.** The increments are safe only
  because of the single-threaded loop. Leave a comment so a future
  refactor to threads knows it must revisit this.
- **`statvfs` for the storage gauge is cheap but not free** — compute it
  per-scrape (on the `/metrics` request), not per-S3-request.
- **Histograms vs summaries:** histograms aggregate across instances;
  summaries don't. For a single-node server either is fine, but
  histogram buckets are the Prometheus-idiomatic choice.
