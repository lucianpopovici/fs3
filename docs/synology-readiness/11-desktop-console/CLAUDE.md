# CLAUDE.md — desktop console / DSM tile

**Problem:** the DSM desktop tile (`packaging/synology/ui/`) is a static
info page — it shows connection strings, status, and AWS CLI examples,
but you can't *do* anything from it. All configuration (port, data
folder, credentials) is "edit `fs3.conf`, restart the package."

**Why it matters here specifically:** lowest priority of the readiness
gaps. It's a UX nicety, not a correctness or safety issue. The
conf-file-and-restart workflow is entirely functional; this just makes
fs3 feel like a first-class DSM app instead of a side-loaded binary.

## Current state

`packaging/synology/ui/`:
- `config` registers `SYNO.SDS.fs3.Application` as a URL-type tile
  pointing at `index.cgi`.
- `index.cgi` is a shell CGI that reads `fs3.conf` + the PID file and
  renders an HTML status/info page (endpoint, data folder, auth state,
  CLI examples). Read-only.
- Tile icons in `ui/images/` at all DSM sizes.

So there's a working tile and a CGI that can already read live state.
Turning it into a console means letting that CGI (or a richer one) also
*write* config and trigger restarts.

## Approach — only if someone wants point-and-click

Strictly optional. If pursued, smallest-useful-first:

1. **Show more live state (cheap, low-risk).** The CGI already reads
   conf + PID. Add: storage used/free (`df` on the data dir — or scrape
   the `/metrics` endpoint if the metrics brief is done), object/bucket
   counts, recent log tail, in-flight MPU count. Still read-only, still
   safe, immediately more useful.

2. **Add config editing (more work, more risk).** A form that writes
   `fs3.conf` and triggers a package restart via `synopkgctl` /
   `synopkg`. Now the CGI mutates state and restarts a service, so it
   needs: input validation (port range, path sanity, key format), CSRF
   protection, and to run with appropriate privilege. This is where it
   stops being trivial — a config UI that can restart a storage service
   is a small attack surface of its own.

3. **Or integrate with the metrics dashboard instead.** If the
   metrics-health brief is done, the "console" can largely be a Grafana
   dashboard, and the tile just deep-links to it. Arguably better than
   building a bespoke UI: reuses the Pi 4 stack, no new attack surface,
   no config-write risk.

## Hookpoints

- `packaging/synology/ui/index.cgi` — the existing read-only page;
  extend for richer state (step 1) or add a form (step 2).
- `packaging/synology/ui/config` — tile registration; could add a
  second tile or deep-link target.
- For config writes: `synopkgctl`/`synopkg` to restart; the CGI's
  effective user and DSM's CGI privilege model.

## How to test

- Read-only enrichments (step 1): load the tile on DSM, confirm the
  added state (storage, counts, log tail) renders and matches reality.
- Config editing (step 2): change the port via the form, confirm the
  conf file updates, the package restarts, and fs3 comes up on the new
  port; test input validation rejects garbage (port 0, non-absolute
  path, etc.); confirm the form isn't exploitable (CSRF, injection into
  the conf file).

## What "done" looks like

- Minimum: richer read-only status on the tile (storage, counts, log
  tail). That alone closes most of the "feels second-class" gap.
- Optional maximum: validated config editing + restart from the UI, or a
  deep-link to a Grafana dashboard.

## Traps

- **A config UI that writes a file and restarts a service is an attack
  surface.** The moment the CGI mutates state, validate everything and
  consider CSRF. Don't bolt on a write form casually.
- **CGI injection into `fs3.conf`.** If the form value flows into the
  conf file unescaped, a crafted value could inject extra config lines
  (the conf is sourced as shell by `start-stop-status`!). Sourcing
  user-written values as shell is dangerous — if you add a write path,
  switch `fs3.conf` to a non-sourced format (parsed, not `.`-included)
  first. This is the sharpest trap here.
- **Don't gold-plate.** This is Tier 3 for a reason. If the conf-file
  workflow works and the metrics brief gives you a dashboard, a bespoke
  console may never be worth building.
