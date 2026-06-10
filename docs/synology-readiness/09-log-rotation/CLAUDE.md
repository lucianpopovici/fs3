# CLAUDE.md — log rotation

**Problem:** `start-stop-status` appends fs3's stderr to
`${SYNOPKG_PKGVAR}/fs3.log` with no rotation. Over a months-long NAS
uptime, especially with verbose logging or a noisy client, that file
grows without bound and eventually wastes meaningful space (or fills a
small system partition).

**Why it matters here specifically:** NAS uptime is measured in months.
An unbounded log is a slow leak that nobody notices until it's a problem.
On the C2000 box where the *system* partition is separate from the data
volume, a runaway log could fill the system partition and destabilize
DSM itself.

## Current state

`packaging/synology/scripts/start-stop-status`:
```sh
"${BIN}" ${ARGS} >> "${LOG_FILE}" 2>&1 &
```
Pure append, forever. `fs3` itself (`src/log.c`) writes leveled lines to
stderr; it has no file handling, no rotation, no size awareness. The
`log` subcommand just prints the path for DSM's log viewer.

## Approach — prefer the platform, keep fs3 dumb

fs3 logging to stderr is the right design (twelve-factor; let the
supervisor handle the sink). So don't build rotation into fs3. Handle it
at the packaging layer.

1. **Use DSM's log rotation if the supervised-service path is adopted**
   (see the service-supervision brief). If DSM owns the process and its
   stdout/stderr, DSM's logging handles rotation. This is the cleanest
   outcome and another reason to prefer DSM-native supervision.

2. **Otherwise, drop in a `logrotate` config.** DSM ships `logrotate`.
   Install a config (from `postinst`, into the appropriate DSM
   logrotate.d location, or invoked from a periodic task) that rotates
   `fs3.log` by size (e.g. 10 MB) keeping a few generations, with
   `copytruncate` (since fs3 holds the file open via the append
   redirect — `copytruncate` avoids needing fs3 to reopen the fd).

3. **Or, simplest: bound it in the launcher.** Have `start-stop-status`
   pipe fs3's output through a size-capping tee, or periodically truncate
   from the GC-tick-style timer. Crudest option; only if logrotate isn't
   cleanly available.

4. **Make log level configurable** so the default isn't chatty. fs3 has
   `LOG_D/I/W/E` levels and a `-v` verbose flag; ensure the SPK default
   is INFO-or-quieter, not debug. Less volume is the cheapest rotation.

## Hookpoints

- `packaging/synology/scripts/postinst` — install the logrotate config.
- `packaging/synology/scripts/start-stop-status` — the redirect; the
  `copytruncate` consideration; ensure not passing `-v` by default.
- `src/log.c` — only if you decide fs3 should honor a `SIGHUP`-driven
  reopen (needed if you use logrotate *without* copytruncate). Likely
  unnecessary if you use copytruncate.

## How to test

- On DSM: let fs3 log, force the log past the rotation threshold (loop
  some requests with verbose on), confirm rotation happens and old
  generations are pruned, and that fs3 keeps logging to the live file
  afterward (the copytruncate / reopen actually worked).
- Confirm a rotated-and-truncated log doesn't make fs3 lose its file
  handle and silently stop logging — this is the classic logrotate bug.

## What "done" looks like

- `fs3.log` is bounded in size with a few rotated generations kept.
- fs3 keeps logging correctly across a rotation (no lost fd).
- Default log level is not debug.
- Rotation handled by DSM-native logging or a logrotate drop-in — not by
  rotation code inside fs3.

## Traps

- **The classic logrotate fd bug:** if logrotate renames the file but
  fs3 holds the old fd open (which the `>>` redirect does), fs3 keeps
  writing to the now-unlinked inode and the live file stays empty.
  `copytruncate` sidesteps this; plain rotation requires fs3 to reopen
  on SIGHUP. Pick one and test it actually rotates *and* keeps logging.
- **Don't add rotation logic into fs3.** Logging to stderr and letting
  the platform handle the sink is correct; rotation code in the server
  is scope creep.
- **A truncate-based crude approach can lose the tail** of the log right
  when you need it (during an incident). Size-based rotation with
  retained generations is safer than truncate-in-place.
