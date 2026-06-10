# CLAUDE.md — service supervision / auto-restart

> **STATUS: fallback implemented (2026-06-10); DSM-native path still
> open.** `start-stop-status` now runs fs3 under a watchdog that
> respawns it on unexpected exit with 1s→60s exponential backoff (reset
> after a 60s-healthy run); `stop` raises a stop flag first so
> intentional stops don't respawn, and the DSM status contract (0/3) is
> unchanged. Verified locally: kill -9 → respawn, port-conflict
> crash-loop backs off and self-recovers, clean stop. Known limits, as
> the brief warned: the watchdog itself is unsupervised, and DSM shows
> "running" during backoff. The preferred DSM-native service model
> still needs investigating against the DSM 7 developer guide + real
> hardware (reboot autostart relies on `startable="yes"` — verify on
> the DS1515+).

**Problem:** the SPK launches fs3 as a backgrounded process and records
its PID (`start-stop-status` in `packaging/synology/scripts/`). If fs3
crashes, nothing restarts it — DSM just shows "stopped" until someone
notices and clicks Run. There's no crash recovery and no
start-on-boot guarantee beyond DSM's package autostart.

**Why it matters here specifically:** a NAS runs unattended for months.
"Silently dead until a human looks" is the wrong failure mode for a
storage service holding data other things depend on. Combined with the
C2000 box's tendency to reboot unexpectedly, you want the service to come
back by itself, reliably.

## Current state

`packaging/synology/scripts/start-stop-status`:
- `start`: `mkdir` data dir, build args, launch `"${BIN}" ${ARGS} &`,
  write `$!` to `fs3.pid`.
- `stop`: read pid, `kill`, wait up to 10 s, `kill -9`, remove pid file.
- `status`: pid alive → exit 0, else exit 3 (DSM "stopped" convention).
- `log`: prints the log path.

This is a bare daemonization. DSM's package manager calls these on
install/boot/stop, but it does **not** supervise the process between
calls — if the PID dies, DSM doesn't know until it next polls `status`,
and even then it doesn't auto-restart.

## Approach — use DSM's own supervisor, don't roll your own

DSM 7 can run a package as a managed service so DSM restarts it on exit.
The mechanism is the package "service" model (declared via
`conf/resource` and the `PkgSynoTool`/`dsm_service` integration), where
DSM owns the process lifecycle instead of a hand-rolled PID file.

1. **Investigate the DSM 7 service-declaration path.** The current
   developer guide (help.synology.com/developer-guide) documents running
   a package as a supervised service. The goal: hand DSM the command
   line and let DSM's `synopkgctl`/service framework keep it alive,
   restart on crash, and start on boot. Confirm the exact INFO /
   `conf/resource` fields the current DSM version expects — the docs
   here have historically been thin (see the nomad-spk-dsm7 project's
   notes), so cross-check against a known-good DSM 7 service package.

2. **If DSM-native supervision is workable:** replace the hand-rolled
   `start_daemon`/`pid file` with the DSM service declaration. DSM then
   provides restart-on-crash and boot-start for free.

3. **If DSM-native supervision is awkward (fallback):** keep the PID
   approach but add a tiny watchdog — a wrapper that re-execs fs3 if it
   exits non-zero, with a backoff so a crash-loop doesn't spin. This is
   strictly inferior to DSM-native (the wrapper itself isn't
   supervised), so only do it if the native path doesn't pan out.

4. **Either way: ensure clean start-on-boot.** Confirm the package's
   autostart flag is honored so the service comes up after a reboot
   without manual intervention.

## Hookpoints

- `packaging/synology/INFO.in` — service-related fields (`startable`,
  `ctl_stop` are already set; the supervised-service path may need more).
- `packaging/synology/conf/resource` — currently declares only the port
  descriptor; the DSM service model is wired here.
- `packaging/synology/scripts/start-stop-status` — either simplified
  (DSM owns lifecycle) or augmented (watchdog fallback).

## How to test

Requires real DSM (the local sim can't reproduce DSM's supervisor):
1. Install, start, then `kill -9` the fs3 process directly via SSH.
   Assert DSM restarts it within its poll interval (native path) or the
   watchdog re-execs it (fallback).
2. Reboot the NAS; assert fs3 is running after boot without touching the
   UI.
3. Crash-loop guard: make fs3 exit immediately (bad config), assert the
   restart backs off instead of spinning at 100% CPU.

Until hardware is available, deliverable is the INFO/resource changes
reviewed against the DSM 7 developer guide + a documented manual test
plan. Don't claim auto-restart works without a real kill-and-watch test.

## What "done" looks like

- fs3 restarts automatically after an unexpected exit.
- fs3 is running after a NAS reboot with no manual step.
- A crash-loop backs off rather than pinning a core.
- Lifecycle is DSM-supervised (preferred) or watchdog-wrapped (fallback,
  documented as such).

## Traps

- **`status` exit codes are load-bearing.** DSM interprets them (0 =
  running, 3 = stopped). If you change the supervision model, keep the
  status contract or DSM's UI lies about state.
- **A watchdog that isn't itself supervised just moves the problem.** If
  you must use the fallback, document clearly that it's weaker than
  DSM-native.
- **Crash-loop without backoff is worse than staying down** on a 2.4 GHz
  Atom — it'll cook a core and spam the log. Always back off.
- **Don't double-supervise.** If DSM owns the lifecycle, remove the
  hand-rolled PID daemonization, or you'll have two things fighting over
  one process.
