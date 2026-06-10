# CLAUDE.md — Synology-readiness gap briefs

fs3 was built as a homelab demo and then packaged as a Synology SPK (see
`packaging/synology/`). A NAS is a different operating environment from
"a binary I run in a tmux session": it's persistent, network-exposed,
multi-user, long-running, and holds data the owner cares about. This
directory holds one brief per gap between "demo that passes its tests"
and "thing I'd trust on a DS1515+ holding real data."

Each subdirectory is a self-contained task brief in the project's
CLAUDE.md style: problem, why-it-matters-here, current state with real
code references, approach, hookpoints, how-to-test, what-done-looks-like,
traps. Read the brief before touching code for that gap. Read the
top-level `../../CLAUDE.md` first for the codebase orientation.

## A present-tense bug worth fixing regardless of priority

**FIXED (2026-06-10).** `fs3.conf` is now a parsed `KEY=value` format:
`start-stop-status` and `ui/index.cgi` read it line-by-line with a
key whitelist and never source it (old quoted-format confs are still
accepted; a surrounding quote pair is stripped). `postinst` strips
CR/LF from wizard values before writing, and the secret key no longer
enters `fs3.conf` at all — credentials go to a 0600
`${VAR_DIR}/credentials` file passed to fs3 via `--credentials-file`,
which also keeps the secret out of `ps` output. `index.cgi` HTML-escapes
conf-derived values before rendering them.

Original problem, for context: `packaging/synology/scripts/`
sourced `fs3.conf` as shell (`. "${CONF_FILE}"`), and `postinst` wrote
the install-wizard values (including the secret key) into that file
unescaped, so a crafted value — e.g. a secret key containing
`"; reboot; "` — would execute as shell when the package started.

## The gaps, by priority

These are ordered by my judgment of "what would actually stop me trusting
fs3 on a NAS," not by effort. The first three are correctness/safety
issues specific to the NAS context. The rest are "want before calling it
done" but survivable on a trusted LAN in the meantime.

### Tier 1 — would block trusting it with real data

1. **[02-disk-full](02-disk-full/CLAUDE.md)** — **DONE (2026-06-10).**
   `ENOSPC`/`EDQUOT` now map to `S3_ERR_INSUFFICIENT_STORAGE` (HTTP 507)
   at every step of the durable write sequence (write, pwrite, fsync,
   mkdir, rename) for single PUT, MPU parts, MPU initiate, and MPU
   complete. Temp-file cleanup on every error path was audited and is
   covered by four new unit tests using injectable write/fsync hooks
   (`s3_store_write_hook`/`s3_store_fsync_hook` in `store.h`). The
   Phase 11 `--min-free-bytes` preflight already covered the early
   quota check. Green under ASan + UBSan.

2. **[03-share-permissions](03-share-permissions/CLAUDE.md)** — **code
   complete, hardware test pending (2026-06-10).** Default data dir is
   now package-owned (`/var/packages/fs3/var/data`); `postinst` chowns
   the var dir (recursive) and the data dir (top-level only) to the
   package user when it has the privilege; `start-stop-status` does a
   probe-file writability preflight and fails the start with a readable
   message via `SYNOPKG_TEMP_LOGFILE` instead of crash-looping; the
   wizard explains the shared-folder permission requirement. Needs a
   real DSM install to verify (see the brief's manual test plan).

3. **[01-tls](01-tls/CLAUDE.md)** — **done via Option A, hardware test
   pending (2026-06-10).** SPK default bind flipped to `127.0.0.1`
   (wizard offers an explicit "expose plain HTTP on the LAN" opt-out);
   README and the DSM tile document the DSM-reverse-proxy HTTPS setup
   and the SigV4 host-header trap. No native TLS in fs3, as recommended.

### Tier 2 — want before calling it production-grade

4. **[06-startup-recovery](06-startup-recovery/CLAUDE.md)** — no startup
   scan for orphaned temp files or interrupted multipart staging after
   an ungraceful shutdown. The C2000 erratum makes these boxes prone to
   sudden death, so this matters more here than usual.

5. **[05-resource-bounds](05-resource-bounds/CLAUDE.md)** — connection
   cap exists (`max_conns`) but there's no per-request body-size limit
   and no bound on concurrent multipart memory. On a 2 GB-RAM box this
   is a DoS-by-accident risk.

6. **[04-credential-management](04-credential-management/CLAUDE.md)** —
   the verifier already supports multiple credentials; what's missing is
   *management*: persistence beyond the install-time conf, rotation
   without downtime, and any notion of per-bucket scoping.

7. **[08-service-supervision](08-service-supervision/CLAUDE.md)** — the
   SPK backgrounds fs3 with a PID file; DSM won't restart it on crash.
   Includes auto-restart / crash recovery.

8. **[07-metrics-health](07-metrics-health/CLAUDE.md)** — no `/healthz`,
   no `/metrics`. You run Prometheus/Grafana on the Pi 4; fs3 gives it
   nothing to scrape.

### Tier 3 — operational polish

9. **[09-log-rotation](09-log-rotation/CLAUDE.md)** — `fs3.log` grows
   unbounded over a months-long NAS uptime.

10. **[10-package-signing](10-package-signing/CLAUDE.md)** — unsigned
    SPK triggers a DSM trust-level warning. Mostly unavoidable without a
    Synology developer cert; brief explains the options.

11. **[11-desktop-console](11-desktop-console/CLAUDE.md)** — the DSM tile
    is an info page, not a control panel. Lowest priority; the conf-file
    workflow is fine.

## Suggested sequencing

If the goal is "store backups I'd be sad to lose": do 02, 03, 01 in that
order and stop there until something else hurts. Those three close the
gap between "demo" and "won't lose or leak my data on a trusted LAN."

If the goal is "a polished community SPK others install": do all of
Tier 1 and 2, then 09 and 10. Skip 11 unless someone asks.

Don't tackle these as one mega-phase. Each brief is sized to be a
focused session with its own tests and its own commit.
