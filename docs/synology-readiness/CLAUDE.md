# CLAUDE.md — Synology readiness: status and open briefs

fs3 started as a homelab demo and was then packaged as a Synology SPK
(`packaging/synology/`). This directory tracked the gaps between "demo
that passes its tests" and "something I'd trust on a DS1515+ holding real
data". Read the top-level `../../CLAUDE.md` first for codebase
orientation.

Most gaps are closed, and their briefs were removed once the work was
done and verified on the DS1515+ (recorded run of 2026-11-18 in
`../AGENT-BUILD-AND-DS1515-TEST.md`). Git history keeps the removed
briefs if you need the original reasoning.

## Closed

| Gap | Outcome |
|---|---|
| 01 TLS | DSM reverse proxy in front, SPK binds `127.0.0.1` by default; native TLS later added as an optional build (`make TLS=1`) |
| 02 disk full | `ENOSPC`/`EDQUOT` → 507 at every durable-write step, temp files cleaned on every error path; `--min-free-bytes` floor |
| 03 share permissions | package-owned default data dir, writability probe before start with a readable DSM error |
| 04 credential management | 0600 credentials file, SIGHUP build-then-swap reload; later key attributes (expiry, disabled, read-only) |
| 05 resource bounds | `--max-body-size`, `--idle-timeout`, `--max-conns`, TLS handshake limits |
| 06 startup recovery | temp files, half-written sidecars and duplicate version links cleaned at `store_open` |
| 07 metrics and health | localhost admin listener with `/healthz` and Prometheus `/metrics`; S3-port `/_health` without auth |
| 11 desktop console | DSM tile: bucket stats (objects, size, quota) and credential management with CSRF/Origin checks |
| 12 DSM identity binding | per-user buckets (`ak:sk[:user]`, owner + random bucket id), admins, legacy owner; the planned management socket became the `/v1` admin API (`--admin-socket`) |

Two present-tense packaging bugs were also fixed along the way: `fs3.conf`
is parsed as `KEY=value` and never sourced as shell, and upgrades preserve
the existing conf and credentials instead of resetting
`FS3_REQUIRE_AUTH` to 0.

## Open

| Brief | State |
|---|---|
| [08-service-supervision](08-service-supervision/CLAUDE.md) | Fallback in place and hardware-verified: the SPK watchdog restarts fs3 with exponential backoff. DSM-native supervision (preferred, because the watchdog itself is unsupervised) is still uninvestigated. |
| [09-log-rotation](09-log-rotation/CLAUDE.md) | Open. `fs3.log` still grows without bound. The audit log reopens on SIGHUP, but nothing rotates the package log. |
| [10-package-signing](10-package-signing/CLAUDE.md) | Open. The SPK is unsigned, so DSM asks to lower the trust level. Mostly unavoidable without a Synology developer certificate. |

## Not yet briefed

- **SPK options.** `fs3.conf` exposes only the basic keys (`FS3_BIND`,
  `FS3_PORT`, `FS3_DATA`, `FS3_REQUIRE_AUTH`, `FS3_LEGACY_OWNER`,
  `FS3_ADMIN`, `FS3_METRICS_PORT`, `FS3_GC_INTERVAL`, `FS3_GC_MAX_AGE`).
  None of the newer features can be enabled without editing
  `start-stop-status`, and an upgrade overwrites that edit. Most urgent:
  the SPK always runs behind the DSM proxy but doesn't pass
  `--trusted-proxy 127.0.0.1`, so auth-failure throttling and
  `aws:SourceIp` see every client as loopback.
- **Per-user views in the DSM tile** (the old 12c): the tile shows every
  bucket and key to the DSM admin. Mapping DSM users to fs3 users needs a
  spike on real hardware first.

Each open item is sized for one focused session with its own tests and
commit.
