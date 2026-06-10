# CLAUDE.md — share permissions / package-user write access

> **STATUS: VERIFIED ON HARDWARE (2026-06-10, DS1515+ / DSM 7.1).**
> DSM created the `fs3` package user; postinst's chown worked; PUT
> objects land owned by `fs3:fs3` in the default data dir with no
> manual steps. The failure path was exercised for real: pointing
> FS3_DATA at a root-owned `/volume1` dir leaves the package stopped
> with the readable preflight message in `fs3.log` (no crash loop), and
> a `chown fs3` on the dir makes the same path work. Original plan
> below for reference.
>
> Previous status: code complete, hardware test pending (2026-06-10).
> Approach (a) implemented: wizard default is the package-owned
> `/var/packages/fs3/var/data`, with volume paths as the documented
> advanced option. `postinst` chowns `VAR_DIR` recursively and the data
> dir non-recursively (never its contents — it may be a pre-existing
> share) to `${SYNOPKG_PKGNAME}` when running as root.
> `start-stop-status start` does a probe-file writability preflight and
> fails with a readable message via `SYNOPKG_TEMP_LOGFILE`. Wizard text
> documents the shared-folder permission step. The manual test plan
> below still needs to run on the DS1515+ before this is "verified."

**Problem:** the SPK declares `run-as: package` (see
`packaging/synology/conf/privilege`), so fs3 runs as the dedicated
`sc-fs3`-style user DSM creates. Whether that user can actually create
and write files under an arbitrary data folder like `/volume1/fs3-data`
is untested — and DSM share permissions do **not** automatically grant
the package user access to volume paths. If it can't write, the first
`PUT` fails and the whole thing looks broken.

**Why it matters here specifically:** this is the most likely "passed in
local simulation, fails on real hardware" gap. My DSM simulation ran the
scripts as root with a `/tmp` data dir, which sidesteps the entire
permission question. Real DSM does not.

## Current state

- `packaging/synology/conf/privilege` sets `run-as: package`, username
  `fs3`.
- `packaging/synology/scripts/postinst` does `mkdir -p "${DATA}"` where
  `DATA` defaults to `/volume1/fs3-data` (from the install wizard).
- `start-stop-status` also `mkdir -p "${FS3_DATA}"` on start.
- `src/store_fs.c` `store_open` creates the tree with mode `0700` and
  fails loudly (`LOG_E`) if any `mkdir_p` fails — good, the error is at
  least logged to `fs3.log`.

The chain that can break: postinst runs in an install context (may be
root or may be the package user depending on DSM version/phase), creates
`/volume1/fs3-data` owned by whoever ran postinst, then
`start-stop-status start` runs fs3 as the *package* user, which may not
own or be able to write that directory.

## Approach

1. **Decide the data-location story.** Two clean options:
   - **(a) Package-owned dir under the package's share.** DSM 7 gives
     each package a home under `/var/packages/fs3/` and can provision a
     share. Keep data there by default; the package user owns it by
     construction. Simplest, but the data isn't in a user-visible share.
   - **(b) User-chosen volume path, with explicit chown in postinst.**
     Keep the wizard field, but in `postinst` (which can run with enough
     privilege) `chown -R` the data dir to the package user, and verify
     writability before declaring success. More flexible, more to get
     right.

   Recommend (a) as the default with (b) as an advanced option. Most
   users want "just work"; power users can point it elsewhere.

2. **Add a writability preflight** to `start-stop-status start`: before
   launching, attempt to create and remove a probe file in `FS3_DATA`.
   If it fails, write a clear message to `SYNOPKG_TEMP_LOGFILE` ("fs3
   cannot write to <dir>; check that the package user owns it") and exit
   non-zero so DSM shows the failure instead of a mysterious crash-loop.

3. **Resolve the actual package username.** DSM 7 derives it; don't
   hardcode `fs3`. Use `$SYNOPKG_PKGNAME` and the DSM-provided user, or
   query it. Confirm against the DSM 7 developer guide
   (help.synology.com/developer-guide) what the resolved name is and
   whether `conf/privilege`'s `username` field is honored or ignored.

4. **Document the share-permission requirement** in the install wizard
   text and the README so a user pointing at an existing share knows to
   grant the package user access in DSM's shared-folder permissions UI.

## Hookpoints

- `packaging/synology/conf/privilege`
- `packaging/synology/scripts/postinst` (chown / verify)
- `packaging/synology/scripts/start-stop-status` (writability preflight)
- `packaging/synology/WIZARD_UIFILES/install_uifile` (wording + maybe a
  default that lives under the package var dir)
- `src/store_fs.c` `store_open` already logs mkdir failures — no change
  needed there, but its log line is the breadcrumb when this fails.

## How to test

This genuinely needs real DSM hardware or a DSM VM — the local sandbox
can't reproduce DSM's user/permission model. Concretely:

1. Install the SPK on the DS1515+.
2. Point the data folder at a fresh `/volume1/fs3-data`.
3. Confirm the package starts (status running) and a `PUT` actually
   writes a file owned by the package user.
4. Repeat pointing at an *existing* shared folder with default
   permissions and confirm the preflight catches the failure with a
   readable message rather than a crash-loop.
5. Check `/var/log/synopkg.log` and the package's `fs3.log` for the
   permission breadcrumb on the failing case.

Until hardware is available, the deliverable is the *defensive code* (the
preflight + chown + clear error), reviewed against the DSM 7 developer
guide, plus a documented manual test plan. Don't claim it's verified
without a real install.

## What "done" looks like

- Default install "just works": package user can write the default data
  dir without manual chown.
- Pointing at an arbitrary path either works (postinst chowned it) or
  fails fast with a human-readable reason in the DSM UI / log.
- README and wizard text explain the share-permission requirement.
- Verified on real DSM (or explicitly marked "code complete, hardware
  test pending").

## Traps

- **Don't assume postinst runs as root.** DSM phases vary. If chown
  needs root and postinst isn't root, you need a different mechanism
  (the privilege manifest, or provisioning the dir at a path the package
  user already owns).
- **Don't hardcode the UID/username.** It's DSM-assigned.
- **`mkdir -p` succeeding is not proof of writability.** A dir can exist
  and be unwritable by the package user. The probe-file check is the
  real test.
- **`/volume1` is not guaranteed** — multi-volume NAS setups may have
  `/volume2`, `/volume3`. The wizard default of `/volume1/...` is a
  guess; validate the path exists in the wizard or postinst.
