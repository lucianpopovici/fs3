# CLAUDE.md — credential management

**Problem:** authentication today is one-or-more static `access:secret`
pairs passed on the command line (`--auth`), which the SPK bakes into
`fs3.conf` in plaintext at install time. Changing a key means editing the
conf file and restarting the package. There's no rotation without
downtime, no per-bucket scoping, and the secret sits in plaintext in a
file and in the process arg list.

**Why it matters here specifically:** a NAS is multi-user and
long-running. "One shared key for everyone, changeable only by SSHing in
and editing a file" is thin for a box several people or services hit, and
secrets in `ps`-visible argv / world-readable conf are a real exposure.

## Current state (real code — better than you'd think)

The *verifier* already supports multiple credentials:
- `src/sigv4.c`: `sigv4_create`, `sigv4_add_cred(v, access_key,
  secret_key)` builds a linked list of `cred_t {access_key, secret_key}`
  (~line 83, 119). `cred_lookup` (~line 154) matches the request's access
  key against the list. `sigv4_verify` (~line 756) uses it.
- So **multiple users already work at the verify layer.** What's missing
  is everything *around* it: where creds come from, how they change, what
  they're scoped to.

The gaps are in provisioning, not verification:
- `src/main.c` parses `--auth ak:sk` (repeatable) into `sigv4_add_cred`.
- The SPK writes a single `FS3_ACCESS_KEY`/`FS3_SECRET_KEY` into
  `fs3.conf` and `start-stop-status` turns it into one `--auth` arg.
- No reload-without-restart. No per-bucket policy. Secrets in argv +
  plaintext conf.

## Approach (incremental — don't build IAM)

Do the smallest things that remove the sharpest edges. Resist building a
policy engine; that's the road to reimplementing AWS IAM, which the
project explicitly does not want to be.

1. **Read credentials from a file, not argv.** Add `--auth-file PATH`
   that loads `access:secret` lines (or a small TOML/JSON). Keeps
   secrets out of `ps`/argv. The SPK writes this file (mode `0600`,
   owned by the package user) instead of passing `--auth` on the
   command line. This is the highest-value, lowest-risk change.

2. **Reload on SIGHUP.** Re-read the auth file on `SIGHUP` so a key can
   be added/rotated without dropping connections. The signal handler
   sets a flag; the event loop (which already wakes every 1 s) checks it
   and rebuilds the verifier. Rotation without downtime.

3. **Multiple keys via the file** — already supported by the verifier,
   just expose it: multiple lines in the auth file → multiple
   `sigv4_add_cred` calls. Gives per-person/per-service keys so one can
   be revoked without affecting others.

4. **(Optional, only if needed) per-bucket scoping.** A minimal model:
   each credential line can carry an optional bucket allow-list. The
   verifier already knows the access key; `route.c` knows the bucket;
   add a check "does this key permit this bucket." Keep it to
   allow-lists, not a policy language. Defer unless someone actually
   needs it — most homelab setups don't.

## Hookpoints

- `src/main.c`: `--auth-file` flag; SIGHUP handler wiring.
- `src/sigv4.c`: a loader `sigv4_load_file(v, path)` that parses lines
  and calls `sigv4_add_cred`; a `sigv4_reload`/rebuild path. The
  per-cred bucket allow-list (if pursued) extends `cred_t`.
- `src/server.c`: SIGHUP flag check in the event loop next to the GC
  tick; verifier swap.
- `packaging/synology/scripts/postinst` + `start-stop-status`: write a
  `0600` auth file owned by the package user; pass `--auth-file` not
  `--auth`.
- `packaging/synology/WIZARD_UIFILES/install_uifile`: unchanged UX, but
  the secret now lands in a mode-0600 file instead of argv.

## How to test

- `tests/test_sigv4.c`: load a multi-line auth file, verify each key
  authenticates and an unknown key is rejected.
- Reload test: start with one key, append a second to the file, send
  SIGHUP, confirm the second key now authenticates and the first still
  does — without restart.
- `tests/test_e2e_auth.sh`: a second credential signs a request
  successfully; a revoked (removed + SIGHUP) credential then fails.
- If bucket scoping is added: key A can access bucket-a, gets 403 on
  bucket-b.

## What "done" looks like

- Secrets live in a mode-0600 file, not argv, not world-readable conf.
- Multiple credentials work end-to-end (they already verify; now they're
  provisioned cleanly).
- SIGHUP rotates/adds keys with no downtime.
- SPK provisions the auth file with correct ownership/mode.
- Tests for multi-key, reload, and revoke.

## Traps

- **Don't put secrets in argv.** `ps aux` shows command lines to other
  users. The whole point of the file is to get them out of argv — so
  `start-stop-status` must stop passing `--auth ak:sk`.
- **File mode and ownership matter.** A 0644 auth file is barely better
  than argv. 0600, owned by the package user.
- **SIGHUP reload must be atomic.** Build the new verifier fully, then
  swap the pointer; never mutate the live list mid-verify (single thread
  helps, but still build-then-swap so a malformed file doesn't leave you
  with zero creds).
- **Don't grow this into IAM.** Allow-lists at most. Policies, roles,
  STS, conditions — that's a different (and explicitly unwanted)
  project. If the requirement starts sounding like AWS IAM, the answer
  is "use rustfs," per the top-level CLAUDE.md.
- **Constant-time compare** is already used for signatures in sigv4.c —
  don't introduce a plain `strcmp` on secrets when loading/looking up.
