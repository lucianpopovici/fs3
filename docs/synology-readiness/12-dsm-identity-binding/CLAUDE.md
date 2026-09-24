# CLAUDE.md — DSM identity binding (per-user keys and buckets)

> **STATUS: the 12a goal is DONE (2026-09-24), but NOT via the plan
> below.** This brief's spec (v2 credentials file, `--identity-mode`,
> `sigv4_verify_principal`, `authz()`, `buckets/<name>/owner`) was
> built and then discarded in favor of an independently-built
> implementation from a different session
> (`session_01PHNX7TKk6izKYohF6nQbKX`, commits `a9efec0`/`30cae60`)
> that landed on `main` first and covers the same goal with a more
> complete design (a per-bucket random id defeats a
> delete-and-recreate-under-another-owner race that this brief's plan
> didn't address). **Read the code, not the steps below, for what's
> actually there:**
> - `src/sigv4.c`: `cred_t.user` (defaults to the access key),
>   `sigv4_add_cred_user`, a separate `admin_t` list via
>   `sigv4_add_admin` (not affected by `sigv4_swap_creds`),
>   `sigv4_verify_id(v, c, sigv4_id_t *id_out)` — copies `user` +
>   `is_admin` out at verify time, same use-after-free-avoidance
>   property this brief called for, just under a different name.
> - `src/main.c`: credentials are `ak:sk[:user]` (`parse_and_add_cred`),
>   not a separate v2 file format. `--admin <user>` and
>   `--legacy-owner <user>` replace this brief's `--identity-mode`.
> - `src/store_fs.c`: `buckets/<bucket>/meta` (`id=`/`owner=` lines,
>   written via a `tmp/bucket.XXXXXX` stage + rename, not a bare
>   `owner` file) via `store_bucket_create_owned`/`store_bucket_meta`/
>   `store_bucket_set_owner`/`store_assign_legacy_owner`. Commits
>   capture the bucket id at `put_begin` and re-check it, so a bucket
>   deleted and recreated (even by another user) mid-upload can't
>   silently receive the object.
> - `src/route.c`: `authz_bucket()` is the single choke point, called
>   from `route_dispatch_headers` (covers bucket- and object-level
>   requests together via `is_bucket_create()`), plus a second call in
>   `handle_object_copy` for the copy source.
> - Tests: `tests/test_e2e_isolation.sh` (52 checks, including a
>   SIGHUP-vs-in-flight-request ASan/UBSan regression via
>   `tests/sign_slow_put.py`), plus store/sigv4/credfile unit coverage.
>   All green under `-O2` and DEBUG.
>
> 12b (management socket + `fs3 ctl`) and 12c (DSM console UI, needs
> hardware) are still NOT STARTED and the plan for those below is
> still a reasonable starting point — just translate "principal" →
> "user", `sigv4_verify_principal` → `sigv4_verify_id`, and the v2
> credentials-file steps → whatever `fs3 ctl`/the management socket
> decides to write into the `ak:sk[:user]` file instead.
>
> Everything below this point is the **original plan**, preserved for
> context. Its step-by-step detail for 12a no longer matches the tree.

**Goal:** a DSM user opens the fs3 tile, sees *their own* S3 access
keys and buckets, mints and revokes keys (secret shown once), and
creates or deletes their own buckets. An S3 request signed with a
user's key can only touch that user's buckets. DSM administrators see
and manage everything.

**Non-goals, stated up front so nobody drifts into them:**

- **No PAM or DSM passwords in the S3 data path.** S3 clients speak
  SigV4 and nothing else. DSM login authenticates the *human* at the
  console; SigV4 keys authenticate *machines*. They never mix.
- **No IAM.** Ownership is "this bucket belongs to this DSM user."
  No policies, no conditions, no roles. If requirements start sounding
  like AWS IAM, the answer is still rustfs (see top-level CLAUDE.md).
- **No DSM-group sharing in v1.** A bucket has exactly one owner.
  Group sharing couples fs3 to DSM's user database; defer it.
- **No NSS/`getpwnam` calls in fs3 core.** fs3 stores DSM usernames as
  opaque strings. Everything that asks DSM a question lives in the CGI.

## Why this is shaped the way it is

DSM has no concept of an S3 keypair, and S3 clients can't present a
DSM password. So the design is a **mapping layer that fs3 owns**:
`access_key → owner (DSM username)`, plus `bucket → owner`. DSM's only
role is telling the console *who is clicking*, and it already does
that: the tile only opens for a logged-in DSM user.

## Current state on `main` (what exists, what's missing)

**Exists, and is exactly the right substrate:**

- `src/sigv4.c` ~L82: `cred_t { char *access_key; uint8_t *secret_key;
  size_t secret_len; struct cred *next; }`, a linked list, secrets
  `OPENSSL_cleanse`d on free. Multiple keys already verify.
- `sigv4_swap_creds` (`include/sigv4.h`) does build-then-swap rotation;
  `src/main.c` `reload_tick` (~L132) rebuilds from `--credentials-file`
  on SIGHUP and swaps. A bad file keeps the old set.
- The SPK already writes credentials to `/var/packages/fs3/var/credentials`
  (mode 0600, `access_key:secret_key` per line), never to argv or conf.
- `conf` is parsed as data, never sourced (the old injection bug is fixed).
- `ui/config` sets `"allUsers": true`, so every DSM user already sees the
  tile. Good for self-service.

**Missing, and each is a separate piece of work:**

1. **No identity flows from auth to routing.** `sigv4_verify(v, c)` in
   `src/conn.c` ~L382 returns only an `s3_err_t`. Nothing downstream
   knows *which* key signed the request. This is the first hookpoint.
2. **No owner on credentials.** `cred_t` has no owner field, and the
   file format can't just grow a `:owner` suffix (see traps).
3. **No owner on buckets.** `store_bucket_create` (`src/store_fs.c`
   ~L418) is a bare `mkdir(buckets/<name>)`.
4. **No authorization step.** `route_dispatch_headers` (`src/route.c`
   ~L1114) dispatches purely on path shape and method.
5. **No safe write channel for the console.** The CGI runs as the DSM
   web-server context, not as the fs3 package user, so it cannot write
   the 0600 credentials file, and it must not. The existing admin
   listener (`src/server.c` `admin_handle`, ~L128) is TCP on 127.0.0.1
   with **no authentication**: any local process (another package, any
   DSM user with SSH) can connect. It must stay read-only.

## Threading constraints you must respect

fs3 is no longer purely single-threaded. `--io-threads` (default 4)
runs an `iopool` (`include/iopool.h`): workers execute `run()` for
blocking store work (fsync, server-side copy, MPU concatenation),
touching only job-owned fields and **never `conn_t`**; `done()` runs
back on the loop thread. Namespace mutations take `s->ns_mu`.

Consequences for this brief:

- `sigv4_verify`, routing, and therefore **authorization all run on the
  loop thread**. Keep it that way. The `sigv4_swap_creds` comment
  ("safe only because the server is single-threaded") remains true only
  because no worker ever verifies. Don't add a verify call inside any
  `run()`.
- **Authorize before any work is handed off.** The authz check must
  happen in `route_dispatch_headers`, before a writer is opened and
  before `iopool_submit`. Denying after a writer exists leaves temp
  files; denying after submit is too late.
- Bucket-owner writes must happen under `ns_mu`, alongside the existing
  delete logic, so a worker-side commit can't interleave (see step 3).

## Approach, in three shippable sub-phases

Do 12a first, alone, and ship it. It's testable in the sandbox with no
DSM at all. 12b and 12c build on it.

### 12a — principals and ownership in fs3 core (no DSM needed)

> **DONE (2026-09-24).** Landed close to the spec below; notable
> concrete choices for the next session to know without re-deriving
> them from git history:
> - `sigv4_verify_principal(v, c, owner_out, owner_cap, is_admin_out)`
>   is the new entrypoint (sigv4.c); `sigv4_verify` is now a thin
>   wrapper calling it with NULL outputs. `sigv4_add_cred_owned` is the
>   owned-credential adder; `sigv4_add_cred` wraps it with `owner=NULL`.
> - The choke point is `static s3_err_t authz(conn_t *c, s3_str_t
>   bucket, authz_op_t op)` in route.c, called at four sites: once in
>   `route_dispatch_headers` (covers every object/MPU/`?acl`
>   operation), once in `handle_object_copy` for the copy *source*
>   bucket, once at the top of `handle_bucket` (covers
>   bucket-level/ListMultipartUploads/bulk-delete-begin, with an
>   explicit `?acl`-vs-real-PUT check so a non-owner's `PUT ?acl` isn't
>   misclassified as a create), and inline in `handle_service` as a
>   post-listing filter (not a deny/allow gate).
> - `store_bucket_create` now takes `ns_mu` for its whole body (it
>   previously wasn't locked at all) and gained an `owner` parameter;
>   every pre-existing call site across `route.c`/tests was updated to
>   pass `""` to preserve today's admin-only-bucket behavior byte for
>   byte when identity mode is off.
> - Credentials-file v2 parsing (`parse_cred_v2_line` et al.) lives in
>   `main.c`, tested via a `FS3_MAIN_TESTING`-guarded seam
>   (`tests/test_credfile.c`) mirroring `sigv4.c`'s `SIGV4_TESTING`
>   pattern — `main()`/`on_signal`/`g_server` are excluded from that
>   build so the test binary supplies its own `main()` without pulling
>   in `server.c`'s dependency chain.
> - New tests: `tests/test_credfile.c` (20 checks), additions to
>   `tests/test_sigv4.c` and `tests/test_store.c`, and
>   `tests/test_e2e_identity.sh` (31 checks, including the SIGHUP/ASan
>   use-after-free regression via the new `tests/sign_slow_put.py`).
>   All green under both `-O2` and DEBUG (ASan+UBSan).
> - One unrelated, pre-existing flake was found (not caused by this
>   work — reproduces on unmodified `main` too): `t_commit_races_bucket_delete`
>   in `tests/test_store.c` fails under DEBUG/ASan in this sandbox
>   (`commit_won` never fires; `delete_won` wins all 500 iterations).
>   Worth a session of its own; out of scope here.
> - Not built: the hardening items 12b/12c depend on (management
>   socket, `fs3 ctl`, console UI) — see those sections below, still
>   accurate as written.

**Step 1: carry the principal through a request.**

- Add `char *owner` to `cred_t`. `NULL`/empty means an **admin key**:
  keys from `--auth` on the CLI and v1 credential lines have no owner
  and keep full access. That's the backward-compatibility story: the
  install-time key becomes the admin key.
- Change the verify contract to report who matched. Either a new
  `sigv4_verify_principal(v, c, char *owner_out, size_t cap, int
  *is_admin_out)` or an out-param on `sigv4_verify`. The caller copies
  the owner **into a fixed buffer on `conn_t`** (e.g.
  `char principal[128]; int principal_admin;`), reset in
  `request_reset`.
- **Never store a pointer into the cred list on `conn_t`.** See the
  use-after-free trap below. Copy the string.

**Step 2: credentials file v2.**

A new, versioned, tab-separated format, detected by a magic first line:

```
#fs3-credentials v2
# access_key <TAB> owner <TAB> created_ms <TAB> label <TAB> secret
FS3K7Q2...	alice	1790000000000	laptop-rclone	9f...base64url...
FS3M1XW...	bob	1790000123456	backup-job	Zk...base64url...
FS3ADMIN0...		1789000000000	install	...
```

- Secret is the **last** field, so it may contain anything except TAB
  and newline. Access key charset: `[A-Z0-9]`. Owner: validated (see
  username trap). Label: printable, no TAB.
- An empty owner field means admin.
- The loader in `src/main.c` (`load_credentials_file`, ~L84) keeps
  accepting v1 `ak:sk` lines (split on first `:` as today) as owner-less
  admin keys. A file is v2 only if line 1 is the magic.
- Unit-test the parser hard: this file is the security boundary.

**Step 3: bucket ownership in the store.**

- Owner lives in a file inside the bucket marker dir:
  `buckets/<name>/owner`, content = the username, no newline.
- `store_bucket_create(s, name, owner)`: under `ns_mu`, `mkdir` the
  marker dir, then write `owner` via tmp + fsync + rename + fsync(dir).
  If the owner write fails, `rmdir` the marker and return the error:
  never leave a half-created bucket.
- `store_bucket_delete`: `bucket_delete_locked` already ends in
  `rmdir(buckets/<name>)`, which **fails with ENOTEMPTY once an owner
  file exists**. Unlink `owner` first, still under `ns_mu`, after the
  emptiness check passes.
- New `store_bucket_owner(s, name, char *buf, size_t cap)`. Missing file
  → empty string → **admin-only bucket**. That covers every bucket that
  exists before this change, and a crash between mkdir and owner write.
- New `store_bucket_set_owner` (admin reassignment, used by 12b).
- Per-request cost is one small file read on the loop thread. The file
  will be in page cache. Measure before adding an in-memory cache; if
  you add one, it must be updated under `ns_mu` on create, delete, and
  reassign.

Why a file and not an xattr: `user.*` xattrs work on DSM's btrfs and
ext4, but backup and replication tools routinely drop them, silently
turning every bucket admin-only after a restore.

**Step 4: one authorization choke point.**

`static s3_err_t authz(conn_t *c, s3_str_t bucket, authz_op_t op)` in
`src/route.c`, called from `route_dispatch_headers` after path parsing.
Rules, in order:

1. Identity mode off → allow (today's behavior, unchanged).
2. Admin principal → allow.
3. `bucket owner == principal` → allow.
4. Otherwise → `S3_ERR_ACCESS_DENIED` (403), same as S3 for a bucket
   that exists but isn't yours.

Per-operation notes, because this is where holes appear:

| operation | handler (`src/route.c`) | check |
|---|---|---|
| ListAllMyBuckets | `handle_service` ~L174 | filter to owned buckets; admin sees all; `<Owner><ID>` = principal |
| CreateBucket | `handle_bucket` PUT ~L346 | any principal may create; owner = principal |
| DeleteBucket / HEAD / ListObjects / ListMultipartUploads | `handle_bucket` | owner |
| Bulk delete (`POST ?delete`) | `handle_bulk_delete_begin` ~L198 | owner, once, before buffering the body |
| PUT / GET / HEAD / DELETE object | `handle_object_*` | owner |
| **CopyObject** | `handle_object_copy` ~L777 | **two checks:** owner of destination bucket *and* owner of `x-amz-copy-source` bucket |
| MPU initiate / part / complete / abort | `handle_mpu_*` | owner, before staging dir or writer exists |
| `/_health` | `conn.c` | already auth-exempt; leave it |

**Step 5: identity mode requires auth.** New flag `--identity-mode`
(SPK: `FS3_IDENTITY=1`). If set without `--require-auth`, refuse to
start. Otherwise a request with no `Authorization` header falls through
as anonymous (see `conn.c` ~L371: verify only runs "if header present
or auth required") and bypasses ownership entirely.

### 12b — management socket in fs3 (still no DSM needed to test)

fs3 becomes the **only writer** of the credentials file and the owner
files. The console asks; fs3 does. This removes every cross-process
write race and keeps the 0600 file private.

- **Transport:** a Unix domain socket, e.g.
  `/var/packages/fs3/var/mgmt.sock`, mode 0660, group = the CGI's
  group. **Not** the TCP admin listener.
- **Authentication of the caller:** `SO_PEERCRED` on accept. Reject any
  peer whose uid isn't in `--mgmt-allow-uid` (the CGI's uid, resolved in
  the spike). The socket permission is defense in depth; the peer-cred
  check is the real gate.
- **Principal assertion:** the CGI sends `X-Fs3-Principal: <dsm user>`
  and `X-Fs3-Admin: 0|1`. fs3 trusts these *only because* the peer uid
  passed. Document this as the trust boundary.
- **Endpoints** (small HTTP/1.0-ish, same synchronous style as
  `admin_handle`, tiny bodies):
  - `GET /keys`: principal's keys (admin: `?user=` for anyone).
    Returns access key, label, created. **Never the secret.**
  - `POST /keys` (label): mint. Returns access key **and secret, once**.
  - `DELETE /keys/<ak>`: revoke. Owner or admin only.
  - `GET /buckets`, `POST /buckets/<name>`, `DELETE /buckets/<name>`
    (must be empty, same semantics as S3 DeleteBucket).
  - `PUT /buckets/<name>/owner`: admin only; reassign (migration path
    for pre-existing admin-only buckets).
- **Minting:** access key = `FS3` + 17 chars base32 from `RAND_bytes`;
  secret = 40 chars base64url from `RAND_bytes(30)`. Cap keys per user
  (e.g. 10) so the file stays bounded.
- **Persisting:** build the new cred set in a scratch verifier, write
  the v2 file via tmp + fsync + rename + fsync(dir), and only on success
  `sigv4_swap_creds`. Same build-then-swap discipline as SIGHUP. The
  fsync runs on the loop thread; mutations are human clicks, rare, and a
  small-file fsync is within the admin listener's existing
  "may stall ~200 ms" budget. Say so in a comment.
- **Command-line client:** add `fs3 ctl <subcommand>` (same binary) that
  speaks to the socket. The CGI calls it instead of hand-rolling HTTP in
  shell, and admins get a CLI for free.

### 12c — the DSM console (needs hardware; do the spike first)

`ui/index.cgi` becomes a self-service page.

- **Who is this:** run `/usr/syno/synoman/webman/modules/authenticate.cgi`
  from the CGI. It prints the logged-in username (empty if not logged
  in), using the `HTTP_COOKIE`, `REMOTE_ADDR`, and `SERVER_ADDR` the CGI
  environment already carries ([Synology developer guide](https://help.synology.com/developer-guide/integrate_dsm/web_authentication.html)).
  Empty → render "log into DSM", never fall back to anything.
- **CSRF:** with DSM's CSRF protection enabled, the session's
  `SynoToken` must accompany the request for authentication to succeed.
  Every mutating action is a POST carrying the token; **GET never
  mutates**. Confirm the exact passing mechanism in the spike.
- **Admin or not:** decided in the CGI (DSM group `administrators`),
  passed as `X-Fs3-Admin`. Mechanism confirmed in the spike.
- **Secret display:** the mint response page shows the secret once, with
  `Cache-Control: no-store`, plus a ready-to-paste `~/.aws/credentials`
  snippet. Never logged, never re-displayable. Lost secret → revoke and
  mint a new one.
- **Output:** everything user- or DSM-derived goes through the existing
  `html_escape` helper. Usernames included.

## The hardware spike (do this before writing 12c code)

These are not answerable from the sandbox, and the docs are thin. Spend
one session on a real DS1515+ answering them, and record the answers in
this file.

1. **Which uid do `/webman/3rdparty/*` CGIs run as on DSM 7?** The
   web-server user, or a per-package user? This decides
   `--mgmt-allow-uid` and whether other packages' CGIs share the uid
   (which would let them impersonate principals over the socket).
2. **`authenticate.cgi` under CSRF protection:** does it return empty
   without a token? Is the token passed as `SynoToken=` in
   `QUERY_STRING`, or as an `X-SYNO-TOKEN` header? How does the page
   obtain it?
3. **Admin detection** that works for local, LDAP, and AD users:
   `id -Gn <user>`, `synogroup --get administrators`, or something else.
4. **Username charset:** what DSM allows locally, and what directory
   users look like (`DOMAIN\user`, `user@domain`).
5. **User deletion and rename:** what happens to a DSM user's session
   and group membership, so the offboarding story (trap below) is right.

Until the spike is done, 12c is "code complete, hardware test pending"
at best, same as 03 and 01.

## How to test

**12a (sandbox):**

- `tests/test_sigv4.c`: v2 parse; owner round-trip; v1 lines load as
  admin; secret containing `:` preserved; TAB or newline in owner or
  label rejected; malformed magic rejected; principal copied into the
  out buffer.
- `tests/test_store.c`: create writes `owner`; delete removes it and
  `rmdir` succeeds; pre-existing bucket without `owner` reads as admin;
  failed owner write leaves no marker dir (use the existing
  `s3_store_write_hook`/`s3_store_fsync_hook` injection).
- New `tests/test_e2e_identity.sh`, two v2 users (alice, bob) and one
  admin key:
  - alice creates `alice-b`; bob gets 403 on HEAD, list, GET, PUT,
    DELETE object, DeleteBucket, bulk delete, MPU initiate, and
    ListMultipartUploads for it.
  - **copy both directions:** bob copying *from* `alice-b` into his own
    bucket → 403; bob copying *into* `alice-b` → 403.
  - ListAllMyBuckets as alice shows only hers; as admin shows all.
  - admin can do everything; legacy (pre-existing) bucket is admin-only.
  - `--identity-mode` without `--require-auth` refuses to start.
- **SIGHUP use-after-free test, under ASan:** start a slow chunked PUT
  as alice, rewrite the credentials file and SIGHUP mid-body, finish the
  PUT. Must complete (or fail cleanly) with zero ASan reports.

**12b (sandbox):**

- Mint returns a working key; the key authenticates an S3 PUT
  immediately, no restart. `GET /keys` never contains a secret.
- Revoke → the key fails on the next request, no restart.
- Wrong peer uid → rejected. Run the client as a different user
  (`setpriv --reuid=nobody` or `su -s /bin/sh nobody`).
- Principal header without passing peer check → rejected.
- A crash mid-rewrite (write hook fails) leaves the old file and old
  live credentials intact.

**12c (hardware):** the spike answers, then log in as two DSM users,
verify each sees only their keys and buckets, mint/revoke round-trips,
a non-admin cannot reach another user's keys by editing request
parameters, and a POST without a valid token is refused.

## What "done" looks like

- A DSM user manages their own keys and buckets from the tile, with no
  SSH and no conf editing.
- S3 requests are authorized per bucket owner, with admin keys
  unrestricted and pre-existing data admin-owned until reassigned.
- fs3 is the only writer of credentials and owner files; the console
  talks to it over a peer-credential-checked Unix socket.
- The TCP admin listener is still read-only.
- All sandbox tests green under ASan + UBSan; hardware checklist done.
- README gains a "Per-user buckets and keys" section, including the
  offboarding procedure.

## Traps

- **Secrets cannot be hashed.** SigV4 recomputes an HMAC with the
  plaintext secret on every request, which is why `cred_t` keeps raw
  bytes. "Show once" is a UX promise, not a storage property: on disk
  the secret lives in the 0600 file. Don't let anyone "improve" this
  into bcrypt; auth would stop working.
- **Use-after-free on reload.** `sigv4_swap_creds` hands the old list to
  a scratch verifier that the caller destroys. A long PUT that started
  before the swap still needs its principal at complete time. If
  `conn_t` points into the old list, that's a UAF. Copy the principal
  into `conn_t` at verify time.
- **`:` is not a safe separator.** `parse_and_add_cred` splits on the
  first `:` and the secret keeps the rest, so secrets may legally
  contain `:`. Appending `:owner` would be ambiguous. That's why v2 is
  tab-separated with the secret last.
- **`rmdir` needs an empty marker dir.** Forget to unlink `owner` in
  delete and every DeleteBucket returns 500.
- **CopyObject has two buckets.** Checking only the destination lets a
  user copy anyone's objects into their own bucket.
- **Authorize before handoff.** After `iopool_submit` or after a writer
  is open is too late: you get orphaned temp files or staging dirs.
- **Anonymous bypass.** Identity mode with optional auth means unsigned
  requests skip ownership. Enforce `--require-auth`.
- **Offboarded users keep S3 access.** Deleting a DSM user does nothing
  to their fs3 keys. fs3 core deliberately doesn't query NSS, so the
  admin view in the console must flag keys whose owner no longer exists
  in DSM, with one-click revoke, and the README must say "revoke keys
  before deleting a DSM user."
- **Directory usernames.** AD users can look like `DOMAIN\user`. A
  backslash, space, or non-ASCII byte has to survive the v2 file, the
  owner file, the socket header, and HTML. Pick one encoding (e.g.
  percent-encode anything outside `[A-Za-z0-9._@-]`) and apply it at
  every boundary, or reject such names explicitly.
- **Existence disclosure.** 403 on someone else's bucket reveals it
  exists. That matches S3 and bucket names are already a global
  namespace in fs3; accept it knowingly rather than returning
  NoSuchBucket inconsistently.
- **Lost updates.** Once fs3 writes the credentials file, a human
  editing it by hand plus SIGHUP can race an API write. Declare the API
  the writer; document manual edits as "stop the package first," or have
  fs3 refuse to overwrite if the file's mtime changed since it last read
  it.
- **Don't put mutating endpoints on the TCP admin listener**, not even
  "just for localhost." Localhost is every local process.
- **Never log a secret,** including at debug level, including in the
  CGI's stderr, which DSM may capture.
