# CLAUDE.md — SigV4 implementation for fs3

This file is for Claude (or Claude Code) picking up the SigV4 work. Read
the project README first; this assumes you've done that. Everything
below is specific to **this codebase** — the hookpoints, conventions,
data structures, and gotchas you'll actually hit. Generic SigV4
explainers exist on the web; this is the bridge between them and our code.

## Goal

Implement AWS Signature V4 verification for incoming HTTP requests, so
the server can refuse unauthenticated traffic and round-trip with the
real AWS CLI / Boto / `mc` against `--endpoint-url
http://127.0.0.1:9000`.

We do header-mode SigV4 first (the `Authorization: AWS4-HMAC-SHA256
Credential=…, SignedHeaders=…, Signature=…` form). Streaming chunked
SigV4 (`x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) is a
follow-up phase, gated behind a clear interface.

## Order of work

Do these in order. Don't merge them. Each step is testable in
isolation, and each catches a different class of bug.

1. **Test vectors first.** AWS publishes canonical-request and
   string-to-sign test vectors at
   <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html>
   ("Examples of how to derive a signing key for Signature Version 4").
   Build a unit test that runs each vector through your SHA-256, your
   canonical-request builder, your string-to-sign builder, and your
   signing-key derivation — independently. **Do this before plumbing
   anything into the request path.** It's the only way to know you're
   computing the right bytes when handlers eventually fail with
   `SignatureDoesNotMatch` and you don't know whose fault it is.

2. **Header-mode verification.** Implement the verifier as a pure
   function: `(parsed request, credentials)` → `S3_OK` or
   `S3_ERR_SIGNATURE_DOES_NOT_MATCH`. No I/O. Test with curl + a known
   secret key, comparing against `aws s3api` requests captured with
   `--debug`.

3. **Plumb into the request path.** Wire the verifier at the hookpoint
   in `cb_on_headers_complete` (see below). Make sure the existing 21
   e2e tests still pass when running with auth disabled (config flag),
   and add new e2e tests for valid/invalid signatures with auth
   enabled.

4. **Body hash for non-streaming PUT.** Header-mode SigV4 requires the
   client to send `x-amz-content-sha256: <sha256-of-body>` (or the
   literal string `UNSIGNED-PAYLOAD`). For real verification we'd need
   to compute the body's SHA-256 as it streams in and compare. Defer
   this initially: accept whatever hash the client sent, treat it as
   advisory. Mark it `// TODO(sigv4-body-hash)` and move on.

5. **Streaming chunked SigV4.** Separate phase. New parser sits between
   llhttp and our `on_body`, decoding `aws-chunked` framing and
   verifying per-chunk signatures. Don't try to do this same-turn as
   header mode.

## The hookpoint

Open `src/conn.c` and find `cb_on_headers_complete`. The verifier slot
is marked:

```c
/* Phase 2 hook: SigV4 verification slots in here, before route
 * dispatch. Return HPE_PAUSED to give the verifier a chance, then
 * llhttp_resume() (or build a 403 and skip the body) below. */
```

The actual integration is simpler than that comment suggests because
the verifier is synchronous — you don't need `HPE_PAUSED`. Replace the
comment with:

```c
if (g_auth_required) {
    s3_err_t e = sigv4_verify(c);
    if (e != S3_OK) {
        return route_build_error(c, e);  /* sets CST_WRITE_RESPONSE */
    }
}
```

Where `route_build_error` is a small new helper in `route.c` that
builds an S3 error response and returns 0 (so llhttp continues to
on_message_complete which writes the response). Returning -1 from the
callback aborts the parser, which is wrong for an auth failure: we
want to send the 403 and keep the connection alive.

**Don't call `rsp_build_s3_error` directly here.** That bypasses the
route layer and would skip cleanup of any state that was set up
earlier in the callback. Use a route-layer wrapper.

## Codebase conventions you must follow

Read `src/route.c` and `src/response.c` once before writing. Patterns
in this codebase:

- **`s3_str_t` everywhere.** No null-terminated `char *` in
  signatures. All header values, headers, query strings are length-
  bounded views into existing buffers (`hdr_scratch` for headers,
  `req_scratch` for decoded query bytes). Don't strdup unless you
  need to outlive the request.

- **No allocation on the hot path.** Use `c->req_scratch` (per-request
  bump arena, 4 KB) for short-lived strings. The canonical request can
  exceed 4 KB for large header sets; if it does, `malloc` it and
  attach to `conn_t` (add a new field, free in `request_reset`).

- **Error codes are `s3_err_t`** declared in `include/s3.h`. The four
  you'll add or use:
  - `S3_ERR_SIGNATURE_DOES_NOT_MATCH` (already declared) — wrong
    signature
  - `S3_ERR_REQUEST_TIME_TOO_SKEWED` (already declared) — `x-amz-date`
    more than 15 min from server time
  - `S3_ERR_ACCESS_DENIED` (already declared) — missing/malformed
    Authorization header, unknown access key
  - You may need `S3_ERR_INVALID_AUTH_HEADER`. Add to the enum and to
    the `ERR_TABLE` in `response.c`.

- **OpenSSL is already linked** (`-lcrypto`). Use `EVP_*` for SHA-256
  and HMAC-SHA256 (`EVP_sha256()`). Don't pull in libssl. Look at
  `store_fs.c` for the existing usage pattern.

- **No global mutable state.** The `g_auth_required` above will need a
  home. Plumb it through `server_cfg_t` → `s3_store_t` (no, store is
  the wrong place) → a new `auth_t` opaque pointer attached to
  `conn_t->store`'s sibling field, OR add an `auth_t *auth` field to
  `conn_t` populated at `conn_create` time. Latter is simpler.

- **Header lookup**: `route.c` has a private static `hdr_get(conn_t,
  const char *lc_name)`. Promote it to `route.h` (or move into
  `conn.h`) before SigV4 needs it — the verifier will look up
  `authorization`, `x-amz-date`, `x-amz-content-sha256`, `host`, and
  whatever `SignedHeaders` lists. Header names in `conn_t->req.headers`
  are already lowercased.

- **Tests live in `tests/`.** Unit tests in C (`tests/test_sigv4.c`),
  integration tests via the existing `tests/test_e2e.sh`. Wire into
  `make test` by adding a `tests/test_sigv4` rule next to `test_store`.

## Module shape

Create `src/sigv4.c` and `include/sigv4.h`. Suggested API:

```c
/* include/sigv4.h */

typedef struct sigv4_creds {
    const char *access_key;   /* AKIA... */
    const char *secret_key;   /* the secret, NUL-terminated */
} sigv4_creds_t;

typedef struct sigv4_verifier sigv4_verifier_t;

/* Build a verifier with one or more credential records. The verifier
 * owns its credential strings. */
sigv4_verifier_t *sigv4_create(void);
int               sigv4_add_cred(sigv4_verifier_t *v,
                                 const char *access_key,
                                 const char *secret_key);
void              sigv4_destroy(sigv4_verifier_t *v);

/* Override "now" for testing (Unix epoch seconds). 0 = use real clock. */
void              sigv4_set_clock(sigv4_verifier_t *v, int64_t fixed_now);

/* Verify a request. `c` provides method, path (RAW, undecoded),
 * query, and headers via the existing conn_req_t fields. Returns:
 *   S3_OK                            — verified
 *   S3_ERR_ACCESS_DENIED             — missing Authorization header,
 *                                       malformed Credential, unknown
 *                                       access key
 *   S3_ERR_REQUEST_TIME_TOO_SKEWED   — x-amz-date > 15 min from now
 *   S3_ERR_SIGNATURE_DOES_NOT_MATCH  — signature mismatch
 *
 * On non-OK return, no other state is mutated. The body hash is NOT
 * verified here — that's a separate streaming concern. */
s3_err_t          sigv4_verify(const sigv4_verifier_t *v, const conn_t *c);
```

**Internal layout** for `src/sigv4.c`:

1. `EVP_*` helpers: `sha256(in, out)`, `hmac_sha256(key, key_len, msg,
   msg_len, out)`. Each ~10 lines.
2. **Canonical request builder.** This is the part that will be
   wrong. See "Canonical request gotchas" below.
3. **String-to-sign builder.** Trivial once canonical request is right.
4. **Signing key derivation.** Four chained HMAC-SHA256s. Easy.
5. `sigv4_verify` — top-level glue.

Keep these as separate file-static functions so each gets its own
unit test. Don't let "canonical request builder" become a 200-line
function.

## Canonical request gotchas

This is where SigV4 implementations go to die. In rough order of how
often they bite people, in **this** codebase specifically:

### Path — use the *raw, undecoded* path

S3 SigV4 canonicalizes the path differently from query strings. For
S3 specifically (different from generic SigV4), **the path is NOT
double-encoded**. AWS docs distinguish "S3" vs "non-S3" canonical
URI; we're S3, so:

- Take `c->req.path` exactly as it appears on the wire (still
  percent-encoded, no decode).
- Normalize `//` runs to `/`.
- Apply RFC 3986 unreserved-only normalization: any `%XX` that decodes
  to `[A-Za-z0-9-_.~]` should be decoded. Other `%XX` stay as-is.
- The leading `/` is preserved.

**Do not use `pct_decode` from `route.c`** — that's for handler-side
decoding. SigV4 needs the encoded form. Add a new
`sigv4_canon_path(s3_str_t in, char *out, size_t cap)` that does
exactly the spec'd normalization.

### Query string — sort by key, then by value

After splitting `c->req.query` on `&`:

- Decode each key and each value (full RFC 3986 decode, all percent
  escapes resolved to bytes).
- Sort the (key, value) pairs lexicographically by key, then by value.
- Re-encode each key and each value using **strict** RFC 3986
  encoding (which encodes `/` to `%2F`, encodes `=` in values, etc.
  — this differs from path encoding).
- Reassemble as `k1=v1&k2=v2…`.
- An empty query yields the empty string. A key with no `=` yields
  `k=` (empty value).

The encode/decode roundtrip is deliberate: it normalizes
inconsistent client encodings.

### Signed headers — lowercase, sorted, exact value normalization

The client tells you which headers it signed via the `SignedHeaders`
field of the Authorization header. For each:

- Take the value from `c->req.headers` (already lowercased keys, so
  match on lowercase).
- Trim leading/trailing OWS (space, tab).
- **Collapse internal sequential whitespace to a single space**,
  but only when the value is NOT inside double quotes. The S3 spec
  is hand-wavy here; `aws-c-auth` and the AWS SDKs collapse runs of
  ASCII whitespace to a single space. Match that.
- For multi-value headers (same key appearing twice), join values
  with `,` (no space). Our `conn_t->req.headers` doesn't currently
  preserve duplicates — it stores just the last one. Real S3 clients
  rarely send duplicates for signed headers, but be aware.

The canonical-headers section ends with a **blank line** (an extra
`\n` after the last header). Forgetting this is the #1 bug.

### `host` header is required and tricky

S3 SigV4 mandates that `host` is signed. We have it in
`c->req.headers` (llhttp captures the Host header). One gotcha: if the
client uses a non-default port, `host` includes `:port` and the
signature must include that. Don't strip the port.

### Body hash placeholder

Header-mode SigV4 expects the *trailing* line of the canonical request
to be the SHA-256 hex of the body, OR the literal string
`UNSIGNED-PAYLOAD`, OR `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` for chunked
mode. The client tells you which via the `x-amz-content-sha256`
header. **Use the value of that header verbatim** as the trailing line
of the canonical request; do not compute the body hash yourself in
this phase. (When you compute it, you compare against the header
value; if they differ, that's `XAmzContentSHA256Mismatch`.)

This means a client can lie about its body hash and get a valid
signature for the wrong body. That's fine for now — clients that lie
are signing themselves into a footgun, and the next phase fixes it.

### `x-amz-date` vs `Date` — prefer x-amz-date

SDKs always send `x-amz-date` in ISO 8601 basic format
(`20260430T123045Z`). Use it. Fall back to `Date` (RFC 1123) only if
absent. The skew check is ±15 minutes. Use `time(NULL)` from the
server (the existing code in `response.c` already does this for
`Last-Modified` formatting; mirror that).

## Configuration

Pre-SigV4 there's no auth config. Add a config file:

```
# /etc/fs3/auth.toml or wherever
auth_required = true   # default false for backwards-compat dev mode

[[user]]
access_key = "AKIAEXAMPLE1234567"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

[[user]]
access_key = "AKIAEXAMPLEUSER2"
secret_key = "anotherSecretKeyHereForUserTwoXXXXXX"
```

For the first cut, accept this as a CLI flag instead: `--auth
"access:secret"` repeated, `--require-auth` to enforce. TOML parsing is
a separate concern; don't gold-plate.

A `SIGHUP` handler that rereads the file is nice-to-have but not
required for the first ship.

## What "done" looks like

- `tests/test_sigv4` — unit tests for canonical request, string to
  sign, and signing key, each running AWS's published vectors.
- `tests/test_e2e.sh` adds at least these cases:
  - Valid signature → 200
  - Wrong secret → 403 with `SignatureDoesNotMatch` body
  - Skewed time → 403 with `RequestTimeTooSkewed` body
  - Missing Authorization → 403 with `AccessDenied` body
  - Unknown access key → 403 with `AccessDenied` body
  - `aws s3 ls --endpoint-url http://localhost:9000 s3://bucket` works
    against a real `aws` CLI invocation (separate test, may be skipped
    if `aws` not installed).
- All previously-passing tests still pass, both with and without auth
  enabled.
- Clean under release `-O2` and DEBUG (ASan + UBSan) builds.
- The 21 e2e tests run in both modes (auth on/off).

## Known traps to avoid

- **Don't try to make this work for AWS SDK v1's "Authorization without
  x-amz-date" form.** SDK v1 over HTTP/1.0 sometimes sends a Date
  header instead. Real S3 supports it; we don't need to. Reject with
  `AccessDenied` if `x-amz-date` is absent.

- **Don't conflate header lookup with header listing.** When iterating
  `SignedHeaders`, you're computing what to *include* in the canonical
  request. Each header name in `SignedHeaders` must exist in
  `c->req.headers` — if not, the request is malformed
  (`AccessDenied`).

- **Don't strdup the secret key into the canonical-request scratch.**
  Secrets stay in the verifier struct; the canonical request never
  contains them. (You'd be amazed how often this gets logged.)

- **Don't add SigV4 logic to `conn.c` or `route.c`.** Keep it in
  `src/sigv4.c`. The integration with `conn.c` is *one function call*.

- **Don't use `strcmp` or `memcmp` for signature comparison.** Use a
  constant-time compare to avoid timing leaks. OpenSSL provides
  `CRYPTO_memcmp`. Yes it matters; yes auditors will look.

- **The Makefile uses `-MMD -MP`** to track header dependencies. If
  you add `include/sigv4.h` and source files include it, dependencies
  pick up automatically. You don't need to declare them.

- **The packed `obj_header_t` in `store_fs.c` triggers a GCC false
  positive** that's silenced with a local `#pragma GCC diagnostic
  ignored "-Wstringop-overread"`. If you create new packed structs in
  `sigv4.c` (you shouldn't need to — SigV4 is all about strings), be
  aware.

## Useful breadcrumbs

- The XML library (in `third_party/xml/`) handles all error response
  bodies. It escapes content properly. `rsp_build_s3_error` in
  `response.c` is the function you want; route a new `s3_err_t` value
  through the existing `ERR_TABLE` if you add new ones.

- `s3_str_t` macros are in `include/s3.h`: `S3_STR_LIT("foo")` for
  literals, `S3_STR_FMT` and `S3_STR_ARG(s)` for printf, `s3_str_eq`
  and `s3_str_eq_lit` for comparisons.

- The route dispatcher splits the request into bucket+key in
  `parse_path` (`src/route.c`). Don't reimplement that; the
  signature is computed against the **raw path**, not the parsed
  bucket/key, so you don't even need this — but be aware it exists if
  you start wondering why path handling looks duplicated.

- `c->req.target` is the raw request-target as it appeared on the
  wire (path?query). `c->req.path` and `c->req.query` are the split
  components, also raw/undecoded. `c->req.headers` has lowercased
  keys.

- `c->store` and now `c->auth` (you'll add it) outlive the request.
  Don't free them.

## When you finish

Update `README.md`'s "What's *not* yet wired" list to remove SigV4.
Add a "What's wired in Phase 4" subsection or bump the phase number.
Add a brief operator note about `--auth` / config file in the "Run"
section.

## When you get stuck

Two debugging tactics that work specifically for this kind of bug:

1. **Run `aws --debug s3api ...` and capture its canonical request and
   string-to-sign.** Compare byte-for-byte with what your code
   produces. AWS CLI prints both in its debug output. The first
   difference is your bug.

2. **Hash everything as you go**, log the SHA-256 of the canonical
   request and the SHA-256 of the string-to-sign at DEBUG level. AWS
   CLI logs the same. If your hashes match AWS CLI's hashes, your
   strings are identical, and the only remaining variable is the
   signing key (which means a problem in HMAC chaining).

Don't add print-the-secret-to-the-log debugging. There's a temptation;
resist it.
