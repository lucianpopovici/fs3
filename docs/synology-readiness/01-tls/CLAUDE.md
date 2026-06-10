# CLAUDE.md — TLS / encryption in transit

> **STATUS: done via Option A, hardware test pending (2026-06-10).**
> SPK default bind is now `127.0.0.1` (`start-stop-status` defaults +
> `postinst`); the wizard offers an explicit "Expose on the LAN (plain
> HTTP)" opt-out that sets `FS3_BIND=0.0.0.0`. The README ("Synology
> deployment" section) and the DSM tile (`ui/index.cgi`) document the
> reverse-proxy setup and the SigV4 host-header trap. Still to verify
> on real DSM: that DSM's generated proxy config preserves the original
> Host header so signed requests validate end-to-end.

**Problem:** fs3 speaks plaintext HTTP only. SigV4 authenticates a
request (proves the sender holds the secret key and the body wasn't
tampered) but does **not** encrypt it. Credentials in the Authorization
header and object payloads both travel in the clear.

**Why it matters here specifically:** a NAS is more likely than a laptop
demo to be reachable beyond the trusted LAN — port-forwarded, on a VLAN
with other devices, accessed over Wi-Fi. Plaintext S3 there means anyone
on-path can read your objects and replay-capture enough to impersonate
you. Fine on an airgapped wired LAN; not fine otherwise.

## Current state

- The listener is a plain `socket`/`accept4` in `src/server.c`; bytes go
  straight into `c->rbuf` and through llhttp. No TLS layer anywhere.
- OpenSSL *is* already linked (`-lcrypto`) and used for SigV4 HMAC/SHA
  and MD5 — but `libssl` (the TLS half) is **not** linked. The
  Synology static build deliberately pins only `libcrypto.a`.

## Approach — recommend reverse proxy, not native TLS

Two paths. For a NAS, the reverse-proxy path is almost certainly the
right call.

### Option A (recommended): document the DSM reverse-proxy pattern

DSM has a built-in reverse proxy (Control Panel → Login Portal →
Advanced → Reverse Proxy) and manages Let's Encrypt certificates
natively. The clean architecture is:

```
client --HTTPS--> DSM nginx (TLS termination, real cert) --HTTP--> fs3 on 127.0.0.1:9000
```

This means:
- fs3 binds `127.0.0.1` only (not `0.0.0.0`), so it's unreachable except
  via the proxy. **Change the SPK default bind from `0.0.0.0` to
  `127.0.0.1`** and let the proxy be the only public face.
- DSM handles cert issuance/renewal — no cert code in fs3, no cert
  management burden.
- This is zero new C code. It's a documentation + default-config change.

Deliverable for Option A: a section in the README and the desktop-tile
info page showing exactly how to set up the DSM reverse proxy entry
(hostname → localhost:9000), plus flipping `FS3_BIND` default to
`127.0.0.1` in `start-stop-status` and the wizard. Note the SigV4 host
header subtlety below.

### Option B: native TLS in fs3

Only worth it if fs3 must run standalone off-DSM. Adds real surface:
link `libssl`, wrap the accept socket in `SSL_accept`, feed
`SSL_read`/`SSL_write` instead of `read`/`write` in `src/conn.c`, manage
cert/key file paths via new CLI flags, handle the TLS handshake state in
the epoll loop (non-blocking `SSL_ERROR_WANT_READ/WRITE`). This is a
multi-day change touching the hot path and the static-build story
(libssl.a is bigger and version-sensitive — the very thing the static
libcrypto build was avoiding). Defer unless there's a concrete need.

## Hookpoints

- Option A: `packaging/synology/scripts/start-stop-status` (`FS3_BIND`
  default), `packaging/synology/WIZARD_UIFILES/install_uifile`,
  `README.md`, `packaging/synology/ui/index.cgi` (tile instructions).
- Option B: `src/server.c` (accept path), `src/conn.c` (read/write
  abstraction — introduce a `conn_read`/`conn_write` indirection so TLS
  and plain share the state machine), `src/main.c` (`--tls-cert`,
  `--tls-key` flags), `Makefile` (link `-lssl`, static `libssl.a`).

## How to test

- Option A: on DSM, set up the reverse proxy, confirm
  `aws --endpoint-url https://nas.example.com s3 ls` works through it
  while `http://nas-ip:9000` is refused from another host (bind is
  localhost-only). Verify SigV4 still validates (see host-header trap).
- Option B: `openssl s_client` handshake, then a full signed round-trip
  over TLS; confirm the epoll loop handles partial handshakes under
  load; ASan + UBSan clean on the new read/write paths.

## What "done" looks like

- Option A: README + tile document the proxy setup; SPK defaults to
  binding localhost; a fresh install behind the DSM proxy round-trips
  over HTTPS and is unreachable in plaintext from the network.
- Option B (if pursued): `--tls-cert`/`--tls-key` bring up an HTTPS
  listener; all existing e2e suites pass over TLS; static build still
  produces a portable binary.

## Traps

- **SigV4 signs the `host` header.** When a client signs for
  `nas.example.com:443` but the proxy forwards to fs3 as
  `127.0.0.1:9000`, the host the client signed and the host fs3 sees
  differ — signature verification fails. Either (a) configure the proxy
  to preserve the original Host header AND have the client sign for that
  host (normal nginx `proxy_set_header Host $host;`), or (b) run fs3
  with auth disabled behind the proxy and let the proxy be the trust
  boundary. Document whichever you choose; this is the #1 thing that
  will look like "TLS broke auth" when it's actually the host header.
- **Don't bind `0.0.0.0` and add a proxy** — that leaves the plaintext
  port exposed alongside the TLS one, defeating the point. Bind
  localhost.
- **Option B static build:** linking `libssl.a` reintroduces exactly the
  OpenSSL-version coupling the libcrypto static build was designed to
  avoid. If you go native, re-test on both DSM 6 and DSM 7 OpenSSL.
