/* include/tls.h — optional native TLS (item 7, Option B)
 *
 * Built only with `make TLS=1` (or the `fs3-tls` target), which defines
 * FS3_TLS and links libssl; the default and Synology static builds stay
 * libcrypto-only and run behind the DSM reverse proxy (Option A).
 *
 * Policy (ANSSI-style, as for BP-028): TLS 1.2+ only; TLS 1.2 limited
 * to ECDHE with AES-GCM or ChaCha20-Poly1305; groups X25519, P-256,
 * P-384; no renegotiation; server cipher preference; no session tickets
 * (no ticket-key rotation); ALPN http/1.1 only. kTLS is requested and
 * SSL_sendfile used when the kernel offers it; otherwise (DS1515+,
 * kernel 3.10) bodies go pread → SSL_write through a 64 KiB buffer.
 * Client-certificate (mTLS) authentication is deliberately not offered:
 * a certificate alone must not grant an S3 identity (review S8).
 */
#ifndef FS3_TLS_H
#define FS3_TLS_H

#include <stddef.h>
#include <sys/types.h>

struct conn;
struct s3_reader;

typedef struct tls_ctx tls_ctx_t;

/* 1 if this binary was built with TLS support. */
int tls_available(void);

/* Load cert chain + key into a new server context; NULL on error
 * (logged). */
tls_ctx_t *tls_ctx_new(const char *cert_file, const char *key_file);
/* Drop a reference (live connections keep theirs). */
void       tls_ctx_free(tls_ctx_t *t);

/* Attach a TLS session to an accepted connection (server side). */
int  tls_conn_attach(struct conn *c, tls_ctx_t *t);
void tls_conn_free(struct conn *c);

/* Non-blocking handshake step: 1 done, 0 in progress (want_* set),
 * -1 failed. */
int  tls_handshake(struct conn *c);

/* Like read()/write(): -1 with errno EAGAIN when the TLS layer would
 * block (c->tls_want_write tells the event loop to wait for EPOLLOUT). */
ssize_t tls_read(struct conn *c, void *buf, size_t n);
ssize_t tls_write(struct conn *c, const void *buf, size_t n);
/* Bytes OpenSSL holds already decrypted (epoll won't report them). */
size_t  tls_pending(const struct conn *c);
/* Send up to `max` body bytes from r: SSL_sendfile with kTLS, else a
 * buffered pread + SSL_write. >0 progress, 0 done, -1 errno. */
ssize_t tls_send_body(struct conn *c, struct s3_reader *r, size_t max);

#endif
