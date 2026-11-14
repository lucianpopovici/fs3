/* include/lockc.h — fs3's client for fs3-lockd (round 2, item 9). */
#ifndef FS3_LOCKC_H
#define FS3_LOCKC_H
#include <stddef.h>
#include <stdint.h>

/* One request line → reply ("OK" / "ERR …"). 0 when the helper said OK,
 * 1 when it refused (reply holds why), -1 when it could not be reached. */
int lockc_call(const char *sock, const char *req, char *reply, size_t cap);
int lockc_set(const char *sock, const char *path, uint64_t until_ms, int hold);
int lockc_hold_off(const char *sock, const char *path);
int lockc_clear(const char *sock, const char *path);
/* 1 if the file carries FS_IMMUTABLE_FL. */
int lockc_is_immutable(const char *path);
/* Startup probe on a scratch file in dir: SET (already expired) then
 * CLEAR must both work and toggle the flag. 0 ok, -1 with a message. */
int lockc_probe(const char *sock, const char *dir, char *why, size_t cap);
#endif
