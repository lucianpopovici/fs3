#!/usr/bin/env bash
#
# tests/test_ui_cgi.sh — tests for the DSM tile admin console
# (packaging/synology/ui/index.cgi), driven against a scratch var dir
# via FS3_VAR_DIR:
#   1. GET rendering: defaults, conf parsing without sourcing, escaping
#   2. CSRF: token file lifecycle, token mismatch, Origin mismatch
#   3. addkey / delkey: validation, atomic 0600 writes, last-key guard
#   4. SIGHUP delivery to the recorded child pid
#   5. live bucket stats through a real fs3 admin listener
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CGI="$ROOT/packaging/synology/ui/index.cgi"
VAR=/tmp/fs3-ui-cgi-$$
DATA=/tmp/fs3-ui-cgi-data-$$
LOG=/tmp/fs3-ui-cgi-$$.log
PORT=${FS3_TEST_PORT:-$(( 19850 + RANDOM % 100 ))}
MPORT=$((PORT + 1))

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; }
    [ -n "${HUPPID:-}" ] && kill "$HUPPID" 2>/dev/null
    rm -rf "$VAR" "$DATA" "$LOG"
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1)

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then
        PASS=$((PASS+1)); printf '.'
    else
        FAIL=$((FAIL+1))
        printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"
    fi
}
check_has() {  # $1=desc $2=haystack $3=needle
    if printf '%s' "$2" | grep -qF -- "$3"; then
        PASS=$((PASS+1)); printf '.'
    else
        FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  missing: %s\n' "$1" "$3"
    fi
}
check_lacks() {  # $1=desc $2=haystack $3=needle
    if printf '%s' "$2" | grep -qF -- "$3"; then
        FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  must not contain: %s\n' "$1" "$3"
    else
        PASS=$((PASS+1)); printf '.'
    fi
}

cgi_get() {  # [query-string]
    env -i PATH="$PATH" FS3_VAR_DIR="$VAR" REQUEST_METHOD=GET \
        QUERY_STRING="${1:-}" SCRIPT_NAME=/webman/3rdparty/fs3/index.cgi \
        HTTP_HOST=nas.local:5000 sh "$CGI"
}
cgi_post() {  # $1=urlencoded-body [$2=Origin header]
    local body="$1"
    if [ -n "${2:-}" ]; then
        printf '%s' "$body" | env -i PATH="$PATH" FS3_VAR_DIR="$VAR" \
            REQUEST_METHOD=POST CONTENT_LENGTH="${#body}" \
            SCRIPT_NAME=/webman/3rdparty/fs3/index.cgi \
            HTTP_HOST=nas.local:5000 HTTP_ORIGIN="$2" sh "$CGI"
    else
        printf '%s' "$body" | env -i PATH="$PATH" FS3_VAR_DIR="$VAR" \
            REQUEST_METHOD=POST CONTENT_LENGTH="${#body}" \
            SCRIPT_NAME=/webman/3rdparty/fs3/index.cgi \
            HTTP_HOST=nas.local:5000 sh "$CGI"
    fi
}

mkdir -p "$VAR"
CONF="$VAR/fs3.conf"
CRED="$VAR/credentials"
TOK_FILE="$VAR/.ui-csrf"

# ===================================================================
# 1. GET rendering
# ===================================================================

# No conf at all: defaults render, package shows stopped.
page=$(cgi_get)
check_has  "default page renders title"    "$page" "fs3 Object Storage"
check_has  "default port in endpoint"      "$page" "9000"
check_has  "no pid file → stopped"         "$page" "stopped"
check_has  "stopped → stats need package"  "$page" "available while the package is running"

# Conf parsing: values are read but never executed, and HTML-escaped.
cat > "$CONF" <<EOF
# comment
FS3_PORT=9123
FS3_BIND="0.0.0.0"
FS3_DATA=/volume1/\$(touch /tmp/fs3-ui-cgi-pwned-$$)<script>
FS3_REQUIRE_AUTH=0
FS3_METRICS_PORT=0
EOF
page=$(cgi_get)
check_has   "conf port parsed"            "$page" "9123"
check_lacks "conf value not raw in HTML"  "$page" "<script>"
check_has   "conf value escaped in HTML"  "$page" "&lt;script&gt;"
[ -e "/tmp/fs3-ui-cgi-pwned-$$" ] \
    && { FAIL=$((FAIL+1)); printf '\nFAIL: conf value was executed as shell\n'; rm -f "/tmp/fs3-ui-cgi-pwned-$$"; } \
    || { PASS=$((PASS+1)); printf '.'; }

# The metrics-port-0 hint only shows for a *running* package (a stopped
# one explains itself first); fake a live pid with our own.
echo $$ > "$VAR/fs3.pid"
page=$(cgi_get)
check_has "metrics port 0 → stats hint" "$page" "need the admin listener"
rm -f "$VAR/fs3.pid"
page=$(cgi_get)

# CSRF token file: created by GET, 0600, 32 hex chars, rendered in form.
[ -s "$TOK_FILE" ] && { PASS=$((PASS+1)); printf '.'; } \
    || { FAIL=$((FAIL+1)); printf '\nFAIL: token file not created\n'; }
perm=$(stat -c %a "$TOK_FILE")
check_eq "token file is 0600" "$perm" "600"
TOKEN=$(cat "$TOK_FILE")
check_eq "token is 32 hex chars" "$(printf '%s' "$TOKEN" | grep -cE '^[0-9a-f]{32}$')" "1"
check_has "token rendered into form" "$page" "name=\"tok\" value=\"$TOKEN\""

# ===================================================================
# 2. CSRF protections
# ===================================================================

out=$(cgi_post "action=addkey&ak=testkey&sk=secretsecret&tok=WRONG")
check_has   "token mismatch → e_csrf" "$out" "m=e_csrf"
[ -f "$CRED" ] && { FAIL=$((FAIL+1)); printf '\nFAIL: credentials written despite bad token\n'; } \
    || { PASS=$((PASS+1)); printf '.'; }

out=$(cgi_post "action=addkey&ak=testkey&sk=secretsecret&tok=$TOKEN" "http://evil.example")
check_has   "cross-site Origin → e_csrf" "$out" "m=e_csrf"

out=$(cgi_post "action=addkey&ak=testkey&sk=secretsecret&tok=$TOKEN" "http://nas.local:5000")
check_has   "matching Origin accepted" "$out" "m=added"

# ===================================================================
# 3. addkey / delkey
# ===================================================================

# That first addkey created the file 0600 and enabled auth in the conf.
perm=$(stat -c %a "$CRED")
check_eq  "credentials file is 0600" "$perm" "600"
check_eq  "credential line written" "$(cat "$CRED")" "testkey:secretsecret"
check_eq  "first key flips FS3_REQUIRE_AUTH" \
          "$(grep -c '^FS3_REQUIRE_AUTH=1$' "$CONF" || true)" "1"
check_has "first key asks for a restart" "$out" "m=added_restart"

# Auth is now on; further changes reload the child via SIGHUP.
HUPFILE="$VAR/hup-received"
( trap 'echo got > "'"$HUPFILE"'"; exit 0' HUP
  while :; do sleep 0.1; done ) &
HUPPID=$!
echo "$HUPPID" > "$VAR/fs3.child.pid"

# Validation: bad charset (no URL-decode pass, so %xx is itself invalid).
out=$(cgi_post "action=addkey&ak=bad%3Akey&sk=secretsecret&tok=$TOKEN")
check_has "percent-encoded ak rejected" "$out" "m=e_ak"
out=$(cgi_post "action=addkey&ak=ok&sk=secretsecret&tok=$TOKEN")
check_has "too-short ak rejected" "$out" "m=e_ak"
out=$(cgi_post "action=addkey&ak=secondkey&sk=short&tok=$TOKEN")
check_has "too-short sk rejected" "$out" "m=e_sk"
check_eq  "rejected posts wrote nothing" "$(wc -l < "$CRED" | tr -d ' ')" "1"

# Add a second key, replace the first one's secret.
out=$(cgi_post "action=addkey&ak=secondkey&sk=second-secret.1&tok=$TOKEN")
check_has "second key added (no restart)" "$out" "m=added"
check_lacks "second key needs no restart" "$out" "m=added_restart"
out=$(cgi_post "action=addkey&ak=testkey&sk=replaced-secret&tok=$TOKEN")
check_has "replace existing key" "$out" "m=added"
check_eq  "replace keeps one line per key" "$(wc -l < "$CRED" | tr -d ' ')" "2"
check_eq  "replaced secret stored" \
          "$(grep -c '^testkey:replaced-secret$' "$CRED" || true)" "1"

# Users: buckets belong to a key's user, so the console must write the
# optional user field and never drop it when a key's secret is replaced.
out=$(cgi_post "action=addkey&ak=rotkey&sk=rotsecret-1&user=alice&tok=$TOKEN")
check_has "key with user added" "$out" "m=added"
check_eq  "user written as third field" \
          "$(grep -c '^rotkey:rotsecret-1:alice$' "$CRED" || true)" "1"
out=$(cgi_post "action=addkey&ak=rotkey&sk=rotsecret-2&tok=$TOKEN")
check_eq  "replacing the secret keeps the user" \
          "$(grep -c '^rotkey:rotsecret-2:alice$' "$CRED" || true)" "1"
out=$(cgi_post "action=addkey&ak=rotkey&sk=rotsecret-3&user=bob&tok=$TOKEN")
check_eq  "an explicit user replaces it" \
          "$(grep -c '^rotkey:rotsecret-3:bob$' "$CRED" || true)" "1"
out=$(cgi_post "action=addkey&ak=rotkey&sk=rotsecret-4&user=bad%3Auser&tok=$TOKEN")
check_has "invalid user rejected" "$out" "m=e_user"
check_eq  "rejected user wrote nothing" \
          "$(grep -c '^rotkey:rotsecret-3:bob$' "$CRED" || true)" "1"
page=$(cgi_get)
check_has   "page shows a key's user" "$page" "<code>bob</code>"
check_has   "page marks a key that is its own user" "$page" "testkey (the key itself)"
check_lacks "page never shows secrets" "$page" "rotsecret-3"
out=$(cgi_post "action=delkey&ak=rotkey&tok=$TOKEN")
check_has "key with user removed" "$out" "m=removed"
check_eq  "back to two keys" "$(wc -l < "$CRED" | tr -d ' ')" "2"

# SIGHUP reached the recorded child pid.
for _ in $(seq 1 20); do [ -f "$HUPFILE" ] && break; sleep 0.1; done
[ -f "$HUPFILE" ] && { PASS=$((PASS+1)); printf '.'; } \
    || { FAIL=$((FAIL+1)); printf '\nFAIL: child pid never got SIGHUP\n'; }

# Secrets never render back into the page.
page=$(cgi_get)
check_has   "page lists access keys"   "$page" "testkey"
check_has   "page lists second key"    "$page" "secondkey"
check_lacks "page never shows secrets" "$page" "replaced-secret"
check_lacks "page never shows secrets" "$page" "second-secret.1"

# delkey: unknown key, then a real one, then the last-key guard.
out=$(cgi_post "action=delkey&ak=nosuchkey&tok=$TOKEN")
check_has "delkey unknown → e_nokey" "$out" "m=e_nokey"
out=$(cgi_post "action=delkey&ak=secondkey&tok=$TOKEN")
check_has "delkey removes" "$out" "m=removed"
check_eq  "removed key gone from file" "$(grep -c '^secondkey:' "$CRED" || true)" "0"
out=$(cgi_post "action=delkey&ak=testkey&tok=$TOKEN")
check_has "last key protected while auth on" "$out" "m=e_last"
check_eq  "last key still present" "$(grep -c '^testkey:' "$CRED" || true)" "1"

# Unknown action and oversized body are rejected.
out=$(cgi_post "action=reboot&tok=$TOKEN")
check_has "unknown action → e_req" "$out" "m=e_req"

kill "$HUPPID" 2>/dev/null || true; HUPPID=

# ===================================================================
# 4. Live bucket stats via a real fs3 admin listener
# ===================================================================
mkdir -p "$DATA"
"$ROOT/fs3" -p "$PORT" -d "$DATA" --metrics-port "$MPORT" >"$LOG" 2>&1 &
SP=$!
sleep 0.4
kill -0 "$SP" 2>/dev/null || { echo "fs3 did not start" >&2; cat "$LOG" >&2; exit 1; }

curl -s -X PUT "http://127.0.0.1:$PORT/cgibuk" >/dev/null
printf '12345' | curl -s -X PUT "http://127.0.0.1:$PORT/cgibuk/obj" \
    --data-binary @- >/dev/null

cat > "$CONF" <<EOF
FS3_PORT=$PORT
FS3_BIND=0.0.0.0
FS3_DATA=$DATA
FS3_REQUIRE_AUTH=0
FS3_METRICS_PORT=$MPORT
EOF
echo "$SP" > "$VAR/fs3.pid"

page=$(cgi_get)
check_has "live page shows running"     "$page" ">running</span>"
check_has "live page shows bucket row"  "$page" "<code>cgibuk</code>"
check_has "live page shows object count" "$page" "<td>1</td>"
check_has "live page shows size"        "$page" "5 B"

kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; SP=

printf '\n===== ui cgi: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
