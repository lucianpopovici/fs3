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
#   6. DSM sign-in / administrators gate
#   7. settings form: rendering, validation, conf writes, restart, restore
#   8. object browser: listing, streamed upload/download, share links, delete
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

# DSM sign-in is simulated: AUTH_CMD prints the signed-in user, GROUPS_CMD
# that user's groups (on DSM the CGI runs authenticate.cgi and `id -Gn`).
AUTH_CMD="echo admin"
GROUPS_CMD="echo administrators users"
PKG="$ROOT/packaging/synology"
cgi_env() {
    env -i PATH="$PATH" FS3_VAR_DIR="$VAR" FS3_PKG_DIR="$PKG" \
        FS3_UI_AUTH_CMD="$AUTH_CMD" FS3_UI_GROUPS_CMD="$GROUPS_CMD" \
        SCRIPT_NAME=/webman/3rdparty/fs3/index.cgi HTTP_HOST=nas.local:5000 "$@"
}
cgi_get() {  # [query-string]
    cgi_env REQUEST_METHOD=GET QUERY_STRING="${1:-}" sh "$CGI"
}
cgi_post() {  # $1=urlencoded-body [$2=Origin header]
    local body="$1"
    if [ -n "${2:-}" ]; then
        printf '%s' "$body" | cgi_env REQUEST_METHOD=POST CONTENT_LENGTH="${#body}" \
            HTTP_ORIGIN="$2" sh "$CGI"
    else
        printf '%s' "$body" | cgi_env REQUEST_METHOD=POST CONTENT_LENGTH="${#body}" sh "$CGI"
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
# Key attributes (round 2, item 4): a secret change keeps them, and the
# page shows a status column without leaking the attributes as a user.
sed -i 's/^rotkey:rotsecret-3:bob$/rotkey:rotsecret-3:bob:created=1763107200,ro,disabled/' "$CRED"
out=$(cgi_post "action=addkey&ak=rotkey&sk=rotsecret-5&tok=$TOKEN")
check_eq  "replacing the secret keeps the attributes" \
          "$(grep -c '^rotkey:rotsecret-5:bob:created=1763107200,ro,disabled$' "$CRED" || true)" "1"
page=$(cgi_get)
check_has   "status column: disabled + read-only" "$page" "disabled read-only"
check_has   "user shown without attributes" "$page" "<code>bob</code>"
check_lacks "attributes not shown as part of the user" "$page" "bob:created"
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
${FS3_WRAP:-} "$ROOT/fs3" -p "$PORT" -d "$DATA" --metrics-port "$MPORT" \
    --admin-socket "$VAR/admin.sock" >"$LOG" 2>&1 &
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
echo "$SP" > "$VAR/fs3.child.pid"

page=$(cgi_get)
check_has "live page shows running"     "$page" ">running</span>"
check_has "live page shows bucket row"  "$page" "<code>cgibuk</code>"
check_has "live page shows object count" "$page" "<td>1</td>"
check_has "live page shows size"        "$page" "5 B"

# Replication through the admin API socket.
TOKEN=$(cat "$TOK_FILE")
check_has "replication: empty state"    "$page" "No bucket replicates yet"
check_has "replication: rule form"      "$page" "Replicate a bucket"
RSEC=tileReplSecret0123456789
rform() { printf 'action=setrepl&tok=%s&rb=cgibuk&rep=%s&rbk=target-bkt&rak=AKTILE&rsk=%s&rpfx=docs%%2F&rplain=1%s' \
              "$TOKEN" "$1" "$RSEC" "${2:-}"; }
out=$(cgi_post "$(rform 'http%3A%2F%2F127.0.0.1%3A1')")
check_has "replication: rule saved"     "$out" "m=repl_set"
page=$(cgi_get "m=repl_set")
check_has "replication: row shown"      "$page" "<code>http://127.0.0.1:1/target-bkt</code>"
check_has "replication: sync button"    "$page" 'value="syncrepl"'
check_lacks "replication: secret never rendered" "$page" "$RSEC"
check_eq "replication: deletes off by default" \
    "$(curl -s --unix-socket "$VAR/admin.sock" http://x/v1/buckets/cgibuk/replication | grep -c '"deletes":false' || true)" "1"
check_eq "replication: prefix decoded" \
    "$(curl -s --unix-socket "$VAR/admin.sock" http://x/v1/buckets/cgibuk/replication | grep -c '"prefix":"docs/"' || true)" "1"
out=$(cgi_post "$(rform 'http%3A%2F%2F8.8.8.8')")
check_has "replication: public plain http refused by fs3" "$out" "m=e_repl_rule"
out=$(cgi_post "$(rform 'https%3A%2F%2Fh%22%2C%22x%22%3A%221')")
check_has "replication: JSON injection refused" "$out" "m=e_repl_in"
out=$(cgi_post "$(rform 'ftp%3A%2F%2Fh')")
check_has "replication: bad scheme refused" "$out" "m=e_repl_in"
out=$(cgi_post "action=setrepl&tok=wrong&rb=cgibuk&rep=x&rbk=y&rak=z")
check_has "replication: CSRF enforced"  "$out" "m=e_csrf"
out=$(cgi_post "action=syncrepl&tok=$TOKEN&rb=cgibuk")
check_has "replication: sync started"   "$out" "m=repl_sync"
out=$(cgi_post "action=delrepl&tok=$TOKEN&rb=cgibuk")
check_has "replication: rule removed"   "$out" "m=repl_removed"
out=$(cgi_post "action=delrepl&tok=$TOKEN&rb=cgibuk")
check_has "replication: removing again → no rule" "$out" "m=e_repl_bucket"
out=$(cgi_post "action=delrepl&tok=$TOKEN&rb=..%2Fx")
check_has "replication: bad bucket name" "$out" "m=e_repl_in"
mv "$VAR/admin.sock" "$VAR/admin.sock.off"
out=$(cgi_post "action=syncrepl&tok=$TOKEN&rb=cgibuk")
check_has "replication: socket missing reported" "$out" "m=e_repl_sock"
mv "$VAR/admin.sock.off" "$VAR/admin.sock"

kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; SP=

# ===================================================================
# 5. Object browser (signed: fs3 with a key for the bucket owner)
# ===================================================================
OAK=AKIATILEOWNER001; OSK=tileOwnerSecret01234567890123456789012
rm -f "$VAR/admin.sock"
${FS3_WRAP:-} "$ROOT/fs3" -p "$PORT" -d "$DATA" --metrics-port "$MPORT" \
    --auth "$OAK:$OSK" --require-auth --admin-socket "$VAR/admin.sock" >>"$LOG" 2>&1 &
SP=$!
for _ in $(seq 50); do [ -S "$VAR/admin.sock" ] && break; sleep 0.1; done
echo "$SP" > "$VAR/fs3.pid"; echo "$SP" > "$VAR/fs3.child.pid"
curl -s --unix-socket "$VAR/admin.sock" -X PUT -d "{\"owner\":\"$OAK\"}" http://x/v1/buckets/cgibuk/owner >/dev/null
cgi_upload() {  # $1=query $2=file [$3=token]
    cgi_env REQUEST_METHOD=POST QUERY_STRING="$1" CONTENT_LENGTH="$(wc -c < "$2" | tr -d ' ')" \
        HTTP_X_FS3_TOKEN="${3-$TOKEN}" sh "$CGI" < "$2"
}
printf 'hello <tile>' > "$VAR/up1"
head -c 3000000 /dev/urandom > "$VAR/up2"
out=$(cgi_upload "a=upload&b=cgibuk&k=docs/a%20%3Cb%3E.txt" "$VAR/up1")
check_has "browser: upload ok"            "$out" "ok"
out=$(cgi_upload "a=upload&b=cgibuk&k=docs/big.bin" "$VAR/up2")
check_has "browser: 3 MB upload ok"       "$out" "ok"
out=$(cgi_upload "a=upload&b=cgibuk&k=x" "$VAR/up1" WRONG)
check_has "browser: upload needs the token" "$out" "e_csrf"
out=$(cgi_upload "a=upload&b=cgibuk&k=x" "$VAR/up1" "")
check_has "browser: upload without token refused" "$out" "e_csrf"
out=$(cgi_env REQUEST_METHOD=POST QUERY_STRING="a=upload&b=cgibuk&k=x" CONTENT_LENGTH=12 \
      HTTP_X_FS3_TOKEN="$TOKEN" HTTP_ORIGIN=http://evil.example sh "$CGI" < "$VAR/up1")
check_has "browser: cross-origin upload refused" "$out" "e_csrf"
out=$(cgi_upload "a=upload&b=cgibuk&k=bad%2" "$VAR/up1")
check_has "browser: malformed key refused" "$out" "e_req"
out=$(cgi_upload "a=upload&b=cgibuk&k=a'b" "$VAR/up1")
check_has "browser: quote in key refused" "$out" "e_req"
out=$(cgi_upload "a=upload&b=..&k=x" "$VAR/up1")
check_has "browser: bad bucket refused"   "$out" "e_req"
check_eq "browser: stored through fs3" \
    "$(curl -s --unix-socket "$VAR/admin.sock" "http://x/v1/buckets/cgibuk/objects?prefix=docs/&format=tsv" | grep -c '^O' || true)" 2

page=$(cgi_get)
check_has "browser: bucket links to the browser" "$page" "?v=browse&amp;b=cgibuk"
page=$(cgi_get "v=browse&b=cgibuk")
check_has "browser: folder row"           "$page" "p=docs/\">docs/</a>"
check_has "browser: root object row"      "$page" "v=get&amp;b=cgibuk&amp;k=obj\">obj</a>"
check_has "browser: upload widget"        "$page" 'id="files"'
check_has "browser: token in the page"    "$page" "$TOKEN"
page=$(cgi_get "v=browse&b=cgibuk&p=docs/")
check_has "browser: name escaped"         "$page" "a &lt;b&gt;.txt"
check_lacks "browser: no raw markup"      "$page" "a <b>.txt"
check_has "browser: size"                 "$page" "2.9 MiB"
check_has "browser: breadcrumbs"          "$page" "p=docs/\">docs</a>"
check_has "browser: share form"           "$page" 'value="share"'
page=$(cgi_get "v=browse&b=..%2Fetc")
check_has "browser: bad bucket → 400"     "$page" "Status: 400"
page=$(cgi_get "v=browse&b=cgibuk&p=%3Cscript%3E")
check_lacks "browser: prefix never reflected raw" "$page" "<script>alert"

dl=$(cgi_get "v=get&b=cgibuk&k=docs/a%20%3Cb%3E.txt")
check_has "browser: download disposition" "$dl" "filename*=UTF-8''a%20%3Cb%3E.txt"
check_has "browser: download length"      "$dl" "Content-Length: 12"
check_has "browser: download body"        "$dl" "hello <tile>"
check_eq "browser: big download intact" \
    "$(cgi_get "v=get&b=cgibuk&k=docs/big.bin" | tail -c 3000000 | md5sum | cut -d' ' -f1)" \
    "$(md5sum < "$VAR/up2" | cut -d' ' -f1)"
dl=$(cgi_get "v=get&b=cgibuk&k=nope")
check_has "browser: missing object → 404" "$dl" "Status: 404"

out=$(cgi_post "action=share&tok=$TOKEN&ob=cgibuk&ok=docs/big.bin&op=docs/&exp=3600")
check_has "browser: share page"           "$out" "Share link"
url=$(printf '%s' "$out" | sed -n 's/.*value="\([^"]*\)".*/\1/p' | sed 's/&amp;/\&/g')
check_has "browser: share link host"      "$url" "http://nas.local:$PORT/cgibuk/docs/big.bin?X-Amz-Algorithm="
check_eq "browser: share link works" \
    "$(curl -s -H "Host: nas.local:$PORT" "http://127.0.0.1:$PORT${url#http://nas.local:$PORT}" | md5sum | cut -d' ' -f1)" \
    "$(md5sum < "$VAR/up2" | cut -d' ' -f1)"
out=$(cgi_post "action=share&tok=$TOKEN&ob=cgibuk&ok=docs/big.bin&op=docs/&exp=99")
check_has "browser: bad expiry refused"   "$out" "m=e_req"
out=$(cgi_post "action=share&tok=wrong&ob=cgibuk&ok=docs/big.bin&exp=3600")
check_has "browser: share needs CSRF"     "$out" "m=e_csrf"
check_eq "browser: presigns audited in the log" \
    "$(grep -c 'admin: presign GET bucket cgibuk key docs/big.bin' "$LOG" || true)" 2

out=$(cgi_post "action=objdel&tok=$TOKEN&ob=cgibuk&ok=docs/big.bin&op=docs/")
check_has "browser: deleted"              "$out" "m=obj_deleted"
check_has "browser: back in the folder"   "$out" "v=browse&b=cgibuk&p=docs/"
check_eq "browser: gone" \
    "$(curl -s --unix-socket "$VAR/admin.sock" "http://x/v1/buckets/cgibuk/objects?prefix=docs/&format=tsv" | grep -c 'big.bin' || true)" 0
out=$(cgi_post "action=objdel&tok=wrong&ob=cgibuk&ok=docs/x")
check_has "browser: delete needs CSRF"    "$out" "m=e_csrf"

# No usable key: the owner's only key disabled → the browser says so.
curl -s --unix-socket "$VAR/admin.sock" -X PUT -d '{"owner":"nobody"}' http://x/v1/buckets/cgibuk/owner >/dev/null
out=$(cgi_post "action=objdel&tok=$TOKEN&ob=cgibuk&ok=obj&op=")
check_has "browser: no usable key reported" "$out" "m=e_nokey"
check_has "browser: no-key message" "$(cgi_get "v=browse&b=cgibuk&m=e_nokey")" "no usable key"

# Bound to 127.0.0.1 without a public host: share links refused.
sed -i 's/^FS3_BIND=.*/FS3_BIND=127.0.0.1/' "$CONF"
out=$(cgi_post "action=share&tok=$TOKEN&ob=cgibuk&ok=obj&op=&exp=3600")
check_has "browser: share needs a public host" "$out" "m=e_noshare"
printf 'FS3_PUBLIC_HOST=s3.example.com\n' >> "$CONF"
curl -s --unix-socket "$VAR/admin.sock" -X PUT -d "{\"owner\":\"$OAK\"}" http://x/v1/buckets/cgibuk/owner >/dev/null
out=$(cgi_post "action=share&tok=$TOKEN&ob=cgibuk&ok=obj&op=&exp=86400")
check_has "browser: public-host share link" "$out" "https://s3.example.com/cgibuk/obj?X-Amz-"
sed -i -e 's/^FS3_BIND=.*/FS3_BIND=0.0.0.0/' -e '/^FS3_PUBLIC_HOST=/d' "$CONF"

kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; SP=
rm -f "$VAR/fs3.pid" "$VAR/fs3.child.pid"

# ===================================================================
# 6. DSM sign-in / administrators gate
# ===================================================================
TOKEN=$(cat "$TOK_FILE")
AUTH_CMD="true"                                   # not signed in to DSM
page=$(cgi_get)
check_has   "not signed in → 403"             "$page" "Status: 403"
check_lacks "not signed in → no token"        "$page" "$TOKEN"
check_lacks "not signed in → no keys"         "$page" "testkey"
check_lacks "not signed in → no settings"     "$page" "FS3_TRUSTED_PROXY"
cp "$CRED" "$VAR/cred.before"
out=$(cgi_post "action=addkey&ak=sneaky&sk=sneakysecret&tok=$TOKEN")
check_has   "not signed in → POST refused"    "$out" "Status: 403"
check_eq    "refused POST wrote nothing" "$(cmp -s "$CRED" "$VAR/cred.before" && echo same)" "same"
AUTH_CMD="echo bob"; GROUPS_CMD="echo users"      # signed in, not an admin
page=$(cgi_get)
check_has   "non-admin → 403"                 "$page" "Only DSM administrators"
check_lacks "non-admin → no token"            "$page" "$TOKEN"
out=$(cgi_post "action=savecfg&tok=$TOKEN&FS3_PORT=9555")
check_has   "non-admin → POST refused"        "$out" "Status: 403"
AUTH_CMD="echo admin"; GROUPS_CMD="echo administrators users"
page=$(cgi_get)
check_has   "admin → page"                    "$page" "Signed in as"
check_has   "admin → token"                   "$page" "$TOKEN"

# ===================================================================
# 7. Settings form
# ===================================================================
printf '# kept comment\nFS3_DATA=%s\nFS3_REQUIRE_AUTH=1\nFS3_UNKNOWN=keepme\n' "$DATA" > "$CONF"
page=$(cgi_get)
check_has   "settings section"                "$page" "<h3>Settings</h3>"
check_has   "trusted proxy field, default"    "$page" 'name="FS3_TRUSTED_PROXY" id="FS3_TRUSTED_PROXY" value="127.0.0.1"'
check_has   "dedup select"                    "$page" '<select name="FS3_DEDUP"'
check_has   "audit checkbox"                  "$page" 'name="FS3_AUDIT_LOG" id="FS3_AUDIT_LOG" value="1"'
check_lacks "no restore button without backup" "$page" "restorecfg"

form() {  # the form at the current defaults, then overrides "K=V"...
    local b="action=savecfg&tok=$TOKEN&FS3_PORT=9000&FS3_BIND=127.0.0.1&FS3_TRUSTED_PROXY=127.0.0.1"
    b="$b&FS3_METRICS_PORT=9101&FS3_DEDUP=off&FS3_FS_COMPRESS=off&FS3_REFLINK=auto&FS3_SECCOMP=enforce&FS3_ADMIN_SOCKET=1"
    for o in "$@"; do b="$b&$o"; done
    printf '%s' "$b"
}
out=$(cgi_post "$(form)")
check_has "unchanged form → cfg_same"         "$out" "m=cfg_same"
check_eq  "unchanged form → no backup" "$([ -f "$CONF.bak" ] && echo yes || echo no)" "no"

out=$(cgi_post "$(form FS3_PORT=9555 FS3_DEDUP=owner FS3_AUDIT_LOG=1 'FS3_TRUSTED_PROXY=127.0.0.1%2C+10.0.0.1' FS3_WEB_ROOT_DOMAIN=web.lan FS3_NOT_A_KEY=1)")
check_has "valid save, stopped → cfg_saved"   "$out" "m=cfg_saved"
check_eq  "port written"        "$(grep -c '^FS3_PORT=9555$' "$CONF" || true)" "1"
check_eq  "dedup written"       "$(grep -c '^FS3_DEDUP=owner$' "$CONF" || true)" "1"
check_eq  "checkbox written"    "$(grep -c '^FS3_AUDIT_LOG=1$' "$CONF" || true)" "1"
check_eq  "list stored without spaces" "$(grep -c '^FS3_TRUSTED_PROXY=127.0.0.1,10.0.0.1$' "$CONF" || true)" "1"
check_eq  "defaults omitted"    "$(grep -c '^FS3_BIND=' "$CONF" || true)" "0"
check_eq  "unknown form key ignored" "$(grep -c 'FS3_NOT_A_KEY' "$CONF" || true)" "0"
check_eq  "comment kept"        "$(grep -c '^# kept comment$' "$CONF" || true)" "1"
check_eq  "data folder kept"    "$(grep -cx "FS3_DATA=$DATA" "$CONF" || true)" "1"
check_eq  "auth switch kept"    "$(grep -c '^FS3_REQUIRE_AUTH=1$' "$CONF" || true)" "1"
check_eq  "unknown conf key kept" "$(grep -c '^FS3_UNKNOWN=keepme$' "$CONF" || true)" "1"
check_eq  "conf is 0600"        "$(stat -c %a "$CONF")" "600"
check_eq  "backup made"         "$([ -f "$CONF.bak" ] && echo yes || echo no)" "yes"
page=$(cgi_get)
check_has "saved value rendered"   "$page" 'name="FS3_PORT" id="FS3_PORT" value="9555"'
check_has "restore button offered" "$page" "restorecfg"

# A second save keeps one managed block, and an unchecked box turns off.
out=$(cgi_post "$(form FS3_PORT=9555 FS3_DEDUP=owner 'FS3_TRUSTED_PROXY=127.0.0.1,10.0.0.1' FS3_WEB_ROOT_DOMAIN=web.lan)")
check_eq  "one managed block"   "$(grep -c '^# Settings below are managed' "$CONF" || true)" "1"
check_eq  "unchecked box off"   "$(grep -c '^FS3_AUDIT_LOG=' "$CONF" || true)" "0"

# Validation: nothing is written on any error.
cp "$CONF" "$VAR/conf.before"
unchanged() { cmp -s "$CONF" "$VAR/conf.before" && echo same || echo changed; }
out=$(cgi_post "$(form FS3_PORT=99999)")
check_has "bad port → e_cfg.FS3_PORT"         "$out" "m=e_cfg.FS3_PORT"
check_eq  "bad port wrote nothing" "$(unchanged)" "same"
page=$(cgi_get "m=e_cfg.FS3_PORT")
check_has "error names the field label"       "$page" "invalid value for <b>S3 port</b>"
page=$(cgi_get "m=e_cfg.<script>")
check_lacks "error never reflects input"      "$page" "<script>"
out=$(cgi_post "$(form 'FS3_WEB_ROOT_DOMAIN=evil.lan%0AFS3_ALLOW_PUBLIC%3D1')")
check_has "newline smuggling rejected"        "$out" "m=e_cfg.FS3_WEB_ROOT_DOMAIN"
check_eq  "smuggling wrote nothing" "$(unchanged)" "same"
out=$(cgi_post "$(form 'FS3_ADMIN=al%24(id)ice')")
check_has "shell metacharacters rejected"     "$out" "m=e_cfg.FS3_ADMIN"
out=$(cgi_post "$(form FS3_DEDUP=everything)")
check_has "bad enum rejected"                 "$out" "m=e_cfg.FS3_DEDUP"
out=$(cgi_post "$(form 'FS3_TRUSTED_PROXY=1.2.3.4,nas.local')")
check_has "host name in proxy list rejected"  "$out" "m=e_cfg.FS3_TRUSTED_PROXY"
out=$(cgi_post "$(form FS3_MAX_BODY_SIZE=5T)")
check_has "bad size rejected"                 "$out" "m=e_cfg.FS3_MAX_BODY_SIZE"
out=$(cgi_post "$(form FS3_METRICS_PORT=9000)")
check_has "port clash → e_ports"              "$out" "m=e_ports"
out=$(cgi_post "$(form FS3_WEB_PORT=9101)")
check_has "website/admin port clash"          "$out" "m=e_ports"
out=$(cgi_post "$(form FS3_LOCK_IMMUTABLE=1)")
check_has "immutable without lockd → e_lockd" "$out" "m=e_lockd"
out=$(cgi_post "action=savecfg&tok=WRONG&FS3_PORT=9600")
check_has "settings need the CSRF token"      "$out" "m=e_csrf"
check_eq  "rejected posts wrote nothing" "$(unchanged)" "same"
out=$(cgi_post "$(form FS3_SECCOMP=require)")
if grep -q '^Seccomp:' /proc/self/status 2>/dev/null; then
    check_has "require accepted where seccomp exists" "$out" "m=cfg_saved"
else
    check_has "require refused without seccomp"       "$out" "m=e_seccomp"
fi
# Public write implies public.
out=$(cgi_post "$(form FS3_PORT=9555 FS3_DEDUP=owner 'FS3_TRUSTED_PROXY=127.0.0.1,10.0.0.1' FS3_WEB_ROOT_DOMAIN=web.lan FS3_ALLOW_PUBLIC_WRITE=1)")
check_eq  "public write implies public" "$(grep -c '^FS3_ALLOW_PUBLIC=1$' "$CONF" || true)" "1"

# Save while running: the watchdog is asked to restart fs3.
( trap 'exit 0' TERM; while :; do sleep 0.1; done ) &
WD=$!
( trap 'echo term > "$VAR/child-term"; exit 0' TERM; while :; do sleep 0.1; done ) &
CH=$!
echo "$WD" > "$VAR/fs3.pid"; echo "$CH" > "$VAR/fs3.child.pid"
page=$(cgi_get)
check_has "running → restart button"          "$page" 'value="restart"'
out=$(cgi_post "$(form FS3_PORT=9556)")
check_has "save while running → cfg_restarted" "$out" "m=cfg_restarted"
check_eq  "restart request left for the watchdog" "$([ -f "$VAR/fs3.restart" ] && echo yes || echo no)" "yes"
for _ in $(seq 1 30); do [ -f "$VAR/child-term" ] && break; sleep 0.1; done
check_eq  "fs3 child got SIGTERM" "$([ -f "$VAR/child-term" ] && echo yes || echo no)" "yes"
wait "$CH" 2>/dev/null || true
rm -f "$VAR/fs3.child.pid" "$VAR/fs3.restart"
echo "fs3: listen 127.0.0.1:9556: Address in use <b>" >> "$VAR/fs3.log"
page=$(cgi_get)
check_has "watchdog without child → restarting" "$page" ">restarting</span>"
check_has "log tail shown, escaped"           "$page" "Address in use &lt;b&gt;"
out=$(cgi_post "action=restart&tok=$TOKEN")
check_has "restart button works"              "$out" "m=restarted"
kill "$WD" 2>/dev/null; wait "$WD" 2>/dev/null || true
rm -f "$VAR/fs3.pid" "$VAR/fs3.restart"

# Restore swaps the previous settings back in.
before="$(cat "$CONF.bak")"
out=$(cgi_post "action=restorecfg&tok=$TOKEN")
check_has "restore → cfg_restored"            "$out" "m=cfg_restored"
check_eq  "restored conf is the old backup"   "$(cat "$CONF")" "$before"
check_eq  "previous conf became the backup"   "$(grep -c '^FS3_PORT=9556$' "$CONF.bak" || true)" "1"
out=$(cgi_post "action=restart&tok=$TOKEN")
check_has "restart while stopped → error"     "$out" "m=e_notrunning"

# The package is incomplete without the shared schema: fail clearly.
out=$(env -i PATH="$PATH" FS3_VAR_DIR="$VAR" FS3_PKG_DIR=/nonexistent REQUEST_METHOD=GET sh "$CGI")
check_has "missing lib → clear 500"           "$out" "lib/fs3-conf.sh is missing"

printf '\n===== ui cgi: %d passed, %d failed =====\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
