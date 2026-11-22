#!/bin/sh
# index.cgi — the fs3 DSM tile: status, live bucket stats, SigV4
# credential management and the server settings form.
#
# Security posture, since this CGI writes state:
#  - DSM does not authenticate third-party CGIs. Every request is checked
#    with DSM's own authenticate.cgi, and only members of the DSM
#    "administrators" group get the page; everyone else gets a 403 with
#    nothing in it (no CSRF token, no keys, no settings).
#  - fs3.conf is parsed line-by-line (lib/fs3-conf.sh), never sourced, and
#    every value is validated against the schema before it is written.
#  - POSTs require a random token from ${VAR_DIR}/.ui-csrf (rendered into
#    the forms, compared on submit) plus an Origin/Host match when the
#    browser sends Origin.
#  - Access/secret keys are restricted to [A-Za-z0-9._-] with no URL
#    decoding, so ':' or newlines can't reach the credentials file.
#    Settings values are URL-decoded and then must pass their type's
#    validator (which rejects control characters).
#  - Secrets are never rendered back into the page.
#  - Writes are tmp + chmod 600 + rename; the previous fs3.conf is kept as
#    fs3.conf.bak and can be restored from the page.

# FS3_VAR_DIR, FS3_PKG_DIR, FS3_UI_AUTH_CMD and FS3_UI_GROUPS_CMD are
# settable only by the web server's environment (clients can influence
# only HTTP_* variables); they exist so tests can run this CGI against a
# scratch directory without DSM.
VAR_DIR="${FS3_VAR_DIR:-/var/packages/fs3/var}"
PKG_DIR="${FS3_PKG_DIR:-/var/packages/fs3/target}"
CONF_FILE="${VAR_DIR}/fs3.conf"
CRED_FILE="${VAR_DIR}/credentials"
PID_FILE="${VAR_DIR}/fs3.pid"
CHILD_PID_FILE="${VAR_DIR}/fs3.child.pid"
RESTART_FILE="${VAR_DIR}/fs3.restart"
LOG_FILE="${VAR_DIR}/fs3.log"
START_LOG="${VAR_DIR}/fs3.start.log"
TOK_FILE="${VAR_DIR}/.ui-csrf"
CONF_LIB="${PKG_DIR}/lib/fs3-conf.sh"
ADMIN_SOCK="${VAR_DIR}/admin.sock"

SCRIPT_PATH="$(printf '%s' "${SCRIPT_NAME:-index.cgi}" | tr -d '\r\n ')"

plain_page() {  # $1=status line $2=message (fixed text only)
    printf 'Status: %s\r\nContent-type: text/html\r\nCache-Control: no-store\r\n\r\n' "$1"
    printf '<!doctype html><html><head><meta charset="utf-8"><title>fs3</title></head>'
    printf '<body style="font-family: system-ui, sans-serif; margin: 40px;">'
    printf '<h1>fs3 Object Storage</h1><p>%s</p></body></html>\n' "$2"
    exit 0
}

[ -f "${CONF_LIB}" ] || plain_page "500 Internal Server Error" \
    "The package is incomplete (lib/fs3-conf.sh is missing). Reinstall fs3."
. "${CONF_LIB}"
fs3_conf_defaults "${VAR_DIR}"
fs3_conf_load "${CONF_FILE}" 2>/dev/null

# ---- DSM authentication ------------------------------------------------

# Print the signed-in DSM user, or nothing. authenticate.cgi reads the
# session cookie from our environment. With DSM's CSRF protection on it
# also wants the session's SynoToken, which login.cgi returns for the
# same cookie; this CGI has its own CSRF token and Origin check. The
# helpers must not see our request body or method.
ui_user() {
    if [ -n "${FS3_UI_AUTH_CMD}" ]; then
        u="$(sh -c "${FS3_UI_AUTH_CMD}" </dev/null 2>/dev/null)"
    else
        A=/usr/syno/synoman/webman/modules/authenticate.cgi
        L=/usr/syno/synoman/webman/login.cgi
        [ -x "${A}" ] || return 0
        u="$(REQUEST_METHOD=GET CONTENT_LENGTH= QUERY_STRING= "${A}" </dev/null 2>/dev/null)"
        if [ -z "${u}" ] && [ -x "${L}" ]; then
            tok="$(REQUEST_METHOD=GET CONTENT_LENGTH= QUERY_STRING= "${L}" </dev/null 2>/dev/null \
                | tr -d '\r' \
                | sed -n 's/.*"SynoToken"[[:space:]]*:[[:space:]]*"\([A-Za-z0-9._-]*\)".*/\1/p' \
                | head -n 1)"
            if [ -n "${tok}" ]; then
                u="$(REQUEST_METHOD=GET CONTENT_LENGTH= QUERY_STRING="SynoToken=${tok}" \
                     HTTP_X_SYNO_TOKEN="${tok}" "${A}" </dev/null 2>/dev/null)"
            fi
        fi
    fi
    u="$(printf '%s' "${u}" | head -n 1 | tr -d '\r')"
    case "${u}" in ''|*[[:cntrl:]]*) return 0 ;; esac
    [ "${#u}" -le 128 ] && printf '%s' "${u}"
}

ui_is_admin() {
    if [ -n "${FS3_UI_GROUPS_CMD}" ]; then
        g="$(sh -c "${FS3_UI_GROUPS_CMD}" sh "$1" </dev/null 2>/dev/null)"
    else
        g="$(id -Gn "$1" 2>/dev/null)"
    fi
    case " ${g} " in *" administrators "*) return 0 ;; esac
    return 1
}

UI_USER="$(ui_user)"
if [ -z "${UI_USER}" ]; then
    plain_page "403 Forbidden" \
        "Sign in to DSM as an administrator to manage fs3, then open this page from the DSM main menu."
fi
ui_is_admin "${UI_USER}" || plain_page "403 Forbidden" \
    "Only DSM administrators can manage fs3."

# ---- helpers ------------------------------------------------------------

# Escape strings before interpolating them into HTML (covers attribute
# context too via the quote rule).
html_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' \
                           -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

# Decode an application/x-www-form-urlencoded value (%XX and '+'). The
# result still has to pass a validator before it is used anywhere.
url_decode() {
    printf '%s' "$1" | awk '
        BEGIN { hex = "0123456789abcdef" }
        {
            s = $0; gsub(/\+/, " ", s); out = ""
            while ((i = index(s, "%")) > 0) {
                out = out substr(s, 1, i - 1)
                h = tolower(substr(s, i + 1, 2))
                hi = index(hex, substr(h, 1, 1)); lo = index(hex, substr(h, 2, 1))
                if (length(h) == 2 && hi && lo) { out = out sprintf("%c", (hi - 1) * 16 + lo - 1); s = substr(s, i + 3) }
                else { out = out "%"; s = substr(s, i + 1) }
            }
            printf "%s", out s
        }'
}

# Fetch a path from the localhost admin listener. Fails (rc 1) when the
# listener is disabled, the server is down, or no HTTP client exists.
fetch_admin() {
    [ "${FS3_METRICS_PORT}" = "0" ] && return 1
    if command -v curl >/dev/null 2>&1; then
        curl -fs --max-time 2 "http://127.0.0.1:${FS3_METRICS_PORT}$1" 2>/dev/null
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 2 -O - "http://127.0.0.1:${FS3_METRICS_PORT}$1" 2>/dev/null
    else
        return 1
    fi
}

# 303 back to the page with a fixed message code (never reflected input).
redirect() {
    printf 'Status: 303 See Other\r\nLocation: %s?m=%s\r\n' "${SCRIPT_PATH}" "$1"
    printf 'Content-type: text/plain\r\n\r\n%s\n' "$1"
    exit 0
}

# Atomic credentials write: stdin -> tmp (0600) -> rename.
write_creds() {
    umask 077
    tmp="${CRED_FILE}.tmp.$$"
    cat > "${tmp}" 2>/dev/null || { rm -f "${tmp}"; return 1; }
    chmod 600 "${tmp}" 2>/dev/null
    mv "${tmp}" "${CRED_FILE}" 2>/dev/null || { rm -f "${tmp}"; return 1; }
}

alive() { [ -f "$1" ] && p="$(cat "$1" 2>/dev/null)" && [ -n "${p}" ] && kill -0 "${p}" 2>/dev/null; }

# Tell a running fs3 to reload the credentials file (SIGHUP swaps the
# credential set atomically; a bad file keeps the old set).
reload_creds() {
    [ "${FS3_REQUIRE_AUTH}" = "1" ] || return 0
    [ -f "${CHILD_PID_FILE}" ] || return 0
    cpid="$(cat "${CHILD_PID_FILE}" 2>/dev/null)"
    [ -n "${cpid}" ] && kill -HUP "${cpid}" 2>/dev/null
    return 0
}

# Ask the package's watchdog to restart fs3 with the current conf.
# Returns 1 when the package isn't running (the conf applies at the next
# start).
restart_fs3() {
    alive "${PID_FILE}" || return 1
    : > "${RESTART_FILE}" 2>/dev/null || return 1
    if alive "${CHILD_PID_FILE}"; then
        kill -TERM "$(cat "${CHILD_PID_FILE}")" 2>/dev/null
    fi
    return 0
}

valid_key() {  # $1=value $2=min $3=max — charset [A-Za-z0-9._-]
    case "$1" in ''|*[!A-Za-z0-9._-]*) return 1 ;; esac
    [ "${#1}" -ge "$2" ] && [ "${#1}" -le "$3" ]
}

# $1=value $2=allowed characters (tr set) $3=min $4=max length.
valid_chars() {
    [ "${#1}" -ge "$3" ] && [ "${#1}" -le "$4" ] || return 1
    [ -z "$(printf '%s' "$1" | tr -d "$2")" ]
}

# Call the fs3 admin API over its Unix socket (replication rules).
# $1=method $2=path under /v1 $3=JSON body (optional). Sets API_CODE;
# rc 2 when the socket or curl is missing or fs3 doesn't answer.
API_CODE=""
admin_api() {
    API_CODE=""
    [ -S "${ADMIN_SOCK}" ] || return 2
    command -v curl >/dev/null 2>&1 || return 2
    if [ -n "${3:-}" ]; then
        API_CODE="$(printf '%s' "$3" | curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            --unix-socket "${ADMIN_SOCK}" -X "$1" -H 'Content-Type: application/json' \
            --data-binary @- "http://localhost/v1$2" 2>/dev/null)"
    else
        API_CODE="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            --unix-socket "${ADMIN_SOCK}" -X "$1" "http://localhost/v1$2" 2>/dev/null)"
    fi
    case "${API_CODE}" in 2??) return 0 ;; 000|'') return 2 ;; *) return 1 ;; esac
}

# Bucket names as fs3 accepts them (the API checks them again).
valid_bucket() { valid_chars "$1" 'a-z0-9.-' 3 63; }

# Replication form -> JSON. Every value is restricted to characters that
# need no JSON escaping, so the document can be assembled with printf.
set_replication() {
    valid_bucket "${F_RB}" || redirect e_repl_in
    ep="$(url_decode "${F_REP}")"
    case "${ep}" in http://?*|https://?*) ;; *) redirect e_repl_in ;; esac
    valid_chars "${ep}" 'A-Za-z0-9.:/-' 9 280 || redirect e_repl_in
    reg="$(url_decode "${F_RREG}")"
    valid_chars "${reg}" 'a-z0-9-' 0 63 || redirect e_repl_in
    valid_bucket "${F_RBK}" || redirect e_repl_in
    rak="$(url_decode "${F_RAK}")"
    valid_chars "${rak}" 'A-Za-z0-9._/+=-' 1 128 || redirect e_repl_in
    rsk="$(url_decode "${F_RSK}")"
    valid_chars "${rsk}" 'A-Za-z0-9._/+=-' 0 256 || redirect e_repl_in
    pfx="$(url_decode "${F_RPFX}")"
    valid_chars "${pfx}" 'A-Za-z0-9._/-' 0 256 || redirect e_repl_in
    addr=path; [ "${F_RADDR}" = "virtual" ] && addr=virtual
    del=true;   [ "${F_RDEL}" = "1" ] || del=false
    plain=false; [ "${F_RPLAIN}" = "1" ] && plain=true
    json="{\"endpoint\":\"${ep}\",\"bucket\":\"${F_RBK}\",\"access_key\":\"${rak}\""
    [ -n "${rsk}" ] && json="${json},\"secret_key\":\"${rsk}\""
    [ -n "${reg}" ] && json="${json},\"region\":\"${reg}\""
    json="${json},\"prefix\":\"${pfx}\",\"addressing\":\"${addr}\",\"deletes\":${del},\"allow_plain_http\":${plain}}"
    admin_api PUT "/buckets/${F_RB}/replication" "${json}"
    case $? in
        0) redirect repl_set ;;
        2) redirect e_repl_sock ;;
    esac
    case "${API_CODE}" in
        400) redirect e_repl_rule ;;
        404) redirect e_repl_bucket ;;
        501) redirect e_repl_off ;;
    esac
    redirect e_repl_api
}

seccomp_supported() { grep -q '^Seccomp:' /proc/self/status 2>/dev/null; }

# ---- POST -----------------------------------------------------------------

save_settings() {  # $1 = the raw form body
    # Start from the current values; bools absent from the form are off.
    for k in ${FS3_CONF_KEYS}; do
        [ "$(fs3_conf_type "${k}")" = "bool" ] && eval "NEW_${k}=0" || eval "NEW_${k}=\${${k}}"
    done
    oldifs="${IFS}"; IFS='&'
    for pair in $1; do
        IFS="${oldifs}"
        k="${pair%%=*}"; v="${pair#*=}"
        if fs3_conf_is_key "${k}"; then
            v="$(url_decode "${v}")"
            # Lists are entered as "a, b"; store them without spaces.
            [ "$(fs3_conf_type "${k}")" = "iplist" ] && v="$(printf '%s' "${v}" | tr -d ' ')"
            eval "NEW_${k}=\${v}"
        fi
        IFS='&'
    done
    IFS="${oldifs}"

    for k in ${FS3_CONF_KEYS}; do
        eval "v=\${NEW_${k}}"
        fs3_conf_valid "$(fs3_conf_type "${k}")" "${v}" || redirect "e_cfg.${k}"
    done

    # Cross-field rules.
    [ "${NEW_FS3_ALLOW_PUBLIC_WRITE}" = "1" ] && NEW_FS3_ALLOW_PUBLIC=1
    for a in "${NEW_FS3_METRICS_PORT}" "${NEW_FS3_WEB_PORT}"; do
        [ "${a}" != "0" ] && [ "${a}" = "${NEW_FS3_PORT}" ] && redirect e_ports
    done
    [ "${NEW_FS3_WEB_PORT}" != "0" ] && [ "${NEW_FS3_WEB_PORT}" = "${NEW_FS3_METRICS_PORT}" ] \
        && redirect e_ports
    if [ "${NEW_FS3_LOCK_IMMUTABLE}" = "1" ] && [ "${FS3_LOCK_IMMUTABLE}" != "1" ] \
       && [ ! -S "${VAR_DIR}/lockd.sock" ]; then
        redirect e_lockd
    fi
    if [ "${NEW_FS3_SECCOMP}" = "require" ] && ! seccomp_supported; then
        redirect e_seccomp
    fi

    changed=0
    for k in ${FS3_CONF_KEYS}; do
        eval "v=\${NEW_${k}}; cur=\${${k}}"
        [ "${v}" != "${cur}" ] && changed=1
        eval "${k}=\${v}"
    done
    [ "${changed}" = "1" ] || redirect cfg_same
    umask 077
    fs3_conf_write "${CONF_FILE}" || redirect e_write
    restart_fs3 && redirect cfg_restarted
    redirect cfg_saved
}

restore_settings() {
    [ -f "${CONF_FILE}.bak" ] || redirect e_nobak
    umask 077
    cp -p "${CONF_FILE}" "${CONF_FILE}.tmp.$$" 2>/dev/null \
        && cp -p "${CONF_FILE}.bak" "${CONF_FILE}.new.$$" 2>/dev/null \
        && mv "${CONF_FILE}.new.$$" "${CONF_FILE}" 2>/dev/null \
        && mv "${CONF_FILE}.tmp.$$" "${CONF_FILE}.bak" 2>/dev/null \
        || { rm -f "${CONF_FILE}.tmp.$$" "${CONF_FILE}.new.$$"; redirect e_write; }
    restart_fs3 && redirect cfg_restored_restarted
    redirect cfg_restored
}

handle_post() {
    # Same-origin check: browsers send Origin on cross-site POSTs.
    if [ -n "${HTTP_ORIGIN}" ] && [ "${HTTP_ORIGIN}" != "null" ]; then
        o="${HTTP_ORIGIN#*://}"; o="${o%%/*}"
        [ "${o}" = "${HTTP_HOST}" ] || redirect e_csrf
    fi

    case "${CONTENT_LENGTH}" in ''|*[!0-9]*) redirect e_req ;; esac
    [ "${CONTENT_LENGTH}" -gt 16384 ] && redirect e_req
    body="$(dd bs=1 count="${CONTENT_LENGTH}" 2>/dev/null)"

    F_ACTION=""; F_AK=""; F_SK=""; F_USER=""; F_TOK=""
    F_RB=""; F_REP=""; F_RREG=""; F_RBK=""; F_RAK=""; F_RSK=""; F_RPFX=""
    F_RADDR=""; F_RDEL=""; F_RPLAIN=""
    oldifs="${IFS}"; IFS='&'
    for pair in ${body}; do
        k="${pair%%=*}"; v="${pair#*=}"
        case "${k}" in
            action) F_ACTION="${v}" ;;
            ak)     F_AK="${v}" ;;
            sk)     F_SK="${v}" ;;
            user)   F_USER="${v}" ;;
            tok)    F_TOK="${v}" ;;
            rb)     F_RB="${v}" ;;
            rep)    F_REP="${v}" ;;
            rreg)   F_RREG="${v}" ;;
            rbk)    F_RBK="${v}" ;;
            rak)    F_RAK="${v}" ;;
            rsk)    F_RSK="${v}" ;;
            rpfx)   F_RPFX="${v}" ;;
            raddr)  F_RADDR="${v}" ;;
            rdel)   F_RDEL="${v}" ;;
            rplain) F_RPLAIN="${v}" ;;
        esac
    done
    IFS="${oldifs}"

    # CSRF token: must match the file rendered into the form.
    [ -n "${F_TOK}" ] && [ -s "${TOK_FILE}" ] \
        && [ "${F_TOK}" = "$(cat "${TOK_FILE}" 2>/dev/null)" ] \
        || redirect e_csrf

    case "${F_ACTION}" in
    addkey)
        valid_key "${F_AK}" 3 64   || redirect e_ak
        valid_key "${F_SK}" 8 128  || redirect e_sk
        # The user owns the buckets this key creates. Empty: a replaced
        # key keeps the user it had (so a secret change never moves its
        # buckets away); a new key is its own user.
        if [ -n "${F_USER}" ]; then
            valid_key "${F_USER}" 1 64 || redirect e_user
        elif [ -f "${CRED_FILE}" ]; then
            F_USER="$(awk -F: -v k="${F_AK}" \
                '!/^[ \t]*#/ && NF >= 3 && $1 == k { sub(/[ \t\r]+$/, "", $3);
                                                   print $3; exit }' \
                "${CRED_FILE}")"
        fi
        # A replaced key keeps its attributes (expiry, disabled, read-only):
        # changing a secret must never silently re-enable a disabled key.
        F_ATTRS=""
        [ -f "${CRED_FILE}" ] && F_ATTRS="$(awk -F: -v k="${F_AK}" \
            '!/^[ \t]*#/ && NF >= 4 && $1 == k { sub(/[ \t\r]+$/, "", $4); print $4; exit }' \
            "${CRED_FILE}")"
        # Keep comments and other keys; same access key is replaced.
        {
            [ -f "${CRED_FILE}" ] && \
                awk -F: -v k="${F_AK}" \
                    '/^[ \t]*#/ || NF < 2 { print; next } $1 != k' \
                    "${CRED_FILE}"
            if [ -n "${F_ATTRS}" ]; then
                printf '%s:%s:%s:%s\n' "${F_AK}" "${F_SK}" "${F_USER}" "${F_ATTRS}"
            elif [ -n "${F_USER}" ]; then
                printf '%s:%s:%s\n' "${F_AK}" "${F_SK}" "${F_USER}"
            else
                printf '%s:%s\n' "${F_AK}" "${F_SK}"
            fi
        } | write_creds || redirect e_write

        if [ "${FS3_REQUIRE_AUTH}" != "1" ]; then
            # First credential: turn authentication on in the conf, then
            # restart fs3 through the watchdog so it takes effect.
            umask 077
            { [ -f "${CONF_FILE}" ] && grep -v '^FS3_REQUIRE_AUTH=' "${CONF_FILE}"
              echo "FS3_REQUIRE_AUTH=1"; } > "${CONF_FILE}.tmp.$$" 2>/dev/null \
                && mv "${CONF_FILE}.tmp.$$" "${CONF_FILE}" 2>/dev/null \
                || { rm -f "${CONF_FILE}.tmp.$$"; redirect e_write; }
            restart_fs3 && redirect added_restarted
            redirect added_restart
        fi
        reload_creds
        redirect added
        ;;
    delkey)
        valid_key "${F_AK}" 3 64 || redirect e_ak
        [ -f "${CRED_FILE}" ] || redirect e_nokey
        awk -F: -v k="${F_AK}" \
            '/^[ \t]*#/ { next } NF >= 2 && $1 == k { found = 1 }
             END { exit !found }' "${CRED_FILE}" || redirect e_nokey
        # Never delete the last credential while auth is on: it would
        # lock every client out, and fs3 refuses to start with an empty
        # credentials file.
        if [ "${FS3_REQUIRE_AUTH}" = "1" ]; then
            left="$(awk -F: -v k="${F_AK}" \
                '/^[ \t]*#/ { next } NF >= 2 && $1 != k { n++ }
                 END { print n + 0 }' "${CRED_FILE}")"
            [ "${left}" -eq 0 ] && redirect e_last
        fi
        awk -F: -v k="${F_AK}" \
            '/^[ \t]*#/ || NF < 2 { print; next } $1 != k' \
            "${CRED_FILE}" | write_creds || redirect e_write
        reload_creds
        redirect removed
        ;;
    savecfg)
        save_settings "${body}"
        ;;
    restorecfg)
        restore_settings
        ;;
    setrepl)
        set_replication
        ;;
    delrepl|syncrepl)
        valid_bucket "${F_RB}" || redirect e_repl_in
        if [ "${F_ACTION}" = "delrepl" ]; then
            admin_api DELETE "/buckets/${F_RB}/replication"; rc=$?; ok=repl_removed
        else
            admin_api POST "/buckets/${F_RB}/replication/sync"; rc=$?; ok=repl_sync
        fi
        [ "${rc}" -eq 0 ] && redirect "${ok}"
        [ "${rc}" -eq 2 ] && redirect e_repl_sock
        [ "${API_CODE}" = "404" ] && redirect e_repl_bucket
        redirect e_repl_api
        ;;
    restart)
        restart_fs3 && redirect restarted
        redirect e_notrunning
        ;;
    *)
        redirect e_req
        ;;
    esac
}

if [ "${REQUEST_METHOD}" = "POST" ]; then
    handle_post
fi

# ---- GET: render the page -------------------------------------------

# CSRF token for the forms: random, 0600, rotated daily.
TOKEN=""
if [ -w "${VAR_DIR}" ] || [ -w "${TOK_FILE}" ] 2>/dev/null; then
    if [ ! -s "${TOK_FILE}" ] \
       || [ -n "$(find "${TOK_FILE}" -mmin +1440 2>/dev/null)" ]; then
        umask 077
        od -An -tx1 -N16 /dev/urandom 2>/dev/null | tr -d ' \n' \
            > "${TOK_FILE}" 2>/dev/null
    fi
    TOKEN="$(cat "${TOK_FILE}" 2>/dev/null)"
fi

H_PORT="$(html_escape "${FS3_PORT}")"
H_DATA="$(html_escape "${FS3_DATA}")"

# running: watchdog and fs3 both alive. restarting: the watchdog is
# alive but fs3 isn't (restart in progress, or a crash loop).
RUNNING="stopped"
if alive "${PID_FILE}"; then
    if alive "${CHILD_PID_FILE}"; then RUNNING="running"; else RUNNING="restarting"; fi
fi

# Fixed message codes -> fixed strings; nothing user-supplied reflects
# (e_cfg.<KEY> names a schema key, checked below, and shows its label).
MSG=""
case "${QUERY_STRING}" in
    *m=added_restarted*) MSG="Credential saved and authentication enabled. fs3 is restarting with authentication on." ;;
    *m=added_restart*) MSG="Credential saved and authentication enabled in fs3.conf. It takes effect when the package next starts." ;;
    *m=added*)   MSG="Credential saved. The running server reloaded it — it is active now." ;;
    *m=removed*) MSG="Credential removed and reloaded." ;;
    *m=cfg_restarted*) MSG="Settings saved. fs3 is restarting to apply them; reload this page in a few seconds." ;;
    *m=cfg_saved*) MSG="Settings saved. They take effect when the package next starts." ;;
    *m=cfg_same*) MSG="No settings changed." ;;
    *m=cfg_restored_restarted*) MSG="Previous settings restored. fs3 is restarting with them." ;;
    *m=cfg_restored*) MSG="Previous settings restored. They take effect when the package next starts." ;;
    *m=restarted*) MSG="fs3 is restarting." ;;
    *m=repl_set*) MSG="Replication rule saved. Changes from now on are copied to the target; use <b>Sync</b> to copy existing objects too." ;;
    *m=repl_removed*) MSG="Replication rule removed; its queue was dropped." ;;
    *m=repl_sync*) MSG="Backfill started: objects missing or different on the target are being queued." ;;
    *m=e_repl_in*) MSG="Error: invalid replication field. Endpoint is <code>https://host[:port]</code>; bucket names use a&ndash;z 0&ndash;9 . -; keys use A&ndash;Z a&ndash;z 0&ndash;9 . _ / + = -; the prefix uses A&ndash;Z a&ndash;z 0&ndash;9 . _ / -. Nothing was saved." ;;
    *m=e_repl_rule*) MSG="Error: fs3 refused the replication rule. Plain <code>http://</code> targets must be on a private network address with <i>Allow plain HTTP</i> ticked, a new rule needs the secret key, and virtual-host addressing can't be used with a dotted bucket name over https. Nothing was saved." ;;
    *m=e_repl_bucket*) MSG="Error: no such bucket here, or it has no replication rule." ;;
    *m=e_repl_off*) MSG="Error: replication is turned off (<i>Replication threads</i> is 0 under Settings)." ;;
    *m=e_repl_sock*) MSG="Error: could not reach fs3's admin API socket. Turn on <i>Admin API socket</i> under Settings and make sure the package is running." ;;
    *m=e_repl_api*) MSG="Error: fs3 could not apply the change (see fs3.log)." ;;
    *m=e_cfg.*)
        k="${QUERY_STRING#*m=e_cfg.}"; k="${k%%&*}"
        if fs3_conf_is_key "${k}"; then
            lbl="$(fs3_conf_schema | awk -F'|' -v k="${k}" '$1 == k { print $5; exit }')"
            MSG="Error: invalid value for <b>$(html_escape "${lbl}")</b>. Nothing was saved."
        else
            MSG="Error: invalid value. Nothing was saved."
        fi ;;
    *m=e_ports*) MSG="Error: the S3, admin listener and website ports must all be different. Nothing was saved." ;;
    *m=e_lockd*) MSG="Error: immutable versions need the fs3-lockd helper, and its socket ($(html_escape "${VAR_DIR}")/lockd.sock) doesn't exist. Start the helper first (see the package notes). Nothing was saved." ;;
    *m=e_seccomp*) MSG="Error: this kernel has no seccomp filter support, so <code>require</code> would keep fs3 from starting. Nothing was saved." ;;
    *m=e_nobak*) MSG="Error: there are no previous settings to restore." ;;
    *m=e_notrunning*) MSG="Error: the package isn't running. Start it from Package Center." ;;
    *m=e_csrf*)  MSG="Error: the form expired (security token mismatch). Reload the page and try again." ;;
    *m=e_ak*)    MSG="Error: the access key must be 3&ndash;64 characters from A&ndash;Z a&ndash;z 0&ndash;9 . _ -" ;;
    *m=e_user*)  MSG="Error: the user must be 1&ndash;64 characters from A&ndash;Z a&ndash;z 0&ndash;9 . _ -" ;;
    *m=e_sk*)    MSG="Error: the secret key must be 8&ndash;128 characters from A&ndash;Z a&ndash;z 0&ndash;9 . _ -" ;;
    *m=e_last*)  MSG="Error: refusing to remove the last credential while authentication is enabled &mdash; that would lock every client out." ;;
    *m=e_nokey*) MSG="Error: no such access key." ;;
    *m=e_write*) MSG="Error: could not write to $(html_escape "${VAR_DIR}"). The CGI does not run with the package user's permissions on this DSM version; edit the files over SSH instead." ;;
    *m=e_req*)   MSG="Error: malformed request." ;;
esac

AUTHLINE="Authentication is <b>disabled</b> &mdash; any client that can reach the port has full access. Define a credential below to enable SigV4 authentication."
if [ "${FS3_REQUIRE_AUTH}" = "1" ]; then
    AUTHLINE="Authentication is <b>enabled</b> (SigV4). Clients must sign requests with one of the credentials below."
fi

ENDPOINT="http://&lt;NAS-IP&gt;:${H_PORT}"
BINDLINE=""
if [ "${FS3_BIND}" = "127.0.0.1" ]; then
    ENDPOINT="https://&lt;your-hostname&gt;"
    BINDLINE="<p>fs3 is bound to <code>127.0.0.1:${H_PORT}</code> and is only
reachable through a DSM reverse-proxy entry (Control Panel &gt; Login Portal
&gt; Advanced &gt; Reverse Proxy: source = HTTPS on your hostname, destination
= <code>http://localhost:${H_PORT}</code>). DSM terminates TLS with its own
certificate, so traffic on the network is encrypted. To expose plain HTTP on
the LAN instead, change the listen address under Settings.</p>"
fi

# Restarting or crash-looping: show the end of both logs (startup
# failures land in fs3.start.log, everything after in fs3.log).
log_tail_html() {  # $1 = file
    [ -r "$1" ] || return 0
    printf '<p class="muted">Last lines of <code>%s</code>:</p>\n<pre>%s</pre>\n' \
        "$(html_escape "$1")" \
        "$(tail -n 8 "$1" 2>/dev/null | tr -d '\r' \
           | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g')"
}
LOGTAIL_HTML=""
if [ "${RUNNING}" = "restarting" ]; then
    LOGTAIL_HTML="<p class=\"notice err\">fs3 is not running at the moment (restarting,
or failing to start).</p>
$(log_tail_html "${START_LOG}")
$(log_tail_html "${LOG_FILE}")"
fi

# Bucket stats from the admin listener: "<name> <objects> <bytes> [<quota> <quota-used>]"
# lines (quota 0 = none).
BUCKETS_HTML=""
if BUCKETS_TXT="$(fetch_admin /buckets)"; then
    if [ -n "${BUCKETS_TXT}" ]; then
        ROWS="$(printf '%s\n' "${BUCKETS_TXT}" | sort | awk '
            NF >= 3 {
                name = $1
                gsub(/&/, "\\&amp;", name)
                gsub(/</, "\\&lt;", name)
                gsub(/>/, "\\&gt;", name)
                b = $3 + 0
                if      (b < 1024)       hs = sprintf("%d B", b)
                else if (b < 1048576)    hs = sprintf("%.1f KiB", b / 1024)
                else if (b < 1073741824) hs = sprintf("%.1f MiB", b / 1048576)
                else                     hs = sprintf("%.2f GiB", b / 1073741824)
                q = $4 + 0; qu = $5 + 0
                if (q > 0) {
                    if      (q < 1048576)    qs = sprintf("%.1f KiB", q / 1024)
                    else if (q < 1073741824) qs = sprintf("%.1f MiB", q / 1048576)
                    else                     qs = sprintf("%.2f GiB", q / 1073741824)
                    qs = sprintf("%d%% of %s", int(qu * 100 / q), qs)
                } else qs = "&mdash;"
                printf "<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>\n", name, $2, hs, qs
                nb++; tobj += $2; tb += b
                if      (tb < 1024)       ts = sprintf("%d B", tb)
                else if (tb < 1048576)    ts = sprintf("%.1f KiB", tb / 1024)
                else if (tb < 1073741824) ts = sprintf("%.1f MiB", tb / 1048576)
                else                      ts = sprintf("%.2f GiB", tb / 1073741824)
            }
            END {
                if (nb > 1)
                    printf "<tr class=\"tot\"><td>%d buckets</td><td>%s</td><td>%s</td><td></td></tr>\n", nb, tobj, ts
            }')"
        BUCKETS_HTML="<table>
<tr><th>Bucket</th><th>Objects</th><th>Size</th><th>Quota</th></tr>
${ROWS}
</table>"
    else
        BUCKETS_HTML="<p class=\"muted\">No buckets yet. Create one with
<code>aws s3 mb</code> (see below).</p>"
    fi
else
    if [ "${RUNNING}" = "stopped" ]; then
        BUCKETS_HTML="<p class=\"muted\">Bucket statistics are available while the package is running.</p>"
    elif [ "${FS3_METRICS_PORT}" = "0" ]; then
        BUCKETS_HTML="<p class=\"muted\">Bucket statistics need the admin listener; set the admin listener port under Settings.</p>"
    else
        BUCKETS_HTML="<p class=\"muted\">Bucket statistics are unavailable (could not reach the admin listener on 127.0.0.1:$(html_escape "${FS3_METRICS_PORT}")).</p>"
    fi
fi

# Replication: rules and their state from the admin listener
# ("<bucket> <queue> <failed> <lag> <target> <last error...>"), managed
# through the admin API socket.
REPL_HTML=""
if [ "${RUNNING}" != "running" ]; then
    REPL_HTML="<p class=\"muted\">Replication can be managed while the package is running.</p>"
elif [ "${FS3_REPL_WORKERS}" = "0" ]; then
    REPL_HTML="<p class=\"muted\">Replication is turned off (<i>Replication threads</i> is 0 under Settings).</p>"
else
    REPL_ROWS=""
    if RTXT="$(fetch_admin /replication)" && [ -n "${RTXT}" ]; then
        REPL_ROWS="$(printf '%s\n' "${RTXT}" | while read -r rb rq rf rl rt rerr; do
            [ -n "${rb}" ] || continue
            valid_bucket "${rb}" || continue
            hb="$(html_escape "${rb}")"
            he="$(html_escape "${rerr}")"; [ "${rerr}" = "-" ] && he="&mdash;"
            printf '<tr><td><code>%s</code></td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s s</td><td class="muted">%s</td><td>' \
                "${hb}" "$(html_escape "${rt}")" "$(html_escape "${rq}")" "$(html_escape "${rf}")" \
                "$(html_escape "${rl}")" "${he}"
            if [ -n "${TOKEN}" ]; then
                printf '<form method="post" class="inline"><input type="hidden" name="action" value="syncrepl"><input type="hidden" name="tok" value="%s"><input type="hidden" name="rb" value="%s"><button type="submit">Sync</button></form> ' "${TOKEN}" "${hb}"
                printf '<form method="post" class="inline" onsubmit="return confirm('"'"'Stop replicating %s?'"'"');"><input type="hidden" name="action" value="delrepl"><input type="hidden" name="tok" value="%s"><input type="hidden" name="rb" value="%s"><button type="submit">Remove</button></form>' "${hb}" "${TOKEN}" "${hb}"
            fi
            printf '</td></tr>\n'
        done)"
    fi
    if [ -n "${REPL_ROWS}" ]; then
        REPL_HTML="<table><tr><th>Bucket</th><th>Target</th><th>Queued</th><th>Failed</th><th>Lag</th><th>Last error</th><th></th></tr>
${REPL_ROWS}</table>"
    else
        REPL_HTML="<p class=\"muted\">No bucket replicates yet.</p>"
    fi
    if [ "${FS3_ADMIN_SOCKET}" != "1" ]; then
        REPL_HTML="${REPL_HTML}
<p class=\"muted\">To add or change rules here, turn on <i>Admin API socket</i> under Settings.</p>"
    elif [ -n "${TOKEN}" ]; then
        REPL_HTML="${REPL_HTML}
<h4>Replicate a bucket</h4>
<p class=\"muted\">Copies every change of a bucket here to a bucket on another S3 endpoint
(Backblaze B2, AWS, MinIO, another fs3). Saving a rule for a bucket that already has one
replaces it; leave the secret empty to keep the stored one. A CA certificate for a private
endpoint goes in <code>$(html_escape "${VAR_DIR}")/repl-ca.pem</code> (read at start).</p>
<form method=\"post\" autocomplete=\"off\">
<input type=\"hidden\" name=\"action\" value=\"setrepl\">
<input type=\"hidden\" name=\"tok\" value=\"${TOKEN}\">
<table class=\"cfg\">
<tr><td>Bucket here</td><td><input name=\"rb\" size=\"24\" required></td></tr>
<tr><td>Target endpoint</td><td><input name=\"rep\" size=\"44\" placeholder=\"https://s3.eu-central-003.backblazeb2.com\" required></td></tr>
<tr><td>Region</td><td><input name=\"rreg\" size=\"20\" placeholder=\"us-east-1\"></td></tr>
<tr><td>Target bucket</td><td><input name=\"rbk\" size=\"24\" required></td></tr>
<tr><td>Access key</td><td><input name=\"rak\" size=\"32\" required></td></tr>
<tr><td>Secret key</td><td><input name=\"rsk\" type=\"password\" size=\"32\"></td></tr>
<tr><td>Only keys starting with</td><td><input name=\"rpfx\" size=\"24\"></td></tr>
<tr><td>Addressing</td><td><select name=\"raddr\"><option value=\"path\">path-style</option><option value=\"virtual\">virtual-host</option></select></td></tr>
<tr><td></td><td><label><input type=\"checkbox\" name=\"rdel\" value=\"1\"> Also delete on the target</label>
<label><input type=\"checkbox\" name=\"rplain\" value=\"1\"> Allow plain HTTP (private network only)</label></td></tr>
</table>
<button type=\"submit\">Save rule</button>
</form>"
    fi
fi

# Credentials section: list access keys (never secrets) with remove
# buttons, plus an add form. Degrades to manual instructions when this
# CGI can't write the var dir (no token, no forms).
CREDS_HTML=""
if [ -z "${TOKEN}" ]; then
    CREDS_HTML="<p class=\"muted\">This page cannot manage credentials on
this DSM version (the CGI has no write access to
<code>$(html_escape "${VAR_DIR}")</code>). Edit
<code>$(html_escape "${CRED_FILE}")</code> over SSH (one
<code>access_key:secret_key</code> per line, mode 600), set
<code>FS3_REQUIRE_AUTH=1</code> in the conf, and restart the package.</p>"
else
    KEYROWS=""
    if [ -f "${CRED_FILE}" ] && [ -r "${CRED_FILE}" ]; then
        while IFS= read -r cline || [ -n "${cline}" ]; do
            case "${cline}" in ''|'#'*) continue ;; esac
            case "${cline}" in *:*) ;; *) continue ;; esac
            ak="${cline%%:*}"
            hak="$(html_escape "${ak}")"
            rest="${cline#*:}"
            uf=""; attrs=""
            case "${rest}" in
                *:*) uf="${rest#*:}"
                     case "${uf}" in *:*) attrs="${uf#*:}"; uf="${uf%%:*}" ;; esac ;;
            esac
            if [ -n "${uf}" ]; then
                huser="<code>$(html_escape "${uf}")</code>"
            else
                huser="<span class=\"muted\">${hak} (the key itself)</span>"
            fi
            # Status from the attributes field (fs3 refuses unknown ones).
            hstat="$(printf '%s' "${attrs}" | awk -F, -v now="$(date +%s)" '{
                d = 0; r = 0; x = ""
                for (i = 1; i <= NF; i++) {
                    if ($i == "disabled") d = 1
                    else if ($i == "ro") r = 1
                    else if ($i ~ /^expires=[0-9]+$/) {
                        e = substr($i, 9) + 0
                        x = (e <= now) ? "expired" : sprintf("expires in %d d", int((e - now) / 86400))
                    }
                }
                s = (d ? "disabled " : "") (r ? "read-only " : "") x
                sub(/ +$/, "", s)
                if (s == "") s = "active"
                print s }')"
            [ -n "${hstat}" ] || hstat="active"
            KEYROWS="${KEYROWS}<tr><td><code>${hak}</code></td><td>${huser}</td><td>$(html_escape "${hstat}")</td><td>
<form method=\"post\" onsubmit=\"return confirm('Remove access key ${hak}?');\">
<input type=\"hidden\" name=\"action\" value=\"delkey\">
<input type=\"hidden\" name=\"tok\" value=\"${TOKEN}\">
<input type=\"hidden\" name=\"ak\" value=\"${hak}\">
<button type=\"submit\">Remove</button></form></td></tr>"
        done < "${CRED_FILE}"
    fi
    if [ -n "${KEYROWS}" ]; then
        CREDS_HTML="<table><tr><th>Access key</th><th>Owns buckets as user</th><th>Status</th><th></th></tr>${KEYROWS}</table>"
        # Key hygiene counters from the admin listener's /metrics.
        if KM="$(fetch_admin /metrics)"; then
            KSOON="$(printf '%s\n' "${KM}" | awk '$1 == "fs3_keys_expiring_soon" { print $2 + 0 }')"
            KUNUSED="$(printf '%s\n' "${KM}" | awk '$1 == "fs3_keys_unused_90d" { print $2 + 0 }')"
            if [ -n "${KSOON}" ] || [ -n "${KUNUSED}" ]; then
                CREDS_HTML="${CREDS_HTML}
<p class=\"muted\">Keys expiring within 7 days: ${KSOON:-0} &middot; unused for 90 days: ${KUNUSED:-0}</p>"
            fi
        fi
    else
        CREDS_HTML="<p class=\"muted\">No credentials defined.</p>"
    fi
    RESTART_NOTE=""
    if [ "${FS3_REQUIRE_AUTH}" != "1" ]; then
        RESTART_NOTE="<p class=\"muted\">Adding the first credential enables
authentication and restarts fs3 once.</p>"
    fi
    CREDS_HTML="${CREDS_HTML}
<form method=\"post\" autocomplete=\"off\">
<input type=\"hidden\" name=\"action\" value=\"addkey\">
<input type=\"hidden\" name=\"tok\" value=\"${TOKEN}\">
<p>
<label>Access key <input name=\"ak\" size=\"20\" maxlength=\"64\"
       pattern=\"[A-Za-z0-9._-]{3,64}\" required></label>
<label>Secret key <input name=\"sk\" type=\"password\" size=\"28\" maxlength=\"128\"
       pattern=\"[A-Za-z0-9._-]{8,128}\" required></label>
<label>User (optional) <input name=\"user\" size=\"16\" maxlength=\"64\"
       pattern=\"[A-Za-z0-9._-]{1,64}\"></label>
<button type=\"submit\">Add / replace</button>
</p>
</form>
<p class=\"muted\">Keys may contain letters, digits and <code>. _ -</code>
(generate a secret with e.g. <code>openssl rand -hex 32</code>). Adding an
existing access key replaces its secret (and keeps its user unless you enter
a new one). Each bucket belongs to the user of the key that created it, and
other users cannot see it. To rotate a key without losing access to your
buckets, give the new key the <em>same user</em> as the old one, then remove
the old key. Without a user, a new key is its own user. Changes are reloaded
by the running server without a restart.</p>
${RESTART_NOTE}"
fi

# Settings form, generated from the schema in lib/fs3-conf.sh.
render_field() {  # $1=key $2=type $3=default $4=label $5=help
    k="$1"; t="$2"; d="$3"
    cur="$(fs3_conf_get "${k}")"
    hcur="$(html_escape "${cur}")"
    case "${t}" in
    bool)
        chk=""; [ "${cur}" = "1" ] && chk=" checked"
        ctl="<input type=\"checkbox\" name=\"${k}\" id=\"${k}\" value=\"1\"${chk}>"
        dflt="$([ "${d}" = "1" ] && echo on || echo off)" ;;
    enum:*)
        ctl="<select name=\"${k}\" id=\"${k}\">"
        oldifs="${IFS}"; IFS='/'
        for o in ${t#enum:}; do
            sel=""; [ "${o}" = "${cur}" ] && sel=" selected"
            ctl="${ctl}<option value=\"$(html_escape "${o}")\"${sel}>$(html_escape "${o}")</option>"
        done
        IFS="${oldifs}"
        ctl="${ctl}</select>"
        dflt="${d}" ;;
    *)
        sz=10
        case "${t}" in iplist|host) sz=32 ;; user) sz=20 ;; esac
        ctl="<input name=\"${k}\" id=\"${k}\" value=\"${hcur}\" size=\"${sz}\" maxlength=\"253\">"
        dflt="${d}" ;;
    esac
    [ -n "${dflt}" ] || dflt="empty"
    printf '<tr><td><label for="%s">%s</label></td><td>%s</td></tr>\n' \
        "${k}" "$(html_escape "$4")" "${ctl}"
    printf '<tr class="help"><td colspan="2">%s <span class="dflt">Default: %s.</span> <code>%s</code></td></tr>\n' \
        "$(html_escape "$5")" "$(html_escape "${dflt}")" "${k}"
}

render_settings() {
    fs3_conf_sections | while IFS='|' read -r sec title; do
        printf '<h4>%s</h4>\n<table class="cfg">\n' "$(html_escape "${title}")"
        fs3_conf_schema | while IFS='|' read -r k t d s l h; do
            [ "${s}" = "${sec}" ] && render_field "${k}" "${t}" "${d}" "${l}" "${h}"
        done
        printf '</table>\n'
    done
}

SETTINGS_HTML=""
if [ -n "${TOKEN}" ]; then
    APPLY_NOTE="Saving restarts fs3 (a few seconds; requests in flight are dropped)."
    [ "${RUNNING}" = "stopped" ] && APPLY_NOTE="The package is stopped; saved settings apply when it next starts."
    RESTORE_HTML=""
    if [ -f "${CONF_FILE}.bak" ]; then
        RESTORE_HTML="<form method=\"post\" class=\"inline\" onsubmit=\"return confirm('Restore the settings from before the last save?');\">
<input type=\"hidden\" name=\"action\" value=\"restorecfg\">
<input type=\"hidden\" name=\"tok\" value=\"${TOKEN}\">
<button type=\"submit\">Restore previous settings</button></form>"
    fi
    RESTART_HTML=""
    if [ "${RUNNING}" != "stopped" ]; then
        RESTART_HTML="<form method=\"post\" class=\"inline\">
<input type=\"hidden\" name=\"action\" value=\"restart\">
<input type=\"hidden\" name=\"tok\" value=\"${TOKEN}\">
<button type=\"submit\">Restart fs3</button></form>"
    fi
    SETTINGS_HTML="<p class=\"muted\">Data folder <code>${H_DATA}</code> and
authentication (on once a credential exists) are not changed here. ${APPLY_NOTE}</p>
<form method=\"post\" autocomplete=\"off\">
<input type=\"hidden\" name=\"action\" value=\"savecfg\">
<input type=\"hidden\" name=\"tok\" value=\"${TOKEN}\">
$(render_settings)
<p><button type=\"submit\">Save settings</button></p>
</form>
<p>${RESTORE_HTML} ${RESTART_HTML}</p>"
else
    SETTINGS_HTML="<p class=\"muted\">This page cannot change settings on this DSM
version (no write access to <code>$(html_escape "${VAR_DIR}")</code>). Edit
<code>$(html_escape "${CONF_FILE}")</code> over SSH and restart the package.</p>"
fi

MSGBLOCK=""
if [ -n "${MSG}" ]; then
    CLS="notice"
    case "${QUERY_STRING}" in *m=e_*) CLS="notice err" ;; esac
    MSGBLOCK="<p class=\"${CLS}\">${MSG}</p>"
fi

printf "Content-type: text/html\r\nCache-Control: no-store\r\n\r\n"
cat <<HTML
<!doctype html>
<html><head><meta charset="utf-8"><title>fs3 Object Storage</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 760px;
         margin: 40px auto; color: #264653; line-height: 1.5; padding: 0 16px; }
  h1 { font-size: 22px; }
  h4 { margin: 18px 0 4px; }
  .status { display: inline-block; padding: 2px 10px; border-radius: 12px;
            font-size: 13px; font-weight: 600; }
  .running { background: #2a9d8f; color: #fff; }
  .stopped { background: #e76f51; color: #fff; }
  .restarting { background: #e9c46a; color: #264653; }
  code { background: #f0f0f0; padding: 1px 5px; border-radius: 4px; }
  pre { background: #f6f6f6; padding: 12px; border-radius: 8px; overflow-x: auto; }
  .muted { color: #6b7b82; font-size: 14px; }
  .notice { background: #e9f5f3; border-left: 4px solid #2a9d8f;
            padding: 8px 12px; border-radius: 4px; }
  .notice.err { background: #fdf0ec; border-left-color: #e76f51; }
  table { border-collapse: collapse; margin: 8px 0; }
  th, td { text-align: left; padding: 4px 14px 4px 0; font-size: 14px;
           border-bottom: 1px solid #eee; }
  table.cfg td { border-bottom: none; padding-top: 6px; }
  table.cfg tr.help td { color: #6b7b82; font-size: 13px; padding-top: 0;
                         border-bottom: 1px solid #eee; }
  table.cfg tr.help code { font-size: 11px; }
  tr.tot td { font-weight: 600; border-bottom: none; }
  td form, form.inline { display: inline; margin: 0; }
  label { margin-right: 12px; }
</style></head><body>
<h1>fs3 Object Storage <span class="status ${RUNNING}">${RUNNING}</span></h1>
<p>A single-node, S3-compatible object storage endpoint.</p>
${MSGBLOCK}
${LOGTAIL_HTML}
<p>Endpoint: <code>${ENDPOINT}</code><br>
Data folder: <code>${H_DATA}</code></p>
${BINDLINE}
<h3>Buckets</h3>
${BUCKETS_HTML}
<h3>Replication</h3>
${REPL_HTML}
<h3>Credentials</h3>
<p>${AUTHLINE}</p>
${CREDS_HTML}
<h3>Settings</h3>
${SETTINGS_HTML}
<h3>Connect with the AWS CLI</h3>
<p class="muted">Add to <code>~/.aws/config</code> so path-style addressing is used:</p>
<pre>[default]
region = us-east-1
s3 =
    addressing_style = path</pre>
<pre>aws --endpoint-url ${ENDPOINT} s3 mb s3://my-bucket
aws --endpoint-url ${ENDPOINT} s3 cp file.bin s3://my-bucket/
aws --endpoint-url ${ENDPOINT} s3 ls s3://my-bucket</pre>
<p class="muted">Start/stop fs3 from Package Center. Signed in as
$(html_escape "${UI_USER}").</p>
</body></html>
HTML
