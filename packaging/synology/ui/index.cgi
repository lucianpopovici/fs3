#!/bin/sh
# index.cgi — status/connection-info + small admin console for the fs3
# DSM tile. Shows live bucket stats (via the localhost admin listener)
# and lets the admin define SigV4 credentials (written to the 0600
# credentials file, activated live via SIGHUP).
#
# Security posture, since this CGI now writes state:
#  - The conf is parsed line-by-line, never sourced (wizard input must
#    not execute as shell).
#  - POSTs require a random token from ${VAR_DIR}/.ui-csrf (rendered
#    into the form, compared on submit) plus an Origin/Host match when
#    the browser sends Origin. Defeats cross-site form posts.
#  - Access/secret keys are restricted to [A-Za-z0-9._-]; anything else
#    (including form-encoded %xx or +) is rejected outright, so no
#    URL-decoding pass and no chance of smuggling ':' or newlines into
#    the credentials file.
#  - Secrets are never rendered back into the page.
#  - Credential writes are tmp + chmod 600 + rename, like every other
#    write in fs3.

# FS3_VAR_DIR is settable only by the web server's environment (clients
# can only influence HTTP_* vars); it exists so tests can run this CGI
# against a scratch directory.
VAR_DIR="${FS3_VAR_DIR:-/var/packages/fs3/var}"
CONF_FILE="${VAR_DIR}/fs3.conf"
CRED_FILE="${VAR_DIR}/credentials"
PID_FILE="${VAR_DIR}/fs3.pid"
CHILD_PID_FILE="${VAR_DIR}/fs3.child.pid"
TOK_FILE="${VAR_DIR}/.ui-csrf"

FS3_PORT="9000"
FS3_BIND="127.0.0.1"
FS3_REQUIRE_AUTH="0"
FS3_DATA=""
FS3_METRICS_PORT="9101"

# Parse the conf line-by-line — never source it. Conf values originate
# from install-wizard input; sourcing would execute them as shell (as
# the CGI user, every time someone opens this tile).
if [ -f "${CONF_FILE}" ]; then
    while IFS= read -r line || [ -n "${line}" ]; do
        case "${line}" in ''|'#'*) continue ;; esac
        key="${line%%=*}"
        val="${line#*=}"
        case "${val}" in
            '"'*'"') val="${val#\"}"; val="${val%\"}" ;;
        esac
        case "${key}" in
            FS3_PORT|FS3_BIND|FS3_DATA|FS3_REQUIRE_AUTH|FS3_METRICS_PORT)
                eval "${key}=\${val}" ;;
        esac
    done < "${CONF_FILE}"
fi

# Escape strings before interpolating them into HTML (covers attribute
# context too via the quote rule).
html_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' \
                           -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
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
SCRIPT_PATH="$(printf '%s' "${SCRIPT_NAME:-index.cgi}" | tr -d '\r\n ')"
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

# Tell a running fs3 to reload the credentials file (SIGHUP swaps the
# credential set atomically; a bad file keeps the old set).
reload_creds() {
    [ "${FS3_REQUIRE_AUTH}" = "1" ] || return 0
    [ -f "${CHILD_PID_FILE}" ] || return 0
    cpid="$(cat "${CHILD_PID_FILE}" 2>/dev/null)"
    [ -n "${cpid}" ] && kill -HUP "${cpid}" 2>/dev/null
    return 0
}

valid_key() {  # $1=value $2=min $3=max — charset [A-Za-z0-9._-]
    case "$1" in ''|*[!A-Za-z0-9._-]*) return 1 ;; esac
    [ "${#1}" -ge "$2" ] && [ "${#1}" -le "$3" ]
}

handle_post() {
    # Same-origin check: browsers send Origin on cross-site POSTs.
    if [ -n "${HTTP_ORIGIN}" ] && [ "${HTTP_ORIGIN}" != "null" ]; then
        o="${HTTP_ORIGIN#*://}"; o="${o%%/*}"
        [ "${o}" = "${HTTP_HOST}" ] || redirect e_csrf
    fi

    case "${CONTENT_LENGTH}" in ''|*[!0-9]*) redirect e_req ;; esac
    [ "${CONTENT_LENGTH}" -gt 8192 ] && redirect e_req
    body="$(dd bs=1 count="${CONTENT_LENGTH}" 2>/dev/null)"

    F_ACTION=""; F_AK=""; F_SK=""; F_TOK=""
    oldifs="${IFS}"; IFS='&'
    for pair in ${body}; do
        k="${pair%%=*}"; v="${pair#*=}"
        case "${k}" in
            action) F_ACTION="${v}" ;;
            ak)     F_AK="${v}" ;;
            sk)     F_SK="${v}" ;;
            tok)    F_TOK="${v}" ;;
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
        # Keep comments and other keys; same access key is replaced.
        {
            [ -f "${CRED_FILE}" ] && \
                awk -F: -v k="${F_AK}" \
                    '/^[ \t]*#/ || NF < 2 { print; next } $1 != k' \
                    "${CRED_FILE}"
            printf '%s:%s\n' "${F_AK}" "${F_SK}"
        } | write_creds || redirect e_write

        if [ "${FS3_REQUIRE_AUTH}" != "1" ]; then
            # First credential: turn authentication on in the conf. The
            # flag only takes effect on the next package start, so the
            # success message tells the admin to restart.
            awk 'BEGIN { done = 0 }
                 /^FS3_REQUIRE_AUTH=/ { print "FS3_REQUIRE_AUTH=1"; done = 1; next }
                 { print }
                 END { if (!done) print "FS3_REQUIRE_AUTH=1" }' \
                "${CONF_FILE}" > "${CONF_FILE}.tmp.$$" 2>/dev/null \
                && mv "${CONF_FILE}.tmp.$$" "${CONF_FILE}" 2>/dev/null \
                || { rm -f "${CONF_FILE}.tmp.$$"; redirect e_write; }
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

RUNNING="stopped"
if [ -f "${PID_FILE}" ]; then
    PID="$(cat "${PID_FILE}" 2>/dev/null)"
    if [ -n "${PID}" ] && kill -0 "${PID}" 2>/dev/null; then
        RUNNING="running"
    fi
fi

# Fixed message codes -> fixed strings; nothing user-supplied reflects.
MSG=""
case "${QUERY_STRING}" in
    *m=added_restart*) MSG="Credential saved and authentication enabled in fs3.conf. Restart the package (Package Center &gt; fs3 &gt; Stop, then Run) to activate it." ;;
    *m=added*)   MSG="Credential saved. The running server reloaded it — it is active now." ;;
    *m=removed*) MSG="Credential removed and reloaded." ;;
    *m=e_csrf*)  MSG="Error: the form expired (security token mismatch). Reload the page and try again." ;;
    *m=e_ak*)    MSG="Error: the access key must be 3&ndash;64 characters from A&ndash;Z a&ndash;z 0&ndash;9 . _ -" ;;
    *m=e_sk*)    MSG="Error: the secret key must be 8&ndash;128 characters from A&ndash;Z a&ndash;z 0&ndash;9 . _ -" ;;
    *m=e_last*)  MSG="Error: refusing to remove the last credential while authentication is enabled &mdash; that would lock every client out." ;;
    *m=e_nokey*) MSG="Error: no such access key." ;;
    *m=e_write*) MSG="Error: could not write to ${VAR_DIR}. The CGI does not run with the package user's permissions on this DSM version; edit ${CRED_FILE} over SSH instead." ;;
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
the LAN instead, set <code>FS3_BIND=0.0.0.0</code> in <code>${CONF_FILE}</code>
and restart the package.</p>"
fi

# Bucket stats from the admin listener: "<name> <objects> <bytes>" lines.
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
                printf "<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>\n", name, $2, hs
                nb++; tobj += $2; tb += b
                if      (tb < 1024)       ts = sprintf("%d B", tb)
                else if (tb < 1048576)    ts = sprintf("%.1f KiB", tb / 1024)
                else if (tb < 1073741824) ts = sprintf("%.1f MiB", tb / 1048576)
                else                      ts = sprintf("%.2f GiB", tb / 1073741824)
            }
            END {
                if (nb > 1)
                    printf "<tr class=\"tot\"><td>%d buckets</td><td>%s</td><td>%s</td></tr>\n", nb, tobj, ts
            }')"
        BUCKETS_HTML="<table>
<tr><th>Bucket</th><th>Objects</th><th>Size</th></tr>
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
        BUCKETS_HTML="<p class=\"muted\">Bucket statistics need the admin listener; set <code>FS3_METRICS_PORT</code> in <code>$(html_escape "${CONF_FILE}")</code> and restart the package.</p>"
    else
        BUCKETS_HTML="<p class=\"muted\">Bucket statistics are unavailable (could not reach the admin listener on 127.0.0.1:$(html_escape "${FS3_METRICS_PORT}")).</p>"
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
            KEYROWS="${KEYROWS}<tr><td><code>${hak}</code></td><td>
<form method=\"post\" onsubmit=\"return confirm('Remove access key ${hak}?');\">
<input type=\"hidden\" name=\"action\" value=\"delkey\">
<input type=\"hidden\" name=\"tok\" value=\"${TOKEN}\">
<input type=\"hidden\" name=\"ak\" value=\"${hak}\">
<button type=\"submit\">Remove</button></form></td></tr>"
        done < "${CRED_FILE}"
    fi
    if [ -n "${KEYROWS}" ]; then
        CREDS_HTML="<table><tr><th>Access key</th><th></th></tr>${KEYROWS}</table>"
    else
        CREDS_HTML="<p class=\"muted\">No credentials defined.</p>"
    fi
    RESTART_NOTE=""
    if [ "${FS3_REQUIRE_AUTH}" != "1" ]; then
        RESTART_NOTE="<p class=\"muted\">Adding the first credential enables
authentication; you will be asked to restart the package once.</p>"
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
<button type=\"submit\">Add / replace</button>
</p>
</form>
<p class=\"muted\">Keys may contain letters, digits and <code>. _ -</code>
(generate a secret with e.g. <code>openssl rand -hex 32</code>). Adding an
existing access key replaces its secret. Changes are reloaded by the running
server without a restart.</p>
${RESTART_NOTE}"
fi

MSGBLOCK=""
if [ -n "${MSG}" ]; then
    CLS="notice"
    case "${QUERY_STRING}" in *m=e_*) CLS="notice err" ;; esac
    MSGBLOCK="<p class=\"${CLS}\">${MSG}</p>"
fi

printf "Content-type: text/html\r\n\r\n"
cat <<HTML
<!doctype html>
<html><head><meta charset="utf-8"><title>fs3 Object Storage</title>
<style>
  body { font-family: -apple-system, system-ui, sans-serif; max-width: 640px;
         margin: 40px auto; color: #264653; line-height: 1.5; padding: 0 16px; }
  h1 { font-size: 22px; }
  .status { display: inline-block; padding: 2px 10px; border-radius: 12px;
            font-size: 13px; font-weight: 600; }
  .running { background: #2a9d8f; color: #fff; }
  .stopped { background: #e76f51; color: #fff; }
  code { background: #f0f0f0; padding: 1px 5px; border-radius: 4px; }
  pre { background: #f6f6f6; padding: 12px; border-radius: 8px; overflow-x: auto; }
  .muted { color: #6b7b82; font-size: 14px; }
  .notice { background: #e9f5f3; border-left: 4px solid #2a9d8f;
            padding: 8px 12px; border-radius: 4px; }
  .notice.err { background: #fdf0ec; border-left-color: #e76f51; }
  table { border-collapse: collapse; margin: 8px 0; }
  th, td { text-align: left; padding: 4px 14px 4px 0; font-size: 14px;
           border-bottom: 1px solid #eee; }
  tr.tot td { font-weight: 600; border-bottom: none; }
  td form { margin: 0; }
  label { margin-right: 12px; }
</style></head><body>
<h1>fs3 Object Storage <span class="status ${RUNNING}">${RUNNING}</span></h1>
<p>A single-node, S3-compatible object storage endpoint.</p>
${MSGBLOCK}
<p>Endpoint: <code>${ENDPOINT}</code><br>
Data folder: <code>${H_DATA}</code></p>
${BINDLINE}
<h3>Buckets</h3>
${BUCKETS_HTML}
<h3>Credentials</h3>
<p>${AUTHLINE}</p>
${CREDS_HTML}
<h3>Connect with the AWS CLI</h3>
<p class="muted">Add to <code>~/.aws/config</code> so path-style addressing is used:</p>
<pre>[default]
region = us-east-1
s3 =
    addressing_style = path</pre>
<pre>aws --endpoint-url ${ENDPOINT} s3 mb s3://my-bucket
aws --endpoint-url ${ENDPOINT} s3 cp file.bin s3://my-bucket/
aws --endpoint-url ${ENDPOINT} s3 ls s3://my-bucket</pre>
<p class="muted">Start/stop fs3 from Package Center. Change the port or data
folder by editing <code>${CONF_FILE}</code> and restarting the package.</p>
</body></html>
HTML
