#!/bin/sh
# index.cgi — simple status/connection-info page for the fs3 DSM tile.
# fs3 has no web UI of its own; this page tells the admin how to connect.

VAR_DIR="/var/packages/fs3/var"
CONF_FILE="${VAR_DIR}/fs3.conf"
PID_FILE="${VAR_DIR}/fs3.pid"

FS3_PORT="9000"
FS3_BIND="127.0.0.1"
FS3_REQUIRE_AUTH="0"
FS3_DATA=""

# Parse the conf line-by-line — never source it. Conf values originate
# from install-wizard input; sourcing would execute them as shell (as
# the DSM web user, every time someone opens this tile).
if [ -f "${CONF_FILE}" ]; then
    while IFS= read -r line || [ -n "${line}" ]; do
        case "${line}" in ''|'#'*) continue ;; esac
        key="${line%%=*}"
        val="${line#*=}"
        case "${val}" in
            '"'*'"') val="${val#\"}"; val="${val%\"}" ;;
        esac
        case "${key}" in
            FS3_PORT|FS3_BIND|FS3_DATA|FS3_REQUIRE_AUTH)
                eval "${key}=\${val}" ;;
        esac
    done < "${CONF_FILE}"
fi

# Escape conf-derived strings before interpolating them into HTML.
html_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' \
                           -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}
H_PORT="$(html_escape "${FS3_PORT}")"
H_DATA="$(html_escape "${FS3_DATA}")"

RUNNING="stopped"
if [ -f "${PID_FILE}" ]; then
    PID="$(cat "${PID_FILE}" 2>/dev/null)"
    if [ -n "${PID}" ] && kill -0 "${PID}" 2>/dev/null; then
        RUNNING="running"
    fi
fi

AUTHLINE="Authentication is <b>disabled</b> &mdash; any client that can reach the port has full access. Safe only on a trusted LAN."
if [ "${FS3_REQUIRE_AUTH}" = "1" ]; then
    AUTHLINE="Authentication is <b>enabled</b> (SigV4). Credentials are configured in <code>${VAR_DIR}/credentials</code> (one <code>access_key:secret_key</code> per line)."
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
</style></head><body>
<h1>fs3 Object Storage <span class="status ${RUNNING}">${RUNNING}</span></h1>
<p>A single-node, S3-compatible object storage endpoint.</p>
<p>Endpoint: <code>${ENDPOINT}</code><br>
Data folder: <code>${H_DATA}</code></p>
${BINDLINE}
<p>${AUTHLINE}</p>
<h3>Connect with the AWS CLI</h3>
<p class="muted">Add to <code>~/.aws/config</code> so path-style addressing is used:</p>
<pre>[default]
region = us-east-1
s3 =
    addressing_style = path</pre>
<pre>aws --endpoint-url ${ENDPOINT} s3 mb s3://my-bucket
aws --endpoint-url ${ENDPOINT} s3 cp file.bin s3://my-bucket/
aws --endpoint-url ${ENDPOINT} s3 ls s3://my-bucket</pre>
<p class="muted">Start/stop fs3 from Package Center. Change the port, data
folder, or credentials by editing <code>${CONF_FILE}</code> and restarting
the package.</p>
</body></html>
HTML
