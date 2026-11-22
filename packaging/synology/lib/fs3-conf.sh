# fs3-conf.sh — the fs3.conf schema, shared by start-stop-status (which
# turns the conf into fs3 command-line flags) and ui/index.cgi (which
# renders and validates the settings form). Sourced, never executed.
# POSIX sh; no bashisms (DSM runs these with /bin/sh).
#
# fs3.conf is data, not code: one KEY=value per line, parsed by
# fs3_conf_load, never sourced. Only keys in the schema (plus a few legacy
# ones) are read, and every value is validated against its type; an
# invalid value falls back to the default and is reported, so a
# hand-edited typo can't keep fs3 from starting or smuggle in a flag.
#
# Schema line: KEY|type|default|section|label|help
#   types: port (1-65535), port0 (0 or 1-65535), int:MIN:MAX,
#          size (0 or digits with an optional K/M/G suffix), bool (0/1),
#          enum:a/b/c, iplist (up to 4 comma-separated IPv4/IPv6
#          addresses, may be empty), host (empty or a lowercase host
#          name), user (empty or an fs3 user name)
#   sections: net, access, limits, jobs, storage, lock, web, repl, ops
# Defaults equal fs3's own defaults unless noted, and a flag is passed
# only when its value differs, so the command line stays short.

fs3_conf_schema() {
    cat <<'SCHEMA'
FS3_PORT|port|9000|net|S3 port|Port of the S3 endpoint. Point the DSM reverse-proxy entry (or clients) at it.
FS3_BIND|enum:127.0.0.1/0.0.0.0|127.0.0.1|net|Listen address|127.0.0.1: reachable only through the DSM reverse proxy, which adds HTTPS (recommended). 0.0.0.0: plain HTTP on the LAN; credentials and data travel unencrypted.
FS3_TRUSTED_PROXY|iplist|127.0.0.1|net|Trusted proxies|Proxies whose X-Forwarded-For/-Proto headers fs3 believes, comma-separated. Keep 127.0.0.1 behind the DSM reverse proxy, or throttling and IP conditions in bucket policies see every client as the NAS itself.
FS3_METRICS_PORT|port0|9101|net|Admin listener port|Local-only /healthz and Prometheus /metrics (127.0.0.1). This page reads bucket statistics from it. 0 disables it.
FS3_PUBLIC_HOST|host||net|Public host for share links|Host name clients use to reach fs3 through the DSM reverse proxy (https on 443). The object browser signs share links for it; empty: links use this page's host and the S3 port, and only when fs3 listens on the LAN. Not passed to fs3.
FS3_ADMIN|user||access|Admin user|fs3 user who can see and manage every bucket. Empty: none.
FS3_LEGACY_OWNER|user||access|Owner of older buckets|Receives buckets created before per-user isolation or with authentication off. Empty: the first user in the credentials list.
FS3_AUTH_FAIL_LIMIT|int:0:100000|20|access|Failed sign-ins before throttling|Per client address and minute; that address then gets 503 SlowDown for a growing period. 0 disables throttling.
FS3_PRESIGN_MAX_EXPIRES|int:1:604800|86400|access|Longest presigned URL (seconds)|Presigned URLs are bearer credentials until they expire. AWS allows up to 604800 (7 days).
FS3_NO_PRESIGN_ADMIN|bool|0|access|Refuse presigned URLs signed by the admin user|
FS3_KEY_MAX_AGE_DAYS|int:0:36500|0|access|Expiry of keys created through the admin API (days)|0: keys never expire.
FS3_ALLOW_PUBLIC|bool|0|access|Allow public buckets and websites|Lifts block-public-access: bucket policies with Principal "*" and website configurations are accepted.
FS3_ALLOW_PUBLIC_WRITE|bool|0|access|Also allow public write policies|Lets a bucket policy grant anonymous uploads. Implies the option above. Rarely a good idea.
FS3_MAX_CONNS|int:1:100000|512|limits|Maximum connections|
FS3_IDLE_TIMEOUT|int:0:86400|60|limits|Idle timeout (seconds)|Idle connections are closed after this long. 0 disables.
FS3_MAX_BODY_SIZE|size|5G|limits|Largest request body|Larger uploads get 413. Accepts K, M, G suffixes; 0 = no limit.
FS3_MIN_FREE|size|0|limits|Keep this much disk free|Uploads are refused when the volume has less free space. 0 = no floor.
FS3_DEFAULT_BUCKET_QUOTA|size|0|limits|Default bucket quota|For buckets without their own quota. 0 = none.
FS3_DEFAULT_USER_QUOTA|size|0|limits|Default user quota|Per user, over the buckets they own. 0 = none.
FS3_MPU_MIN_PART_SIZE|size|5M|limits|Minimum multipart part size|Every part except the last; S3 uses 5M.
FS3_IO_THREADS|int:0:64|4|limits|Worker threads|For fsync, copies and multipart completion.
FS3_GC_INTERVAL|int:1:86400|60|jobs|Multipart cleanup interval (seconds)|
FS3_GC_MAX_AGE|int:1:31536000|86400|jobs|Abandon multipart uploads after (seconds)|
FS3_LIFECYCLE_HOUR|int:-1:23|3|jobs|Lifecycle sweep hour|Local hour (0-23) of the daily lifecycle run; -1 never runs it.
FS3_LIFECYCLE_RATE|int:0:100000|100|jobs|Lifecycle deletions per second|0 = no cap.
FS3_LIFECYCLE_DRY_RUN|bool|0|jobs|Lifecycle dry run|Log what lifecycle rules would delete, delete nothing.
FS3_SCRUB_INTERVAL_DAYS|int:0:3650|30|jobs|Integrity scrub every (days)|0: only on demand.
FS3_SCRUB_RATE|size|20M|jobs|Scrub read rate (per second)|0 = unthrottled.
FS3_SCRUB_FAIL_READS|bool|0|jobs|Refuse reads of corrupt objects|A GET of a version the scrub found corrupt answers 500 instead of returning bad bytes.
FS3_REFLINK|enum:auto/off|auto|storage|Extent cloning (reflink)|auto: on Btrfs, multipart completion and copies share extents instead of copying.
FS3_DEDUP|enum:off/owner/global|off|storage|Whole-object dedup|Identical objects share disk space (Btrfs). owner: within each user's buckets. global: across users; lets one user learn that another stores a file, so single-user NAS only. Don't combine with compression on DSM 7.1.
FS3_DEDUP_MIN_SIZE|size|1M|storage|Dedup objects of at least|
FS3_DEDUP_VERIFY|bool|0|storage|Byte-compare before sharing|
FS3_FS_COMPRESS|enum:off/auto/all|off|storage|Btrfs compression|auto skips already-compressed types (images, video, archives). On DSM 7.1 don't combine with dedup.
FS3_MAX_RETENTION_DAYS|int:1:36500|3650|lock|Longest Object Lock retention (days)|Caps what clients may set, so writers can't fill the volume with undeletable data.
FS3_LOCK_IMMUTABLE|bool|0|lock|Immutable COMPLIANCE versions (fs3-lockd)|Needs the fs3-lockd helper running as root (see the package notes). fs3 refuses to start without it, so this can only be turned on while the helper's socket exists.
FS3_WEB_PORT|port0|0|web|Website port|Serves buckets with a website configuration anonymously (GET/HEAD) on this port, on the listen address above. Needs public buckets allowed. 0 disables.
FS3_WEB_ROOT_DOMAIN|host||web|Website root domain|Sites at <bucket>.<domain>. Empty: the Host header must equal the bucket name (custom domains through the reverse proxy).
FS3_REPL_WORKERS|int:0:16|2|repl|Replication threads|Buckets with a replication rule are copied to their target by this many threads. 0 turns replication off (rules are kept but nothing is sent).
FS3_REPL_RATE|size|20M|repl|Replication upload rate (per second)|Shared by all buckets. 0 = unthrottled.
FS3_REPL_TIMEOUT|int:1:3600|30|repl|Replication timeout (seconds)|Per network operation; a slower target counts as unreachable and is retried with backoff.
FS3_SSE_S3|bool|0|storage|Server-side encryption keys (SSE-S3)|Creates sse.keys in the package folder on the next start. Objects are then encrypted on disk when a client asks for it (x-amz-server-side-encryption: AES256) or the bucket has default encryption. BACK UP sse.keys apart from the data: without it, encrypted objects cannot be read. Turning this off later keeps using the existing file.
FS3_AUDIT_LOG|bool|0|ops|Audit log|One JSON line per request and admin change in audit.jsonl in the package folder. Rotated like the server log.
FS3_LOG_MAX_SIZE|size|10M|ops|Rotate logs at|fs3.log and audit.jsonl are rotated when they reach this size (K, M, G suffixes). 0 never rotates.
FS3_LOG_KEEP|int:1:50|5|ops|Rotated logs kept|fs3.log.1 … fs3.log.N (and the same for the audit log).
FS3_ADMIN_SOCKET|bool|1|ops|Admin API socket|Serves the /v1 admin API on admin.sock in the package folder (mode 0600, package user only). The Replication section of this page uses it.
FS3_SECCOMP|enum:enforce/log/require/off|enforce|ops|System call filter (seccomp)|DSM 7.1's kernel has no seccomp filter support, so on a DS1515+ enforce only logs a warning; require would keep fs3 from starting there.
FS3_VERBOSE|bool|0|ops|Debug logging|Much more output in fs3.log.
SCHEMA
}

# Keys read from fs3.conf but not edited in the settings form: the data
# folder (moving it needs moving the data), the auth switch (turned on by
# adding the first credential) and two legacy keys from old confs.
FS3_CONF_EXTRA_KEYS="FS3_DATA FS3_REQUIRE_AUTH FS3_ACCESS_KEY FS3_SECRET_KEY"

# Section titles, in display order.
fs3_conf_sections() {
    cat <<'SECTIONS'
net|Network
access|Access and authentication
limits|Limits and quotas
jobs|Background jobs
storage|Storage efficiency
lock|Object Lock
web|Static websites
repl|Replication
ops|Logging and hardening
SECTIONS
}

# Index the schema once into shell variables (_FS3T_<KEY> = type,
# _FS3D_<KEY> = default) so lookups don't fork; the CGI renders ~40
# fields on a slow Atom CPU.
FS3_CONF_KEYS=""
while IFS='|' read -r _k _t _d _rest; do
    [ -n "${_k}" ] || continue
    eval "_FS3T_${_k}=\${_t}; _FS3D_${_k}=\${_d}"
    FS3_CONF_KEYS="${FS3_CONF_KEYS} ${_k}"
done <<FS3_SCHEMA_EOF
$(fs3_conf_schema)
FS3_SCHEMA_EOF

fs3_conf_is_key() {   # schema (form) key?
    case "$1" in ''|*[!A-Z0-9_]*) return 1 ;; esac
    case "${FS3_CONF_KEYS} " in *" $1 "*) return 0 ;; esac
    return 1
}
fs3_conf_type()    { fs3_conf_is_key "$1" && eval "printf '%s' \"\${_FS3T_$1}\""; }
fs3_conf_default() { fs3_conf_is_key "$1" && eval "printf '%s' \"\${_FS3D_$1}\""; }
fs3_conf_keys()    { printf '%s\n' ${FS3_CONF_KEYS}; }

# Decimal integer, optional leading '-', at most 9 digits.
_fs3_is_int() {
    _v="${1#-}"
    case "${_v}" in ''|*[!0-9]*) return 1 ;; esac
    [ "${#_v}" -le 9 ]
}

_fs3_is_ipv4() {
    case "$1" in ''|*[!0-9.]*) return 1 ;; esac
    _ip="$1"; _n=0
    _oldifs="${IFS}"; IFS='.'
    set -- ${_ip}
    IFS="${_oldifs}"
    [ $# -eq 4 ] || return 1
    for _o in "$@"; do
        case "${_o}" in ''|*[!0-9]*) return 1 ;; esac
        [ "${#_o}" -le 3 ] && [ "${_o}" -le 255 ] || return 1
    done
    return 0
}

_fs3_is_ipv6() {
    case "$1" in *:*) ;; *) return 1 ;; esac
    case "$1" in *[!0-9A-Fa-f:.]*) return 1 ;; esac
    [ "${#1}" -ge 2 ] && [ "${#1}" -le 45 ]
}

# fs3_conf_valid TYPE VALUE: 0 if VALUE is acceptable for TYPE.
fs3_conf_valid() {
    _t="$1"; _v="$2"
    case "${_v}" in *'
'*) return 1 ;; esac
    case "${_t}" in
    port)
        _fs3_is_int "${_v}" && [ "${_v}" -ge 1 ] && [ "${_v}" -le 65535 ] ;;
    port0)
        [ "${_v}" = "0" ] || { _fs3_is_int "${_v}" && [ "${_v}" -ge 1 ] && [ "${_v}" -le 65535 ]; } ;;
    int:*)
        _r="${_t#int:}"; _min="${_r%%:*}"; _max="${_r#*:}"
        _fs3_is_int "${_v}" && [ "${_v}" -ge "${_min}" ] && [ "${_v}" -le "${_max}" ] ;;
    size)
        _d="${_v%[KMGkmg]}"
        case "${_d}" in ''|*[!0-9]*) return 1 ;; esac
        [ "${#_d}" -le 13 ] ;;
    bool)
        [ "${_v}" = "0" ] || [ "${_v}" = "1" ] ;;
    enum:*)
        _opts="/${_t#enum:}/"
        case "${_v}" in ''|*/*) return 1 ;; esac
        case "${_opts}" in *"/${_v}/"*) return 0 ;; esac
        return 1 ;;
    iplist)
        [ -z "${_v}" ] && return 0
        case "${_v}" in *[!0-9A-Fa-f:.,]*) return 1 ;; esac
        _cnt=0
        _oldifs="${IFS}"; IFS=','
        for _ip in ${_v}; do
            IFS="${_oldifs}"
            _cnt=$((_cnt + 1))
            [ "${_cnt}" -le 4 ] || return 1
            _fs3_is_ipv4 "${_ip}" || _fs3_is_ipv6 "${_ip}" || return 1
            IFS=','
        done
        IFS="${_oldifs}"
        [ "${_cnt}" -ge 1 ] ;;
    host)
        [ -z "${_v}" ] && return 0
        case "${_v}" in *[!a-z0-9.-]*|.*|*.|-*) return 1 ;; esac
        [ "${#_v}" -le 253 ] ;;
    user)
        [ -z "${_v}" ] && return 0
        case "${_v}" in *[!A-Za-z0-9._@-]*) return 1 ;; esac
        [ "${#_v}" -le 64 ] ;;
    path)
        case "${_v}" in /*) ;; *) return 1 ;; esac
        case "${_v}" in *[[:cntrl:]]*) return 1 ;; esac
        return 0 ;;
    *)
        return 1 ;;
    esac
}

# Set every schema key to its default (and the extra keys to theirs).
fs3_conf_defaults() {
    _vardir="$1"
    for _k in ${FS3_CONF_KEYS}; do
        eval "${_k}=\${_FS3D_${_k}}"
    done
    FS3_DATA="${_vardir}/data"
    FS3_REQUIRE_AUTH="0"
    FS3_ACCESS_KEY=""
    FS3_SECRET_KEY=""
}

# fs3_conf_load FILE: read KEY=value lines over the current values.
# Unknown keys are ignored; invalid values keep the current value and are
# reported on stderr ("fs3.conf: ..."), once per key. A single pair of
# surrounding double quotes is stripped (confs written by old versions).
fs3_conf_load() {
    [ -f "$1" ] || return 0
    while IFS= read -r _line || [ -n "${_line}" ]; do
        case "${_line}" in ''|'#'*) continue ;; esac
        case "${_line}" in *=*) ;; *) continue ;; esac
        _key="${_line%%=*}"
        _val="${_line#*=}"
        _val="$(printf '%s' "${_val}" | tr -d '\r')"
        case "${_val}" in
            '"'*'"') _val="${_val#\"}"; _val="${_val%\"}" ;;
        esac
        case " ${FS3_CONF_EXTRA_KEYS} " in
        *" ${_key} "*)
            case "${_key}" in
            FS3_DATA)
                if fs3_conf_valid path "${_val}"; then FS3_DATA="${_val}"
                else echo "fs3.conf: ignoring invalid FS3_DATA" >&2; fi ;;
            FS3_REQUIRE_AUTH)
                if fs3_conf_valid bool "${_val}"; then FS3_REQUIRE_AUTH="${_val}"
                else echo "fs3.conf: ignoring invalid FS3_REQUIRE_AUTH" >&2; fi ;;
            FS3_ACCESS_KEY|FS3_SECRET_KEY)
                case "${_val}" in *:*|*[[:cntrl:]]*) ;; *) eval "${_key}=\${_val}" ;; esac ;;
            esac
            continue ;;
        esac
        fs3_conf_is_key "${_key}" || continue
        if fs3_conf_valid "$(fs3_conf_type "${_key}")" "${_val}"; then
            eval "${_key}=\${_val}"
        else
            echo "fs3.conf: ignoring invalid value for ${_key}; using $(eval "printf '%s' \"\${${_key}}\"")" >&2
        fi
    done < "$1"
}

# fs3_conf_get KEY: print the current value of a schema or extra key.
fs3_conf_get() {
    case "$1" in ''|*[!A-Z0-9_]*) return 1 ;; esac
    eval "printf '%s' \"\${$1}\""
}

# fs3_conf_args VAR_DIR: print fs3's command-line arguments, one per line,
# from the current values. Values are validated, so none contains a
# newline. Authentication (credentials file, admin, legacy owner) is left
# to the caller, which knows about the credentials file.
fs3_conf_args() {
    _vd="$1"
    printf '%s\n' -a "${FS3_BIND}" -p "${FS3_PORT}" -d "${FS3_DATA}" \
        --mpu-gc-interval "${FS3_GC_INTERVAL}" --mpu-gc-max-age "${FS3_GC_MAX_AGE}" \
        --log-file "${_vd}/fs3.log"
    [ "${FS3_METRICS_PORT}" != "0" ] && printf '%s\n' --metrics-port "${FS3_METRICS_PORT}"

    if [ -n "${FS3_TRUSTED_PROXY}" ]; then
        _oldifs="${IFS}"; IFS=','
        for _ip in ${FS3_TRUSTED_PROXY}; do
            printf '%s\n' --trusted-proxy "${_ip}"
        done
        IFS="${_oldifs}"
    fi

    # Value flags: passed only when different from fs3's default.
    for _pair in \
        FS3_AUTH_FAIL_LIMIT:--auth-fail-limit \
        FS3_PRESIGN_MAX_EXPIRES:--presign-max-expires \
        FS3_KEY_MAX_AGE_DAYS:--key-max-age-days \
        FS3_MAX_CONNS:--max-conns \
        FS3_IDLE_TIMEOUT:--idle-timeout \
        FS3_MAX_BODY_SIZE:--max-body-size \
        FS3_MIN_FREE:--min-free-bytes \
        FS3_DEFAULT_BUCKET_QUOTA:--default-bucket-quota \
        FS3_DEFAULT_USER_QUOTA:--default-user-quota \
        FS3_MPU_MIN_PART_SIZE:--mpu-min-part-size \
        FS3_IO_THREADS:--io-threads \
        FS3_LIFECYCLE_HOUR:--lifecycle-hour \
        FS3_LIFECYCLE_RATE:--lifecycle-rate \
        FS3_SCRUB_INTERVAL_DAYS:--scrub-interval-days \
        FS3_SCRUB_RATE:--scrub-rate \
        FS3_REPL_WORKERS:--repl-workers \
        FS3_REPL_RATE:--repl-rate \
        FS3_REPL_TIMEOUT:--repl-timeout \
        FS3_REFLINK:--reflink \
        FS3_DEDUP:--dedup \
        FS3_DEDUP_MIN_SIZE:--dedup-min-size \
        FS3_FS_COMPRESS:--fs-compress \
        FS3_MAX_RETENTION_DAYS:--max-retention-days \
        FS3_SECCOMP:--seccomp \
        FS3_LOG_MAX_SIZE:--log-max-size \
        FS3_LOG_KEEP:--log-keep
    do
        _k="${_pair%%:*}"; _f="${_pair#*:}"
        _cur="$(fs3_conf_get "${_k}")"
        [ "${_cur}" != "$(fs3_conf_default "${_k}")" ] && printf '%s\n' "${_f}" "${_cur}"
    done

    # Switches.
    [ "${FS3_NO_PRESIGN_ADMIN}" = "1" ]   && printf '%s\n' --no-presign-admin
    [ "${FS3_ALLOW_PUBLIC}" = "1" ]       && printf '%s\n' --allow-public
    [ "${FS3_ALLOW_PUBLIC_WRITE}" = "1" ] && printf '%s\n' --allow-public-write
    [ "${FS3_LIFECYCLE_DRY_RUN}" = "1" ]  && printf '%s\n' --lifecycle-dry-run
    [ "${FS3_SCRUB_FAIL_READS}" = "1" ]   && printf '%s\n' --scrub-fail-reads
    [ "${FS3_DEDUP_VERIFY}" = "1" ]       && printf '%s\n' --dedup-verify
    [ "${FS3_VERBOSE}" = "1" ]            && printf '%s\n' -v

    # Features with fixed files in the package folder (never a path from
    # the conf, so the form can't point fs3 at arbitrary files).
    [ "${FS3_LOCK_IMMUTABLE}" = "1" ] && \
        printf '%s\n' --lock-immutable --lockd-socket "${_vd}/lockd.sock"
    [ "${FS3_AUDIT_LOG}" = "1" ]    && printf '%s\n' --audit-log "${_vd}/audit.jsonl"
    [ "${FS3_ADMIN_SOCKET}" = "1" ] && printf '%s\n' --admin-socket "${_vd}/admin.sock"
    [ -r "${_vd}/repl-ca.pem" ]     && printf '%s\n' --repl-ca-file "${_vd}/repl-ca.pem"

    if [ "${FS3_WEB_PORT}" != "0" ]; then
        printf '%s\n' --web-port "${FS3_WEB_PORT}" --web-addr "${FS3_BIND}"
        [ -n "${FS3_WEB_ROOT_DOMAIN}" ] && printf '%s\n' --web-root-domain "${FS3_WEB_ROOT_DOMAIN}"
    fi
    return 0
}

# fs3_conf_write FILE: rewrite FILE with the current values of the form
# keys, keeping every other line (comments, FS3_DATA, FS3_REQUIRE_AUTH,
# unknown keys) as it was. Only values that differ from the default are
# written, so a future change of a default still reaches this install.
# Atomic (tmp + rename); the previous file is kept as FILE.bak.
fs3_conf_write() {
    _f="$1"; _tmp="$1.tmp.$$"
    _keys="${FS3_CONF_KEYS}"
    {
        if [ -f "${_f}" ]; then
            awk -v keys=" ${_keys}" '
                /^# Settings below are managed by the fs3 DSM tile/ { next }
                { k = $0; sub(/=.*/, "", k) }
                index(keys, " " k " ") && $0 ~ /=/ { next }
                { print }' "${_f}"
        fi
        echo "# Settings below are managed by the fs3 DSM tile (defaults are omitted)."
        for _k in ${_keys}; do
            _cur="$(fs3_conf_get "${_k}")"
            if [ "${_cur}" != "$(fs3_conf_default "${_k}")" ]; then
                printf '%s=%s\n' "${_k}" "${_cur}"
            fi
        done
    } > "${_tmp}" 2>/dev/null || { rm -f "${_tmp}"; return 1; }
    chmod 600 "${_tmp}" 2>/dev/null
    [ -f "${_f}" ] && cp -p "${_f}" "${_f}.bak" 2>/dev/null
    mv "${_tmp}" "${_f}" 2>/dev/null || { rm -f "${_tmp}"; return 1; }
}
