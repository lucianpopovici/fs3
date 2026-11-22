#!/usr/bin/env bash
# tests/compat/duplicati.sh — Duplicati (CLI) against fs3: two backups
# with small volumes, test all with full remote verification, restore
# (latest and older version), delete a version + compact, rebuild the
# local database from the bucket (repair), restore again; plus TLS,
# versioning, Object Lock (--s3-lock-mode / --remote-file-lock-duration)
# and a crash mid-backup.
TOOL_NAME=duplicati
. "$(dirname "$0")/lib.sh"
need duplicati-cli aws2

export DOTNET_CLI_TELEMETRY_OPTOUT=1 SSL_CERT_FILE="$CA"

url() {
    local ssl=false hp="127.0.0.1:$PORT"
    [ "$VARIANT" = tls ] && { ssl=true; hp="localhost:$TPORT"; }
    echo "s3://$BUCKET/dup?s3-server-name=$hp&use-ssl=$ssl&auth-username=$AK&auth-password=$SK&s3-ext-forcepathstyle=true&s3-location-constraint=&s3-client=aws"
}
d() {
    local cmd=$1; shift
    duplicati-cli "$cmd" "$(url)" "$@" --passphrase=compat-duplicati-pass \
        --dbpath="${DBPATH:-$W/dup-$VARIANT.sqlite}" --dblock-size=5mb \
        --console-log-level=Warning --disable-module=console-password-input "${LOCK_OPTS[@]}"
}
# Exit codes: 0 = backup done, 1 = done but nothing changed, 2 = warnings,
# 3+ = errors. Warnings count as failures here.
backup() { d backup "$@"; [ $? -le 1 ]; }
versions() { d list 2>/dev/null | grep -cE '^[0-9]+[[:space:]]*:' || true; }
restore_cmp() {   # restore_cmp <version> <expected-tree>
    rm -rf "$W/restore"
    d restore '*' --version="$1" --restore-path="$W/restore" && same_tree "$2" "$W/restore"
}
verify() { d test all --full-remote-verification=true; }
# A fresh database rebuilt from the bucket alone (lost-NAS scenario).
rebuild_db()      { rm -f "$W/dup-$VARIANT-rebuilt.sqlite"; DBPATH="$W/dup-$VARIANT-rebuilt.sqlite" d repair; }
restore_rebuilt() { DBPATH="$W/dup-$VARIANT-rebuilt.sqlite" restore_cmp 0 "$W/src"; }

full() {
    rm -rf "$W/src" "$W/gen1"; make_dataset "$W/src" 1 "${1:-24}"; cp -a "$W/src" "$W/gen1"
    step "backup 1"                       backup "$W/src/"
    make_dataset "$W/src" 2
    step "backup 2"                       backup "$W/src/"
    step "two versions"                   is_eq "$(versions)" 2
    step "test all (full remote verification)" verify
    step "restore latest = tree 2"        restore_cmp 0 "$W/src"
    step "restore older = tree 1"         restore_cmp 1 "$W/gen1"
    if [ "$VARIANT" != lock ]; then
        step "delete older version"       d delete --version=1
        step "compact"                    d compact --threshold=0
        step "test all after compact"     verify
    fi
    step "rebuild local database (repair)" rebuild_db
    step "restore from rebuilt database"  restore_rebuilt
}

LOCK_OPTS=()
has_compliance() {
    local key vid
    key=$(awsx s3api list-objects-v2 --bucket "$BUCKET" --prefix dup/ --query 'Contents[0].Key' --output text)
    vid=$(awsx s3api list-object-versions --bucket "$BUCKET" --prefix "$key" --query 'Versions[0].VersionId' --output text)
    awsx s3api get-object-retention --bucket "$BUCKET" --key "$key" --version-id "$vid" | grep -q COMPLIANCE
}

scenario_plain()     { full; }
scenario_tls()       { full; }
scenario_versioned() { full; }
scenario_lock() {
    LOCK_OPTS=(--s3-lock-mode=Compliance --remote-file-lock-duration=1D)
    full
    step "volumes carry COMPLIANCE retention" has_compliance
    LOCK_OPTS=()
}
scenario_crash() {
    rm -rf "$W/src"; make_dataset "$W/src" 1 160
    crash_during $((40 << 20)) backup "$W/src/"
    step "repair after restart"           d repair
    step "backup after restart"           backup "$W/src/"
    step "test all"                       verify
    step "restore latest = tree"          restore_cmp 0 "$W/src"
}

compat_main plain tls versioned lock crash
