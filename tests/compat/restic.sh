#!/usr/bin/env bash
# tests/compat/restic.sh — restic against fs3: init, two snapshots,
# check --read-data, restore (latest and first), forget --prune, check
# again; plus TLS, versioning, Object Lock and a crash mid-backup.
TOOL_NAME=restic
. "$(dirname "$0")/lib.sh"
need restic aws2

export RESTIC_PASSWORD=compat-restic-password
export AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_DEFAULT_REGION=$REGION

r() {
    local extra=()
    [ "$VARIANT" = tls ] && extra=(--cacert "$CA")
    restic -r "s3:$(endpoint)/$BUCKET/repo" --no-cache "${extra[@]}" "$@"
}
backup() { (cd "$1" && r backup --host compat .); }
restore_cmp() {   # restore_cmp <snapshot> <expected-tree>
    rm -rf "$W/restore"
    r restore "$1" --target "$W/restore" && same_tree "$2" "$W/restore"
}

full() {
    local big=${1:-24}
    rm -rf "$W/src" "$W/gen1"
    make_dataset "$W/src" 1 "$big"
    cp -a "$W/src" "$W/gen1"
    step "init"                       r init
    step "backup 1"                   backup "$W/src"
    make_dataset "$W/src" 2
    step "backup 2"                   backup "$W/src"
    step "two snapshots"              is_eq "$(r snapshots --json | python3 -c 'import sys,json; print(len(json.load(sys.stdin)))')" 2
    step "check --read-data"          r check --read-data
    step "restore latest = tree 2"    restore_cmp latest "$W/src"
    local first
    first=$(r snapshots --json | python3 -c 'import sys,json; print(sorted(json.load(sys.stdin), key=lambda s: s["time"])[0]["short_id"])')
    step "restore first = tree 1"     restore_cmp "$first" "$W/gen1"
    step "forget --keep-last 1 --prune" r forget --keep-last 1 --prune
    step "check --read-data after prune" r check --read-data
    step "restore after prune"        restore_cmp latest "$W/src"
}

scenario_plain()     { full; }
scenario_tls()       { full; }
scenario_versioned() { full; }
scenario_lock()      { full; }
scenario_crash() {
    rm -rf "$W/src"; make_dataset "$W/src" 1 160
    step "init"                       r init
    crash_during $((40 << 20)) backup "$W/src"
    step "unlock stale locks"         r unlock
    step "backup after restart"       backup "$W/src"
    step "check --read-data"          r check --read-data
    step "restore = tree"             restore_cmp latest "$W/src"
}

compat_main plain tls versioned lock crash
