#!/usr/bin/env bash
# tests/compat/kopia.sh — Kopia against fs3: repository create, two
# snapshots, snapshot verify (all files read), restore (latest and first),
# delete a snapshot + full maintenance, verify again; plus TLS,
# versioning, Object Lock (Kopia sets COMPLIANCE retention on its blobs)
# and a crash mid-snapshot.
TOOL_NAME=kopia
. "$(dirname "$0")/lib.sh"
need kopia aws2

export KOPIA_PASSWORD=compat-kopia-password KOPIA_CHECK_FOR_UPDATES=false

k() {
    kopia --config-file "$W/kopia-$VARIANT.config" --log-dir "$W/kopia-logs" \
          --no-progress "$@"
}
create() {
    local tls=(--disable-tls) ep="127.0.0.1:$PORT"
    [ "$VARIANT" = tls ] && { tls=(--root-ca-pem-path "$CA"); ep="127.0.0.1:$TPORT"; }
    k repository create s3 --bucket "$BUCKET" --endpoint "$ep" "${tls[@]}" \
        --access-key "$AK" --secret-access-key "$SK" --region "$REGION" --prefix repo/ \
        --cache-directory "$W/kopia-cache-$VARIANT" "$@"
}
snap_ids() { k snapshot list "$W/src" --json | python3 -c 'import sys,json; print(" ".join(m["id"] for m in sorted(json.load(sys.stdin), key=lambda m: m["startTime"])))'; }
restore_cmp() { rm -rf "$W/restore"; k snapshot restore "$1" "$W/restore" && same_tree "$2" "$W/restore"; }
verify() { k snapshot verify --verify-files-percent=100 --file-parallelism=4; }

full() {
    rm -rf "$W/src" "$W/gen1"; make_dataset "$W/src" 1 "${1:-24}"; cp -a "$W/src" "$W/gen1"
    step "repository create"            create "${CREATE_EXTRA[@]}"
    step "snapshot 1"                   k snapshot create "$W/src"
    make_dataset "$W/src" 2
    step "snapshot 2"                   k snapshot create "$W/src"
    local ids; ids=$(snap_ids)
    step "two snapshots"                is_eq "$(echo $ids | wc -w)" 2
    step "snapshot verify (100% files)" verify
    step "restore latest = tree 2"      restore_cmp "${ids##* }" "$W/src"
    step "restore first = tree 1"       restore_cmp "${ids%% *}" "$W/gen1"
    step "delete first snapshot"        k snapshot delete "${ids%% *}" --delete
    step "full maintenance"             k maintenance run --full --safety=none
    step "verify after maintenance"     verify
    step "restore after maintenance"    restore_cmp "${ids##* }" "$W/src"
}

has_compliance() {
    awsx s3api get-object-retention --bucket "$BUCKET" --key "$1" --version-id "$2" | grep -q COMPLIANCE
}

CREATE_EXTRA=()
scenario_plain()     { full; }
scenario_tls()       { full; }
scenario_versioned() { full; }
scenario_lock() {
    CREATE_EXTRA=(--retention-mode COMPLIANCE --retention-period 24h)
    full
    CREATE_EXTRA=()
    local key vid
    key=$(awsx s3api list-objects-v2 --bucket "$BUCKET" --prefix repo/p --query 'Contents[0].Key' --output text)
    vid=$(awsx s3api list-object-versions --bucket "$BUCKET" --prefix "$key" --query 'Versions[0].VersionId' --output text)
    step "blob carries COMPLIANCE retention" has_compliance "$key" "$vid"
    expect_fail "locked blob version cannot be deleted" awsx s3api delete-object --bucket "$BUCKET" --key "$key" --version-id "$vid"
}
scenario_crash() {
    rm -rf "$W/src"; make_dataset "$W/src" 1 160
    step "repository create"            create
    crash_during $((40 << 20)) k snapshot create "$W/src"
    step "snapshot after restart"       k snapshot create "$W/src"
    step "snapshot verify (100% files)" verify
    local ids; ids=$(snap_ids)
    step "restore latest = tree"        restore_cmp "${ids##* }" "$W/src"
}

compat_main plain tls versioned lock crash
