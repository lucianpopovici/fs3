#!/usr/bin/env bash
# tests/compat/rclone.sh — rclone against fs3: sync with a small multipart
# cutoff, check --download, modification times kept (x-amz-meta-mtime),
# server-side copy, a second sync with changes and deletions, restore;
# plus TLS, versioning, Object Lock and a crash mid-sync.
TOOL_NAME=rclone
. "$(dirname "$0")/lib.sh"
need rclone aws2

rc() {
    local extra=()
    [ "$VARIANT" = tls ] && extra=(--ca-cert "$CA")
    RCLONE_CONFIG=/dev/null \
    RCLONE_CONFIG_FS3_TYPE=s3 RCLONE_CONFIG_FS3_PROVIDER=Other \
    RCLONE_CONFIG_FS3_ACCESS_KEY_ID=$AK RCLONE_CONFIG_FS3_SECRET_ACCESS_KEY=$SK \
    RCLONE_CONFIG_FS3_ENDPOINT="$(endpoint)" RCLONE_CONFIG_FS3_REGION=$REGION \
    RCLONE_CONFIG_FS3_FORCE_PATH_STYLE=true \
        rclone --s3-upload-cutoff 5M --s3-chunk-size 5M --retries 3 --low-level-retries 5 \
               "${extra[@]}" "$@"
}

mtime_kept() {   # the file with a fixed mtime comes back with it
    local f="names/with space.txt"
    is_eq "$(stat -c %Y "$W/restore/$f")" "$(stat -c %Y "$W/src/$f")"
}
md5_eq() { is_eq "$(rc md5sum "$1" | cut -d' ' -f1)" "$(md5sum < "$2" | cut -d' ' -f1)"; }
restore_cmp() { rm -rf "$W/restore"; rc copy fs3:$BUCKET/sync "$W/restore" && same_tree "$W/src" "$W/restore"; }

full() {
    rm -rf "$W/src"; make_dataset "$W/src" 1 "${1:-24}"
    step "sync 1 (multipart above 5M)"      rc sync "$W/src" fs3:$BUCKET/sync
    step "check --download"                 rc check --download "$W/src" fs3:$BUCKET/sync
    step "restore = tree 1"                 restore_cmp
    step "modification time kept"           mtime_kept
    step "server-side copy"                 rc copyto fs3:$BUCKET/sync/big/large.bin fs3:$BUCKET/copy/large.bin
    step "copy has the same content"        md5_eq fs3:$BUCKET/copy/large.bin "$W/src/big/large.bin"
    make_dataset "$W/src" 2
    step "sync 2 (changes, deletions)"      rc sync "$W/src" fs3:$BUCKET/sync
    step "check --download after sync 2"    rc check --download "$W/src" fs3:$BUCKET/sync
    step "restore = tree 2"                 restore_cmp
    step "deleted files are gone"           is_eq "$(rc lsf fs3:$BUCKET/sync/medium | grep -c 'm01.bin' || true)" 0
}

has_old_version() { rc lsf --s3-versions fs3:$BUCKET/sync/medium | grep -q 'm01-v'; }

scenario_plain()     { full; }
scenario_tls()       { full; }
scenario_versioned() {
    full
    step "old versions listed (--s3-versions)" has_old_version
}
scenario_lock()      { full; }
scenario_crash() {
    rm -rf "$W/src"; make_dataset "$W/src" 1 160
    crash_during $((40 << 20)) rc sync "$W/src" fs3:$BUCKET/sync
    step "sync after restart"               rc sync "$W/src" fs3:$BUCKET/sync
    step "check --download"                 rc check --download "$W/src" fs3:$BUCKET/sync
    step "restore = tree"                   restore_cmp
}

compat_main plain tls versioned lock crash
