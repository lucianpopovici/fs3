#!/usr/bin/env bash
# tests/compat/awscli.sh — AWS CLI v2 (default flexible checksums, i.e.
# aws-chunked uploads with a CRC trailer) against fs3: s3 sync up and down
# with --delete, multipart, explicit checksums, presigned URLs, versions,
# Object Lock retention and legal hold; plus TLS and a crash mid-upload.
TOOL_NAME=awscli
. "$(dirname "$0")/lib.sh"
need aws2

a() {
    local extra=()
    [ "$VARIANT" = tls ] && extra=(--ca-bundle "$CA")
    AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_DEFAULT_REGION=$REGION \
    AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
        aws2 --endpoint-url "$(endpoint)" "${extra[@]}" "$@"
}
down_cmp() { rm -rf "$W/restore"; a s3 sync "s3://$BUCKET/sync" "$W/restore" --only-show-errors && same_tree "$W/src" "$W/restore"; }
md5_of_object() { rm -f "$W/obj"; a s3 cp "s3://$BUCKET/$1" "$W/obj" --only-show-errors && md5sum < "$W/obj" | cut -d' ' -f1; }
presigned_get() {
    local u cacert=()
    u=$(a s3 presign "s3://$BUCKET/sync/names/with space.txt" --expires-in 300)
    [ "$VARIANT" = tls ] && cacert=(--cacert "$CA")
    is_eq "$(curl -sf "${cacert[@]}" "$u")" "space"
}
checksum_roundtrip() {
    local alg=$1
    a s3api put-object --bucket "$BUCKET" --key "ck/$alg" --body "$W/src/medium/m00.bin" \
        --checksum-algorithm "$alg" >/dev/null &&
    a s3api head-object --bucket "$BUCKET" --key "ck/$alg" --checksum-mode ENABLED |
        grep -q "\"Checksum$alg\""
}

legal_hold_on() { a s3api get-object-legal-hold --bucket "$BUCKET" --key sync/empty/zero.txt | grep -q '"ON"'; }
# The interrupted upload may or may not have left a multipart upload
# behind (the CLI aborts when it can); whatever is there must list and abort.
abort_leftovers() {
    a s3api list-multipart-uploads --bucket "$BUCKET" --query 'Uploads[].[Key,UploadId]' --output text |
    while read -r k u; do
        [ -n "$k" ] && [ "$k" != None ] || continue
        a s3api abort-multipart-upload --bucket "$BUCKET" --key "$k" --upload-id "$u" || return 1
    done
    is_eq "$(a s3api list-multipart-uploads --bucket "$BUCKET" --query 'length(Uploads || `[]`)' --output text)" 0
}

full() {
    rm -rf "$W/src"; make_dataset "$W/src" 1 "${1:-24}"
    step "s3 sync up (multipart above 8 MiB)"   a s3 sync "$W/src" "s3://$BUCKET/sync" --only-show-errors
    step "s3 sync down = tree 1"                down_cmp
    step "big object content"                   is_eq "$(md5_of_object sync/big/large.bin)" "$(md5sum < "$W/src/big/large.bin" | cut -d' ' -f1)"
    make_dataset "$W/src" 2
    step "s3 sync --delete"                     a s3 sync "$W/src" "s3://$BUCKET/sync" --delete --only-show-errors
    step "s3 sync down = tree 2"                down_cmp
    for alg in CRC32 CRC32C SHA1 SHA256 CRC64NVME; do
        step "put-object --checksum-algorithm $alg" checksum_roundtrip "$alg"
    done
    step "presigned GET"                        presigned_get
}

scenario_plain() { full; }
scenario_tls()   { full; }
scenario_versioned() {
    full
    local vid
    vid=$(a s3api list-object-versions --bucket "$BUCKET" --prefix sync/medium/m01.bin \
          --query 'Versions[0].VersionId' --output text)
    step "deleted file has a noncurrent version" test -n "$vid" -a "$vid" != None
    step "get the old version"                  a s3api get-object --bucket "$BUCKET" --key sync/medium/m01.bin --version-id "$vid" "$W/old.bin"
}
scenario_lock() {
    full
    local until vid
    until=$(date -u -d '+1 day' +%Y-%m-%dT%H:%M:%SZ)
    step "put-object-retention COMPLIANCE"      a s3api put-object-retention --bucket "$BUCKET" --key sync/names/with\ space.txt \
                                                  --retention "Mode=COMPLIANCE,RetainUntilDate=$until"
    vid=$(a s3api head-object --bucket "$BUCKET" --key "sync/names/with space.txt" --query VersionId --output text)
    expect_fail "locked version cannot be deleted" a s3api delete-object --bucket "$BUCKET" --key "sync/names/with space.txt" --version-id "$vid"
    step "legal hold on"                        a s3api put-object-legal-hold --bucket "$BUCKET" --key sync/empty/zero.txt --legal-hold Status=ON
    step "legal hold reads back"                legal_hold_on
}
scenario_crash() {
    rm -rf "$W/src"; make_dataset "$W/src" 1 160
    crash_during $((40 << 20)) a s3 cp "$W/src/big/large.bin" "s3://$BUCKET/crash/large.bin" --only-show-errors
    step "upload again after restart"           a s3 cp "$W/src/big/large.bin" "s3://$BUCKET/crash/large.bin" --only-show-errors
    step "content intact"                       is_eq "$(md5_of_object crash/large.bin)" "$(md5sum < "$W/src/big/large.bin" | cut -d' ' -f1)"
    step "leftover multipart uploads listable and abortable" abort_leftovers
}

compat_main plain tls versioned lock crash
