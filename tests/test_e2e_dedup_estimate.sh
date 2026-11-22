#!/usr/bin/env bash
#
# tests/test_e2e_dedup_estimate.sh — fs3-dedup-estimate against a real
# data root written by fs3: whole-object duplicates (owner-scoped), block
# duplicates at several sizes and both scopes, versions, delete markers,
# malformed files, --bucket, --no-versions, --sample, JSON output.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PORT=${FS3_TEST_PORT:-$(( 28000 + RANDOM % 200 ))}
T=/tmp/fs3-dedupest-e2e-$$
DATA=$T.data
LOG=$T.log
URL="http://127.0.0.1:$PORT"
EST="$ROOT/fs3-dedup-estimate"

cleanup() {
    [ -n "${SP:-}" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null; [ $? -ne 159 ] || echo "FAIL: server died with SIGSYS (seccomp blocked a syscall; see --seccomp=log)" >&2; } || true
    [ -n "${KEEP:-}" ] || rm -rf "$DATA" "$T".*
}
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 fs3-dedup-estimate >/dev/null 2>&1)

${FS3_WRAP:-} "$ROOT/fs3" -p "$PORT" -d "$DATA" --mpu-min-part-size 0 \
    --scrub-interval-days 0 >>"$LOG" 2>&1 &
SP=$!
for _ in $(seq 50); do curl -s -o /dev/null "$URL/" && break; sleep 0.1; done
kill -0 "$SP" 2>/dev/null || { echo "server did not start" >&2; cat "$LOG" >&2; exit 1; }

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}
put()  { curl -sS -o /dev/null -w '%{http_code}' -X PUT --data-binary "@$2" "$URL/$1"; }
js()   { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

KiB=1024; MiB=$((1024 * 1024))
head -c $MiB /dev/urandom > "$T.A"                       # 1 MiB random
cp "$T.A" "$T.B"                                         # B = A with the last 64 KiB replaced
head -c $((64 * KiB)) /dev/urandom | dd of="$T.B" bs=1 seek=$((MiB - 64 * KiB)) conv=notrunc 2>/dev/null
head -c $((512 * KiB)) /dev/urandom > "$T.C"             # 512 KiB unique

check_eq "create est-a" "$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "$URL/est-a")" 200
check_eq "create est-b" "$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "$URL/est-b")" 200
check_eq "put a/one"   "$(put est-a/one   "$T.A")" 200
check_eq "put a/two"   "$(put est-a/two   "$T.A")" 200     # whole dup, same owner scope
check_eq "put a/three" "$(put est-a/three "$T.B")" 200     # block dups of one
check_eq "put a/four"  "$(put est-a/four  "$T.C")" 200     # unique
check_eq "put b/five"  "$(put est-b/five  "$T.A")" 200     # same bytes, other (ownerless) scope

# Logical 4.5 MiB. Owner scope: whole dup = 1 MiB (two); block dups of
# three vs one = 960 KiB at 4k/64k, 896 KiB at 128k (the last 128 KiB
# block contains the changed 64 KiB). Global adds five (1 MiB).
OUT=$("$EST" -q --json "$DATA")
check_eq "objects"              "$(echo "$OUT" | js 'd["objects"]')" 5
check_eq "logical bytes"        "$(echo "$OUT" | js 'd["logical_bytes"]')" $((4 * MiB + 512 * KiB))
check_eq "whole-object dup"     "$(echo "$OUT" | js 'd["whole_object_dup_bytes"]')" $MiB
check_eq "4k owner"             "$(echo "$OUT" | js 'd["block_sizes"][0]["dup_bytes_owner"]')" $((960 * KiB))
check_eq "64k owner"            "$(echo "$OUT" | js 'd["block_sizes"][1]["dup_bytes_owner"]')" $((960 * KiB))
check_eq "128k owner"           "$(echo "$OUT" | js 'd["block_sizes"][2]["dup_bytes_owner"]')" $((896 * KiB))
check_eq "64k global"           "$(echo "$OUT" | js 'd["block_sizes"][1]["dup_bytes_global"]')" $((960 * KiB + MiB))
check_eq "per-bucket a 128k"    "$(echo "$OUT" | js '[b for b in d["buckets"] if b["name"]=="est-a"][0]["dup_bytes_owner"]["131072"]')" $((896 * KiB))
check_eq "per-bucket b owner"   "$(echo "$OUT" | js '[b for b in d["buckets"] if b["name"]=="est-b"][0]["dup_bytes_owner"]["131072"]')" 0
check_eq "per-bucket b global"  "$(echo "$OUT" | js '[b for b in d["buckets"] if b["name"]=="est-b"][0]["dup_bytes_global"]["131072"]')" $MiB
check_eq "sample rate"          "$(echo "$OUT" | js 'd["sample_rate"]')" 1

# --bucket and text output.
OUT=$("$EST" -q --json --bucket est-b "$DATA")
check_eq "--bucket objects"     "$(echo "$OUT" | js 'd["objects"]')" 1
TXT=$("$EST" -q "$DATA")
case "$TXT" in *"verdict:"*) ok=yes ;; *) ok=no ;; esac
check_eq "text verdict line" "$ok" yes

# Versioning: overwrite four with A (whole dup in est-a), delete three
# (delete marker; three becomes a noncurrent version).
check_eq "enable versioning" "$(curl -sS -o /dev/null -w '%{http_code}' -X PUT "$URL/est-a?versioning" \
    --data '<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>')" 200
check_eq "overwrite four"  "$(put est-a/four "$T.A")" 200
check_eq "delete three"    "$(curl -sS -o /dev/null -w '%{http_code}' -X DELETE "$URL/est-a/three")" 204
OUT=$("$EST" -q --json "$DATA")
check_eq "versions: objects"      "$(echo "$OUT" | js 'd["objects"]')" 6
check_eq "versions: markers"      "$(echo "$OUT" | js 'd["delete_markers"]')" 1
check_eq "versions: whole dup"    "$(echo "$OUT" | js 'd["whole_object_dup_bytes"]')" $((2 * MiB))
check_eq "versions: 128k owner"   "$(echo "$OUT" | js 'd["block_sizes"][2]["dup_bytes_owner"]')" $((896 * KiB))
OUT=$("$EST" -q --json --no-versions "$DATA")
check_eq "--no-versions objects"  "$(echo "$OUT" | js 'd["objects"]')" 4

# --sample: forced 1/4 sampling is reported; whole-object figures stay exact.
OUT=$("$EST" -q --json --sample 4 "$DATA")
check_eq "--sample rate"          "$(echo "$OUT" | js 'd["sample_rate"]')" 4
check_eq "--sample whole dup"     "$(echo "$OUT" | js 'd["whole_object_dup_bytes"]')" $((2 * MiB))

# A malformed file is counted, not fatal; a stray temp file is ignored.
HEX=$(python3 -c "import hashlib; print(hashlib.sha256(b'est-b\0five').hexdigest())")
F="$DATA/data/est-b/${HEX:0:2}/${HEX:2:2}/$HEX"
check_eq "object file found" "$( [ -f "$F" ] && echo yes || echo no )" yes
printf 'x' >> "$F"
: > "$DATA/data/est-b/${HEX:0:2}/${HEX:2:2}/$HEX.tmp.123"
OUT=$("$EST" -q --json "$DATA")
check_eq "malformed counted"      "$(echo "$OUT" | js 'd["unreadable"]')" 1
check_eq "malformed: objects"     "$(echo "$OUT" | js 'd["objects"]')" 5

# Bad arguments.
"$EST" -q --block-sizes 3000 "$DATA" >/dev/null 2>&1 && rc=0 || rc=$?
check_eq "bad block size → 2"     "$rc" 2
"$EST" -q /nonexistent >/dev/null 2>&1 && rc=0 || rc=$?
check_eq "not a data root → 2"    "$rc" 2

echo
echo "===== dedup-estimate e2e: $PASS passed, $FAIL failed ====="
[ "$FAIL" -eq 0 ]
