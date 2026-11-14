#!/usr/bin/env bash
#
# tests/tools/seccomp_profile.sh — evidence for src/sandbox.c's allowlist
# (round 2, item 5). Runs the e2e suites with every fs3 under
# `strace -f -c` (seccomp off) and prints the union of syscalls used,
# then diffs it against the table compiled into the binary
# (`fs3 --seccomp-list`). Run on the target build too (static Synology
# binary): glibc and linking change the set (open vs openat, ...).
#
#   make seccomp-profile          # all e2e suites
#   tests/tools/seccomp_profile.sh tests/test_e2e.sh ...
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${SECCOMP_PROFILE_DIR:-/tmp/fs3-seccomp-profile-$$}
mkdir -p "$OUT"
command -v strace >/dev/null || { echo "strace is required" >&2; exit 2; }
SUITES=("$@")
[ ${#SUITES[@]} -gt 0 ] || SUITES=($(ls "$ROOT"/tests/test_e2e*.sh))
WRAP="$OUT/wrap.sh"
# strace detaches (leaving fs3 running) when it is the one signalled, so
# the wrapper stays the test's "server pid" and forwards signals to fs3.
cat > "$WRAP" <<W
#!/bin/bash
setpriv --pdeathsig KILL strace --kill-on-exit -f -qq -c -U name -o "$OUT/trace.\$\$.\$(date +%s%N)" "\$@" --seccomp=off &
st=\$!
fwd() { pkill -\$1 -P \$st 2>/dev/null; }
trap 'fwd TERM' TERM; trap 'fwd INT' INT; trap 'fwd HUP' HUP; trap 'fwd KILL' USR2
while kill -0 \$st 2>/dev/null; do wait \$st; done
wait \$st
W
chmod +x "$WRAP"
for t in "${SUITES[@]}"; do
    printf '%-40s ' "$(basename "$t")"
    FS3_WRAP="$WRAP" "$t" >/dev/null 2>&1 && echo ok || echo "FAILED (profile still collected)"
done
cat "$OUT"/trace.* 2>/dev/null | awk 'NF == 1 && $1 ~ /^[a-z_0-9]+$/ && $1 != "syscall" && $1 != "total" { print $1 }' \
    | sort -u > "$OUT/used.txt"
echo "== syscalls used ($(wc -l < "$OUT/used.txt")): $OUT/used.txt"
tr '\n' ' ' < "$OUT/used.txt"; echo
if "$ROOT/fs3" --seccomp-list >"$OUT/allowed.txt" 2>/dev/null; then
    missing=$(comm -23 "$OUT/used.txt" <(sort -u "$OUT/allowed.txt"))
    echo "== used but not allowed by src/sandbox.c:"
    echo "${missing:-(none)}"
    [ -z "$missing" ]
fi
