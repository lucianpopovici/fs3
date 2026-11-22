#!/usr/bin/env bash
#
# tests/compat/run.sh — run every backup-tool compatibility script and
# print a summary (also written to tests/compat/last-run.txt).
#   make compat                        all tools, all variants
#   COMPAT_ONLY="restic rclone" make compat
#   COMPAT_VARIANTS="plain tls" make compat
# Tools come from COMPAT_TOOLS (default /opt/compat-tools/bin); install
# the pinned versions with tests/compat/install-tools.sh. Not part of
# `make test`: slow, and needs the external tools.
#
set -u
DIR=$(cd "$(dirname "$0")" && pwd)
export PATH="${COMPAT_TOOLS:-/opt/compat-tools/bin}:$PATH"
OUT="$DIR/last-run.txt"
TOOLS=${COMPAT_ONLY:-"restic rclone kopia duplicati awscli"}
rc=0
{
    echo "fs3 compatibility run: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "fs3 commit: $(git -C "$DIR/../.." rev-parse --short HEAD 2>/dev/null)$(git -C "$DIR/../.." diff --quiet 2>/dev/null || echo ' (modified)')"
    echo "restic:    $(restic version 2>/dev/null | cut -d' ' -f2 || echo missing)"
    echo "rclone:    $(rclone version 2>/dev/null | head -1 | cut -d' ' -f2 || echo missing)"
    echo "kopia:     $(kopia --version 2>/dev/null | cut -d' ' -f1 || echo missing)"
    echo "duplicati: $(basename "$(dirname "$(readlink -f "$(command -v duplicati-cli)" 2>/dev/null)")" 2>/dev/null | sed 's/^duplicati-//; s/-linux.*//')"
    echo "aws cli:   $(aws2 --version 2>/dev/null | cut -d' ' -f1 | cut -d/ -f2 || echo missing)"
    echo
} > "$OUT"
for t in $TOOLS; do
    echo "######## $t"
    if ! "$DIR/$t.sh" 2> >(sed "s/^/[$t] /" >&2) | tee -a "$OUT.tmp"; then rc=1; fi
done
grep '^RESULT' "$OUT.tmp" >> "$OUT"; rm -f "$OUT.tmp"
echo; cat "$OUT"
exit $rc
