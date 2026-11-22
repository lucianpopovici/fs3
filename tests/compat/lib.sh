# tests/compat/lib.sh — shared helpers for the backup-tool compatibility
# scripts. Sourced, not run. Each script defines scenario_<variant>() and
# calls compat_main with the variants it supports.
#
# Variants:
#   plain      HTTP, unversioned bucket
#   tls        native TLS (test CA), unversioned bucket
#   versioned  HTTP, versioning on
#   lock       HTTP, Object Lock bucket (versioning on, layout 2)
#   crash      HTTP; fs3 is killed with SIGKILL in the middle of a backup
#              and restarted, then the tool must recover, verify and restore
#
# Environment:
#   COMPAT_TOOLS     extra PATH entry for the tools (default /opt/compat-tools/bin)
#   COMPAT_VARIANTS  run only these variants (space separated)
#   COMPAT_KEEP=1    keep the scratch directory
#   FS3_TEST_STRICT=1  a missing tool fails instead of skipping

set -eu

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export PATH="${COMPAT_TOOLS:-/opt/compat-tools/bin}:$PATH"
TOOL_NAME=${TOOL_NAME:-$(basename "$0" .sh)}
W=${COMPAT_DIR:-/tmp/fs3-compat-$TOOL_NAME-$$}
mkdir -p "$W"
AK=AKIACOMPATTEST0001
SK=compatSecretKey0123456789012345678901
REGION=us-east-1
BUCKET=backup
FS3_PID=""
PORT=""; TPORT=""; MPORT=""
DATA=""; CA="$W/ca.pem"
RESULTS=()

log() { printf '%s\n' "$*" >&2; }

compat_cleanup() {
    fs3_stop
    [ "${COMPAT_KEEP:-0}" = 1 ] && { log "kept $W"; return; }
    rm -rf "$W"
}
trap compat_cleanup EXIT

need() {
    for t in "$@"; do
        if ! command -v "$t" >/dev/null 2>&1; then
            if [ "${FS3_TEST_STRICT:-0}" = 1 ]; then log "FAIL: $t not installed"; exit 1; fi
            echo "RESULT $TOOL_NAME all SKIP ($t not installed; tests/compat/install-tools.sh)"
            exit 0
        fi
    done
}

# ---- fs3 -----------------------------------------------------------------

compat_build() {
    (cd "$ROOT" && make fs3-tls >/dev/null 2>&1) || { log "fs3-tls build failed"; exit 1; }
    [ -f "$CA" ] && return 0
    printf '[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' > "$W/ca.cnf"
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=fs3 compat CA" \
        -config "$W/ca.cnf" -keyout "$W/ca.key" -out "$CA" >/dev/null 2>&1
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=fs3" \
        -keyout "$W/srv.key" -out "$W/srv.csr" >/dev/null 2>&1
    printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > "$W/srv.ext"
    openssl x509 -req -in "$W/srv.csr" -CA "$CA" -CAkey "$W/ca.key" -CAcreateserial \
        -days 1 -extfile "$W/srv.ext" -out "$W/srv.crt" >/dev/null 2>&1
    chmod 600 "$W/srv.key"
}

# fs3_start <data-dir>: (re)start on the same ports.
fs3_start() {
    DATA=$1
    if [ -z "$PORT" ]; then
        PORT=$(( 26000 + RANDOM % 2000 )); TPORT=$((PORT + 1)); MPORT=$((PORT + 2))
    fi
    mkdir -p "$DATA"
    "$ROOT/fs3-tls" -p "$PORT" -d "$DATA" --auth "$AK:$SK" --require-auth \
        --tls-port "$TPORT" --tls-cert "$W/srv.crt" --tls-key "$W/srv.key" \
        --metrics-port "$MPORT" --scrub-interval-days 0 >>"$W/fs3.log" 2>&1 &
    FS3_PID=$!
    for _ in $(seq 100); do
        curl -s -o /dev/null "http://127.0.0.1:$PORT/health" && return 0
        sleep 0.1
    done
    log "fs3 did not start"; tail -20 "$W/fs3.log" >&2; exit 1
}

fs3_stop() {
    [ -n "$FS3_PID" ] || return 0
    kill "$FS3_PID" 2>/dev/null || true
    wait "$FS3_PID" 2>/dev/null || true
    FS3_PID=""
}

fs3_kill9() {
    kill -9 "$FS3_PID" 2>/dev/null || true
    wait "$FS3_PID" 2>/dev/null || true
    FS3_PID=""
}

# fs3 died on its own (crash, SIGSYS)? Fails the scenario if so.
fs3_alive() { [ -n "$FS3_PID" ] && kill -0 "$FS3_PID" 2>/dev/null; }

# Endpoint for the current variant.
endpoint() { if [ "$VARIANT" = tls ]; then echo "https://127.0.0.1:$TPORT"; else echo "http://127.0.0.1:$PORT"; fi; }
host_port() { if [ "$VARIANT" = tls ]; then echo "127.0.0.1:$TPORT"; else echo "127.0.0.1:$PORT"; fi; }

# AWS CLI v2 against the plain listener (setup and inspection only).
awsx() {
    AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_DEFAULT_REGION=$REGION \
    AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
        "${AWS2:-aws2}" --endpoint-url "http://127.0.0.1:$PORT" "$@"
}

make_bucket() {
    case "$VARIANT" in
        lock) awsx s3api create-bucket --bucket "$BUCKET" --object-lock-enabled-for-bucket >/dev/null ;;
        *)    awsx s3api create-bucket --bucket "$BUCKET" >/dev/null ;;
    esac
    if [ "$VARIANT" = versioned ]; then
        awsx s3api put-bucket-versioning --bucket "$BUCKET" \
            --versioning-configuration Status=Enabled >/dev/null
    fi
}

# Object and version counts in the bucket (for the report).
bucket_stats() {
    local objs vers
    objs=$(awsx s3api list-objects-v2 --bucket "$BUCKET" --query 'length(Contents)' --output text 2>/dev/null || echo "?")
    vers=$(awsx s3api list-object-versions --bucket "$BUCKET" --query 'length(Versions)' --output text 2>/dev/null || echo "?")
    echo "objects=$objs versions=$vers"
}

# ---- data ----------------------------------------------------------------

# make_dataset <dir> <generation> [big-MiB]
#   generation 1: the initial tree; 2: some files changed, added, removed.
make_dataset() {
    python3 - "$1" "$2" "${3:-24}" <<'PY'
import os, random, sys
root, gen, big = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
rnd = random.Random(1234)
def w(p, data):
    p = os.path.join(root, p); os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "wb") as f: f.write(data)
if gen == 1:
    for i in range(150):
        w(f"small/{i % 7}/f{i:03d}.txt", (f"line {i}\n" * rnd.randint(1, 900)).encode())
    for i in range(12):
        w(f"medium/m{i:02d}.bin", rnd.randbytes(rnd.randint(100_000, 1_200_000)))
    w("big/large.bin", rnd.randbytes(big << 20))
    w("names/with space.txt", b"space\n")
    w("names/ünïcødé-é.txt", "unicode\n".encode())
    w("names/plus+and&amp=.txt", b"specials\n")
    w("empty/zero.txt", b"")
    w("deep/a/b/c/d/e/f/g/h/leaf.txt", b"deep\n")
    os.utime(os.path.join(root, "names/with space.txt"), (1600000000, 1600000000))
else:
    r2 = random.Random(99)
    for i in range(0, 150, 10):
        w(f"small/{i % 7}/f{i:03d}.txt", f"changed {i}\n".encode() * 50)
    for i in range(5):
        w(f"added/n{i}.bin", r2.randbytes(300_000))
    for i in (1, 3):
        os.remove(os.path.join(root, f"medium/m{i:02d}.bin"))
PY
}

# same_tree <expected> <actual>: byte-for-byte, names included.
same_tree() {
    if diff -r "$1" "$2" >"$W/diff.out" 2>&1; then return 0; fi
    log "tree differs:"; head -20 "$W/diff.out" >&2
    return 1
}

# ---- results -------------------------------------------------------------

STEP_FAIL=0
# step <description> <command...>: runs, logs output to the variant log.
step() {
    local d=$1; shift
    local t0=$SECONDS
    echo "### $d" >>"$VLOG"
    if "$@" >>"$VLOG" 2>&1; then
        printf '  ok   %s (%ss)\n' "$d" "$((SECONDS - t0))" >&2
    else
        printf '  FAIL %s (exit %s; log: %s)\n' "$d" "$?" "$VLOG" >&2
        tail -15 "$VLOG" | sed 's/^/       /' >&2
        STEP_FAIL=1
    fi
}

is_eq() { [ "$1" = "$2" ] || { echo "want '$2', got '$1'"; return 1; }; }

# expect_fail <description> <command...>: the command must fail.
expect_fail() {
    local d=$1; shift
    if "$@" >>"$VLOG" 2>&1; then
        printf '  FAIL %s (succeeded but should not)\n' "$d" >&2; STEP_FAIL=1
    else
        printf '  ok   %s\n' "$d" >&2
    fi
}

compat_main() {
    compat_build
    local all="$*"
    local want=${COMPAT_VARIANTS:-$all}
    for VARIANT in $all; do
        case " $want " in *" $VARIANT "*) ;; *) continue ;; esac
        VLOG="$W/$TOOL_NAME-$VARIANT.log"
        : > "$VLOG"
        STEP_FAIL=0
        log "== $TOOL_NAME / $VARIANT"
        PORT=""
        fs3_start "$W/data-$VARIANT"
        make_bucket
        local t0=$SECONDS
        "scenario_$VARIANT" || STEP_FAIL=1
        fs3_alive || { log "  FAIL fs3 is not running at the end"; STEP_FAIL=1; }
        local stats; stats=$(bucket_stats)
        fs3_stop
        local res=PASS; [ "$STEP_FAIL" = 0 ] || res=FAIL
        RESULTS+=("RESULT $TOOL_NAME $VARIANT $res ($((SECONDS - t0))s, $stats)")
        if [ "$res" = FAIL ]; then
            mkdir -p "$ROOT/tests/compat/logs"
            cp "$VLOG" "$ROOT/tests/compat/logs/" 2>/dev/null || true
            cp "$W/fs3.log" "$ROOT/tests/compat/logs/$TOOL_NAME-$VARIANT.fs3.log" 2>/dev/null || true
        fi
    done
    printf '%s\n' "${RESULTS[@]}"
    for r in "${RESULTS[@]}"; do case "$r" in *" FAIL "*) return 1 ;; esac; done
    return 0
}

# Run a backup in the background, SIGKILL fs3 once it is uploading, then
# restart fs3. $1: bytes of bucket data to wait for before the kill.
crash_during() {
    local min=$1; shift
    "$@" >>"$VLOG" 2>&1 &
    local tp=$!
    for _ in $(seq 300); do
        local used
        used=$(du -sb "$DATA" 2>/dev/null | cut -f1)
        [ "${used:-0}" -ge "$min" ] && break
        kill -0 "$tp" 2>/dev/null || break
        sleep 0.05
    done
    if kill -0 "$tp" 2>/dev/null; then
        log "  ..   SIGKILL fs3 mid-backup ($(du -sh "$DATA" | cut -f1) stored)"
        fs3_kill9
        sleep 1
        fs3_start "$DATA"
    else
        log "  WARN backup finished before the kill; crash variant not exercised"
    fi
    wait "$tp" 2>/dev/null || log "  ..   interrupted backup exited non-zero (expected)"
}
