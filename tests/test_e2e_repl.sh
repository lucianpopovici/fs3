#!/usr/bin/env bash
#
# tests/test_e2e_repl.sh — bucket replication between two fs3-tls
# instances (source → replica): the admin API and its validation, PUT /
# overwrite / metadata / multipart / copy / delete arriving, coalescing
# while the replica is down and draining after, backfill, deletes:false,
# a permanent 4xx recorded and skipped, a wrong secret held and retried,
# the recovery scan after kill -9 with a lost journal, SSE-C skipped,
# replication over https with --repl-ca-file, metrics, and the secret
# never appearing in responses, logs or the audit log.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BASE=${FS3_TEST_PORT:-$(( 25700 + RANDOM % 250 ))}
SPORT=$BASE; STPORT=$((BASE + 1)); SMPORT=$((BASE + 2))
RPORT=$((BASE + 3)); RTPORT=$((BASE + 4))
T=/tmp/fs3-repl-$$
SDATA=$T.sdata; RDATA=$T.rdata
SLOG=$T.slog; RLOG=$T.rlog; AUDIT=$T.audit
SSOCK=$T.ssock; RSOCK=$T.rsock
AK=AKIAREPLSOURCE01
SK=replSourceSecret0123456789012345678901
RAK=AKIAREPLREPLICA1
RSK=replicaSecretXyZ0123456789abcdefghijklmn

SP=""; RP=""
stop_src() { [ -n "$SP" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; }; SP=""; }
stop_rep() { [ -n "$RP" ] && { kill "$RP" 2>/dev/null; wait "$RP" 2>/dev/null || true; }; RP=""; }
cleanup() { stop_src; stop_rep; rm -rf "$T".*; }
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3-tls >/dev/null 2>&1) || { echo "fs3-tls build failed" >&2; exit 1; }
BIN="$ROOT/fs3-tls"

# CA + certificate for localhost/127.0.0.1 (both servers use it).
printf '[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' > "$T.cacnf"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=fs3 repl test CA" \
    -config "$T.cacnf" -keyout "$T.cakey" -out "$T.ca" >/dev/null 2>&1
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=fs3" \
    -keyout "$T.key" -out "$T.csr" >/dev/null 2>&1
printf 'subjectAltName=IP:127.0.0.1,DNS:localhost\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > "$T.ext"
openssl x509 -req -in "$T.csr" -CA "$T.ca" -CAkey "$T.cakey" -CAcreateserial \
    -days 1 -extfile "$T.ext" -out "$T.crt" >/dev/null 2>&1
chmod 600 "$T.key"

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}

wait_up() { for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$1/health" && return 0; sleep 0.1; done; return 1; }

start_rep() {
    ${FS3_WRAP:-} "$BIN" -p "$RPORT" -d "$RDATA" --auth "$RAK:$RSK" --require-auth \
        --tls-port "$RTPORT" --tls-cert "$T.crt" --tls-key "$T.key" --admin-socket "$RSOCK" \
        >>"$RLOG" 2>&1 &
    RP=$!
    wait_up "$RPORT" || { echo "replica did not start" >&2; cat "$RLOG" >&2; exit 1; }
}
start_src() {
    ${FS3_WRAP:-} "$BIN" -p "$SPORT" -d "$SDATA" --auth "$AK:$SK" --require-auth \
        --tls-port "$STPORT" --tls-cert "$T.crt" --tls-key "$T.key" \
        --admin-socket "$SSOCK" --metrics-port "$SMPORT" --audit-log "$AUDIT" \
        --repl-rate 0 --repl-part-size 5M --repl-timeout 5 --repl-ca-file "$T.ca" "$@" \
        >>"$SLOG" 2>&1 &
    SP=$!
    wait_up "$SPORT" || { echo "source did not start" >&2; cat "$SLOG" >&2; exit 1; }
}

sadm() { curl -sS --unix-socket "$SSOCK" "$@"; }
scode() { curl -sS -o /dev/null -w '%{http_code}' --unix-socket "$SSOCK" "$@"; }
radm() { curl -sS --unix-socket "$RSOCK" "$@"; }
jget() { python3 -c 'import sys,json; d=json.load(sys.stdin); print(eval("d"+sys.argv[1]))' "$1"; }

# s3 <url> <ak> <sk> <cmd> args...  (a small boto3 driver)
cat > "$T.s3.py" <<'PY'
import sys, os, hashlib, json
sys.modules["awscrt"] = None
import boto3, botocore
from boto3.s3.transfer import TransferConfig
url, ak, sk, cmd, *a = sys.argv[1:]
kw = {}
if url.startswith("https"): kw["verify"] = os.environ["FS3_CA"]
s3 = boto3.client("s3", endpoint_url=url, aws_access_key_id=ak, aws_secret_access_key=sk,
                  region_name="us-east-1", **kw)
try:
    if cmd == "mb": s3.create_bucket(Bucket=a[0]); print("ok")
    elif cmd == "put":
        extra = json.loads(a[3]) if len(a) > 3 else {}
        s3.put_object(Bucket=a[0], Key=a[1], Body=a[2].encode(), **extra); print("ok")
    elif cmd == "putfile":
        s3.upload_file(a[2], a[0], a[1], Config=TransferConfig(multipart_threshold=5 << 20,
                       multipart_chunksize=5 << 20)); print("ok")
    elif cmd == "get":
        print(s3.get_object(Bucket=a[0], Key=a[1])["Body"].read().decode())
    elif cmd == "md5":
        print(hashlib.md5(s3.get_object(Bucket=a[0], Key=a[1])["Body"].read()).hexdigest())
    elif cmd == "head":
        h = s3.head_object(Bucket=a[0], Key=a[1])
        print(h["ContentType"], h["Metadata"].get("color", "-"), h.get("CacheControl", "-"))
    elif cmd == "exists":
        try: s3.head_object(Bucket=a[0], Key=a[1]); print("yes")
        except botocore.exceptions.ClientError: print("no")
    elif cmd == "copy":
        s3.copy_object(Bucket=a[0], Key=a[2], CopySource={"Bucket": a[0], "Key": a[1]}); print("ok")
    elif cmd == "rm": s3.delete_object(Bucket=a[0], Key=a[1]); print("ok")
    elif cmd == "burst":
        for i in range(int(a[2])): s3.put_object(Bucket=a[0], Key=a[1], Body=("v%d" % i).encode())
        print("ok")
    elif cmd == "ssec":
        k = b"K" * 32
        s3.put_object(Bucket=a[0], Key=a[1], Body=b"secret", SSECustomerAlgorithm="AES256",
                      SSECustomerKey=k); print("ok")
    elif cmd == "count":
        print(s3.list_objects_v2(Bucket=a[0]).get("KeyCount", 0))
except botocore.exceptions.ClientError as e:
    print(e.response["Error"]["Code"])
PY
export FS3_CA="$T.ca"
src() { python3 "$T.s3.py" "http://127.0.0.1:$SPORT" "$AK" "$SK" "$@"; }
srct() { python3 "$T.s3.py" "https://127.0.0.1:$STPORT" "$AK" "$SK" "$@"; }
rep() { python3 "$T.s3.py" "http://127.0.0.1:$RPORT" "$RAK" "$RSK" "$@"; }

status() { sadm "http://x/v1/buckets/src/replication/status"; }
# Wait until the queue is empty and no backfill/recovery is pending.
drain() {
    local t=${1:-30}
    for _ in $(seq $((t * 5))); do
        s=$(status)
        if [ "$(echo "$s" | jget "['queue']")" = 0 ] && [ "$(echo "$s" | jget "['backfill']['requested']")" = False ] \
           && [ "$(echo "$s" | jget "['recovery_pending']")" = False ]; then return 0; fi
        sleep 0.2
    done
    echo; echo "drain timed out: $(status)" >&2
    return 1
}

start_rep
start_src
check_eq "replica bucket" "$(rep mb rep)" ok
check_eq "source bucket" "$(src mb src)" ok
check_eq "pre-existing object" "$(src put src old1 before-rule)" ok

RULE='{"endpoint":"http://127.0.0.1:'$RPORT'","bucket":"rep","access_key":"'$RAK'","secret_key":"'$RSK'","allow_plain_http":true}'

# ---- validation ---------------------------------------------------------
v() { scode -X PUT --data "$1" "http://x/v1/buckets/src/replication"; }
check_eq "public plain-http host refused" "$(v '{"endpoint":"http://8.8.8.8","bucket":"rep","access_key":"a","secret_key":"b","allow_plain_http":true}')" 400
check_eq "plain http needs allow_plain_http" "$(v '{"endpoint":"http://127.0.0.1:1","bucket":"rep","access_key":"a","secret_key":"b"}')" 400
check_eq "endpoint with a path refused" "$(v '{"endpoint":"https://s3.example.com/x","bucket":"rep","access_key":"a","secret_key":"b"}')" 400
check_eq "verify_tls false on a public host refused" "$(v '{"endpoint":"https://s3.example.com","bucket":"rep","access_key":"a","secret_key":"b","verify_tls":false}')" 400
check_eq "unknown field refused" "$(v '{"endpoint":"https://s3.example.com","bucket":"rep","access_key":"a","secret_key":"b","x":1}')" 400
check_eq "missing secret on a new rule refused" "$(v '{"endpoint":"https://s3.example.com","bucket":"rep","access_key":"a"}')" 400
check_eq "bad remote bucket refused" "$(v '{"endpoint":"https://s3.example.com","bucket":"A_B","access_key":"a","secret_key":"b"}')" 400
check_eq "no rule yet → status 404" "$(scode "http://x/v1/buckets/src/replication/status")" 404
check_eq "unknown bucket → 404" "$(scode "http://x/v1/buckets/nope/replication")" 404

out=$(sadm -X PUT --data "$RULE" "http://x/v1/buckets/src/replication")
check_eq "rule set" "$(echo "$out" | jget "['bucket']")" rep
check_eq "PUT response has no secret" "$(echo "$out" | grep -c "$RSK" || true)" 0
out=$(sadm "http://x/v1/buckets/src/replication")
check_eq "GET has no secret" "$(echo "$out" | grep -c "$RSK" || true)" 0
check_eq "GET says secret is set" "$(echo "$out" | jget "['secret_key_set']")" True
check_eq "sidecar is mode 0600" "$(stat -c %a "$SDATA/buckets/src/replication.json")" 600
check_eq "bucket detail shows replication" \
    "$(sadm "http://x/v1/buckets/src" | jget "['replication']['target']")" "http://127.0.0.1:$RPORT/rep"

# ---- changes arrive ------------------------------------------------------
check_eq "put a" "$(src put src a first '{"ContentType":"text/x-a","Metadata":{"color":"blue"},"CacheControl":"max-age=60"}')" ok
check_eq "put spaced key" "$(src put src 'dir/b c+d' bee)" ok
check_eq "overwrite a" "$(src put src a second '{"ContentType":"text/x-a","Metadata":{"color":"red"},"CacheControl":"max-age=60"}')" ok
head -c 12000000 /dev/urandom > "$T.big"
BIGMD5=$(md5sum < "$T.big" | cut -d' ' -f1)
check_eq "multipart upload" "$(src putfile src big "$T.big")" ok
check_eq "copy" "$(src copy src a a-copy)" ok
check_eq "put doomed" "$(src put src doomed x)" ok
check_eq "delete doomed" "$(src rm src doomed)" ok
drain 60 || true
check_eq "a replicated (latest)" "$(rep get rep a)" second
check_eq "a metadata replicated" "$(rep head rep a)" "text/x-a red max-age=60"
check_eq "spaced key replicated" "$(rep get rep 'dir/b c+d')" bee
check_eq "multipart object replicated" "$(rep md5 rep big)" "$BIGMD5"
check_eq "copy replicated" "$(rep get rep a-copy)" second
check_eq "delete replicated" "$(rep exists rep doomed)" no
check_eq "pre-existing object not replicated before sync" "$(rep exists rep old1)" no
s=$(status)
check_eq "status: nothing failed" "$(echo "$s" | jget "['failed']")" 0

# ---- replica down: backlog, coalescing, drain ---------------------------
before=$(echo "$s" | jget "['replicated']")
stop_rep
check_eq "burst of 20 overwrites" "$(src burst src hot 20)" ok
check_eq "put while down" "$(src put src while-down y)" ok
sleep 1.5
s=$(status)
check_eq "backlog while replica is down (superseded records dropped)" "$(echo "$s" | jget "['queue']")" 2
check_eq "error recorded while down" "$(echo "$s" | jget "['last_error']" | grep -c 'connect' || true)" 1
start_rep
drain 40 || true
check_eq "burst coalesced to the final value" "$(rep get rep hot)" v19
check_eq "put while down arrived" "$(rep get rep while-down)" y
after=$(status | jget "['replicated']")
check_eq "21 changes, 2 uploads" "$((after - before))" 2

# ---- backfill -------------------------------------------------------------
check_eq "sync accepted" "$(scode -X POST "http://x/v1/buckets/src/replication/sync")" 202
drain 30 || true
check_eq "backfill copied the pre-existing object" "$(rep get rep old1)" before-rule
check_eq "backfill queued only what was missing" "$(status | jget "['backfill']['queued']")" 1

# ---- permanent 4xx: recorded and skipped --------------------------------
n=$(rep count rep)
radm -X PUT --data '{"max_bytes":0,"max_objects":'$((n + 1))'}' "http://x/v1/buckets/rep/quota" >/dev/null
src put src q1 one >/dev/null
src put src q2 two >/dev/null
drain 20 || true
s=$(status)
check_eq "quota-refused object counted as failed" "$(echo "$s" | jget "['failed']")" 1
check_eq "failed key in the error ring" "$(echo "$s" | jget "['errors'][0]['key']")" q2
check_eq "failure audited" "$(grep -c 'key q2 failed' "$AUDIT" || true)" 1
radm -X DELETE "http://x/v1/buckets/rep/quota" >/dev/null
src put src q3 three >/dev/null
drain 20 || true
check_eq "queue moved on past the failure" "$(rep get rep q3)" three
check_eq "skipped object not on replica" "$(rep exists rep q2)" no

# ---- deletes:false (secret omitted: kept) --------------------------------
RULE_ND='{"endpoint":"http://127.0.0.1:'$RPORT'","bucket":"rep","access_key":"'$RAK'","allow_plain_http":true,"deletes":false}'
check_eq "rule update without secret" "$(scode -X PUT --data "$RULE_ND" "http://x/v1/buckets/src/replication")" 200
src rm src q1 >/dev/null
src put src after-nd z >/dev/null
drain 20 || true
check_eq "deletes:false keeps the replica copy" "$(rep get rep q1)" one
check_eq "uploads still work with the kept secret" "$(rep get rep after-nd)" z

# ---- wrong secret: held, retried, drained after the fix ------------------
RULE_BAD='{"endpoint":"http://127.0.0.1:'$RPORT'","bucket":"rep","access_key":"'$RAK'","secret_key":"wrong-secret-value","allow_plain_http":true}'
sadm -X PUT --data "$RULE_BAD" "http://x/v1/buckets/src/replication" >/dev/null
src put src held h >/dev/null
sleep 2
s=$(status)
check_eq "bad credentials keep the record" "$(echo "$s" | jget "['queue']")" 1
check_eq "bad credentials reported" "$(echo "$s" | jget "['last_error']" | grep -c SignatureDoesNotMatch || true)" 1
sadm -X PUT --data "$RULE" "http://x/v1/buckets/src/replication" >/dev/null
drain 20 || true
check_eq "held record drained after the fix" "$(rep get rep held)" h

# ---- kill -9 with a lost journal: recovery scan --------------------------
stop_rep
for i in 1 2 3; do src put src "crash$i" "c$i" >/dev/null; done
kill -9 "$SP"; wait "$SP" 2>/dev/null || true; SP=""
ID=$(ls "$SDATA/repl")
: > "$SDATA/repl/$ID/queue"          # pretend the journal never reached the disk
check_eq "no clean marker after kill -9" "$(test -e "$SDATA/repl/$ID/clean" && echo yes || echo no)" no
start_rep
start_src
drain 30 || true
check_eq "recovery scan re-queued crash1" "$(rep get rep crash1)" c1
check_eq "recovery scan re-queued crash3" "$(rep get rep crash3)" c3

# ---- SSE-C skipped; https replication with --repl-ca-file ----------------
RULE_TLS='{"endpoint":"https://localhost:'$RTPORT'","bucket":"rep","access_key":"'$RAK'","secret_key":"'$RSK'"}'
check_eq "https rule accepted" "$(scode -X PUT --data "$RULE_TLS" "http://x/v1/buckets/src/replication")" 200
check_eq "SSE-C put over TLS" "$(srct ssec src sealed)" ok
src put src over-tls t >/dev/null
drain 20 || true
check_eq "replicated over https" "$(rep get rep over-tls)" t
check_eq "SSE-C object skipped" "$(rep exists rep sealed)" no
check_eq "SSE-C skip counted" "$(status | jget "['skipped_ssec']")" 1

# ---- self-healing scrub ---------------------------------------------------
HEAL=$(python3 -c 'print("healme-payload-" * 400)')
BOTH=$(python3 -c 'print("badboth-payload-" * 400)')
src put src heal-me "$HEAL" >/dev/null
src put src bad-both "$BOTH" >/dev/null
drain 20 || true
# Flip one payload byte (the marker occurs only in the payload).
corrupt() {
    python3 - "$1" "$2" <<'PY'
import sys
p, marker = sys.argv[1], sys.argv[2].encode()
b = bytearray(open(p, "rb").read())
i = b.index(marker) + 3
b[i] ^= 0x20
open(p, "r+b").write(b)
PY
}
LH=$(grep -rl 'healme-payload' "$SDATA/data/src" | head -1)
LB=$(grep -rl 'badboth-payload' "$SDATA/data/src" | head -1)
RB=$(grep -rl 'badboth-payload' "$RDATA/data/rep" | head -1)
corrupt "$LH" healme-payload
corrupt "$LB" badboth-payload
corrupt "$RB" badboth-payload
sst() { sadm http://x/v1/scrub | python3 -c "import sys,json; print(json.load(sys.stdin)$1)"; }
pass0=$(sst '["pass"]')
sadm -X POST http://x/v1/scrub >/dev/null
for _ in $(seq 300); do
    [ "$(sst '["running"]')" = False ] && [ "$(sst '["pass"]')" -gt "$pass0" ] && break
    sleep 0.1
done
check_eq "scrub found both corrupt objects" "$(sst '["corrupt"]')" 2
check_eq "scrub repaired one" "$(sst '["repaired"]')" 1
check_eq "repaired object reads back intact" "$(src get src heal-me)" "$HEAL"
check_eq "repair logged" "$(grep -c '"key":"heal-me".*"repaired":true' "$SDATA/scrub/corrupt.log" || true)" 1
check_eq "corrupt replica copy refused" \
    "$(grep -c '"key":"bad-both".*"repaired":false.*does not verify' "$SDATA/scrub/corrupt.log" || true)" 1
check_eq "refused repair left the local (corrupt) file alone" \
    "$([ "$(src get src bad-both 2>/dev/null)" = "$BOTH" ] && echo intact || echo still-corrupt)" still-corrupt
check_eq "repair audited" "$(grep -c 'repaired bucket=src key=heal-me' "$AUDIT" || true)" 1
check_eq "repaired metric" "$(curl -s "http://127.0.0.1:$SMPORT/metrics" | grep -c '^fs3_scrub_repaired_total 1' || true)" 1

# ---- metrics, clean shutdown, secret hygiene, rule removal ---------------
m=$(curl -s "http://127.0.0.1:$SMPORT/metrics")
check_eq "queue depth metric" "$(echo "$m" | grep -c '^fs3_repl_queue_depth{bucket="src"} 0' || true)" 1
check_eq "ops metric" "$(echo "$m" | grep -c '^fs3_repl_ops_total{bucket="src",op="put",result="ok"}' || true)" 1
stop_src
check_eq "clean marker after a clean stop" "$(test -e "$SDATA/repl/$ID/clean" && echo yes || echo no)" yes
start_src
check_eq "clean marker consumed at start" "$(test -e "$SDATA/repl/$ID/clean" && echo yes || echo no)" no
check_eq "secret not in the source log" "$(grep -c "$RSK" "$SLOG" || true)" 0
check_eq "secret not in the audit log" "$(grep -c "$RSK" "$AUDIT" || true)" 0
check_eq "rule change audited" "$(grep -c 'replication set' "$AUDIT" || true)" 5
check_eq "rule removed" "$(scode -X DELETE "http://x/v1/buckets/src/replication")" 200
check_eq "state directory removed" "$(ls "$SDATA/repl" | wc -l | tr -d ' ')" 0
src put src after-removal r >/dev/null
sleep 1
check_eq "no replication after removal" "$(rep exists rep after-removal)" no

echo
echo "replication e2e: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
