#!/usr/bin/env bash
#
# tests/test_e2e_notify.sh — bucket event notifications (webhooks): the
# admin API and its validation, Put/Copy/CompleteMultipartUpload/Delete/
# DeleteMarkerCreated events with prefix/suffix filters, the S3 record
# format (URL-encoded key, ETag, versionId, increasing sequencer), the
# HMAC signature and delivery id, in-order redelivery after 503s and an
# outage, a permanent 4xx dropped and audited, durability across kill -9,
# the test event, metrics, rule removal, --notify off, and the secret
# never appearing in responses, logs or the audit log.
#
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BASE=${FS3_TEST_PORT:-$(( 26000 + RANDOM % 250 ))}
PORT=$BASE; MPORT=$((BASE + 1)); HPORT=$((BASE + 2))
T=/tmp/fs3-notify-$$
DATA=$T.data; LOG=$T.log; AUDIT=$T.audit; SOCK=$T.sock
EVLOG=$T.events; MODE=$T.mode
AK=AKIANOTIFYTEST01
SK=notifySecret0123456789012345678901234
SECRET='hook-Secret-7f3a9c'

SP=""; HP=""
stop_fs3() { [ -n "$SP" ] && { kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null || true; }; SP=""; }
stop_hook() { [ -n "$HP" ] && { kill "$HP" 2>/dev/null; wait "$HP" 2>/dev/null || true; }; HP=""; }
cleanup() { stop_fs3; stop_hook; rm -rf "$T".*; }
trap cleanup EXIT

BUILD_FLAGS=""
[ "${DEBUG:-0}" = "1" ] && BUILD_FLAGS="DEBUG=1"
(cd "$ROOT" && make $BUILD_FLAGS fs3 >/dev/null 2>&1) || { echo "fs3 build failed" >&2; exit 1; }
BIN="$ROOT/fs3"

PASS=0; FAIL=0
check_eq() {
    if [ "$2" = "$3" ]; then PASS=$((PASS+1)); printf '.'
    else FAIL=$((FAIL+1)); printf '\nFAIL: %s\n  want=%s\n  got =%s\n' "$1" "$3" "$2"; fi
}
wait_up() { for _ in $(seq 100); do curl -s -o /dev/null "http://127.0.0.1:$1/health" && return 0; sleep 0.1; done; return 1; }

# ---- webhook receiver: logs each POST as a JSON line, answers with the
# status in $MODE (default 200). ------------------------------------------
cat > "$T.hook.py" <<'PY'
import sys, json, os
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
port, log, mode = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n).decode()
        try: st = int(open(mode).read().strip() or "200")
        except Exception: st = 200
        rec = {"path": self.path, "status": st, "body": body,
               "headers": {k.lower(): v for k, v in self.headers.items()}}
        with open(log, "a") as f: f.write(json.dumps(rec) + "\n")
        self.send_response(st)
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *a): pass
ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
PY
start_hook() {
    python3 "$T.hook.py" "$HPORT" "$EVLOG" "$MODE" &
    HP=$!
    for _ in $(seq 50); do curl -s -o /dev/null -X POST "http://127.0.0.1:$HPORT/ping" -d '' && break; sleep 0.1; done
    # The probe itself is logged; drop it.
    python3 - "$EVLOG" <<'PY'
import sys
p = sys.argv[1]
try: lines = open(p).read().splitlines()
except FileNotFoundError: lines = []
open(p, "w").write("".join(l + "\n" for l in lines if '"path": "/ping"' not in l))
PY
}

start_fs3() {
    ${FS3_WRAP:-} "$BIN" -p "$PORT" -d "$DATA" --auth "$AK:$SK" --require-auth \
        --admin-socket "$SOCK" --metrics-port "$MPORT" --audit-log "$AUDIT" --notify-timeout 3 "$@" \
        >>"$LOG" 2>&1 &
    SP=$!
    wait_up "$PORT" || { echo "fs3 did not start" >&2; cat "$LOG" >&2; exit 1; }
}

adm() { curl -sS --unix-socket "$SOCK" "$@"; }
acode() { curl -sS -o /dev/null -w '%{http_code}' --unix-socket "$SOCK" "$@"; }
jget() { python3 -c 'import sys,json; d=json.load(sys.stdin); print(eval("d"+sys.argv[1]))' "$1"; }

cat > "$T.s3.py" <<'PY'
import sys, json
sys.modules["awscrt"] = None
import boto3, botocore
from boto3.s3.transfer import TransferConfig
url, ak, sk, cmd, *a = sys.argv[1:]
s3 = boto3.client("s3", endpoint_url=url, aws_access_key_id=ak, aws_secret_access_key=sk,
                  region_name="us-east-1")
try:
    if cmd == "mb": s3.create_bucket(Bucket=a[0]); print("ok")
    elif cmd == "put": s3.put_object(Bucket=a[0], Key=a[1], Body=a[2].encode()); print("ok")
    elif cmd == "putfile":
        s3.upload_file(a[2], a[0], a[1], Config=TransferConfig(multipart_threshold=5 << 20,
                       multipart_chunksize=5 << 20)); print("ok")
    elif cmd == "copy":
        s3.copy_object(Bucket=a[0], Key=a[2], CopySource={"Bucket": a[0], "Key": a[1]}); print("ok")
    elif cmd == "rm": s3.delete_object(Bucket=a[0], Key=a[1]); print("ok")
    elif cmd == "etag": print(s3.head_object(Bucket=a[0], Key=a[1])["ETag"].strip('"'))
    elif cmd == "versioning":
        s3.put_bucket_versioning(Bucket=a[0], VersioningConfiguration={"Status": "Enabled"}); print("ok")
    elif cmd == "rb": s3.delete_bucket(Bucket=a[0]); print("ok")
except botocore.exceptions.ClientError as e:
    print(e.response["Error"]["Code"])
PY
s3() { python3 "$T.s3.py" "http://127.0.0.1:$PORT" "$AK" "$SK" "$@"; }

# ev <n> <python expr on r (record), b (body json), h (headers)>: field of the n-th event (0-based).
ev() {
    python3 - "$EVLOG" "$1" "$2" <<'PY'
import sys, json
recs = [json.loads(l) for l in open(sys.argv[1])] if True else []
r = recs[int(sys.argv[2])]
b = json.loads(r["body"]); h = r["headers"]
print(eval(sys.argv[3]))
PY
}
nev() { [ -f "$EVLOG" ] && wc -l < "$EVLOG" | tr -d ' ' || echo 0; }
wait_ev() {  # wait until the receiver has logged at least $1 POSTs
    for _ in $(seq $(( ${2:-15} * 10 ))); do [ "$(nev)" -ge "$1" ] && return 0; sleep 0.1; done
    echo; echo "timed out waiting for $1 events (have $(nev))" >&2; return 1
}
status() { adm "http://x/v1/buckets/hooks/notification/status"; }

echo 200 > "$MODE"
start_hook
start_fs3
check_eq "bucket" "$(s3 mb hooks)" ok
check_eq "second bucket" "$(s3 mb quiet)" ok

# ---- validation ---------------------------------------------------------
v() { acode -X PUT --data "$1" "http://x/v1/buckets/hooks/notification"; }
H="http://127.0.0.1:$HPORT"
check_eq "public plain-http host refused" "$(v '{"endpoint":"http://8.8.8.8/x","allow_plain_http":true}')" 400
check_eq "plain http needs allow_plain_http" "$(v '{"endpoint":"'$H'/x"}')" 400
check_eq "https needs a TLS build" "$(v '{"endpoint":"https://hooks.example.com/x"}')" 400
check_eq "fragment refused" "$(v '{"endpoint":"'$H'/x#y","allow_plain_http":true}')" 400
check_eq "unknown event refused" "$(v '{"endpoint":"'$H'/x","allow_plain_http":true,"events":["s3:ObjectCreated:Nope"]}')" 400
check_eq "empty events refused" "$(v '{"endpoint":"'$H'/x","allow_plain_http":true,"events":[]}')" 400
check_eq "unknown field refused" "$(v '{"endpoint":"'$H'/x","allow_plain_http":true,"x":1}')" 400
check_eq "bad max_age_hours refused" "$(v '{"endpoint":"'$H'/x","allow_plain_http":true,"max_age_hours":0}')" 400
check_eq "missing endpoint refused" "$(v '{"allow_plain_http":true}')" 400
check_eq "not JSON refused" "$(v 'nope')" 400
check_eq "no rule → GET 404" "$(acode "http://x/v1/buckets/hooks/notification")" 404
check_eq "no rule → status 404" "$(acode "http://x/v1/buckets/hooks/notification/status")" 404
check_eq "unknown bucket → 404" "$(acode "http://x/v1/buckets/nope/notification")" 404
check_eq "unknown sub-endpoint → 404" "$(acode "http://x/v1/buckets/hooks/notification/zzz")" 404

RULE='{"endpoint":"'$H'/hook?src=fs3","allow_plain_http":true,"prefix":"in/","secret":"'$SECRET'",
       "events":["s3:ObjectCreated:*","s3:ObjectRemoved:*"]}'
out=$(adm -X PUT --data "$RULE" "http://x/v1/buckets/hooks/notification")
check_eq "rule set" "$(echo "$out" | jget "['prefix']")" in/
check_eq "PUT response has no secret" "$(echo "$out" | grep -c "$SECRET" || true)" 0
out=$(adm "http://x/v1/buckets/hooks/notification")
check_eq "GET has no secret" "$(echo "$out" | grep -c "$SECRET" || true)" 0
check_eq "GET says secret is set" "$(echo "$out" | jget "['secret_set']")" True
check_eq "GET events" "$(echo "$out" | jget "['events']")" "['s3:ObjectCreated:*', 's3:ObjectRemoved:*']"
check_eq "sidecar is mode 0600" "$(stat -c %a "$DATA/buckets/hooks/notification.json")" 600

# ---- events ---------------------------------------------------------------
check_eq "put in/a" "$(s3 put hooks in/a hello)" ok
check_eq "put outside the prefix" "$(s3 put hooks out/x nope)" ok
check_eq "put in another bucket" "$(s3 put quiet in/a nope)" ok
check_eq "put spaced key" "$(s3 put hooks 'in/b c+d' bee)" ok
check_eq "copy" "$(s3 copy hooks in/a in/a-copy)" ok
head -c 11000000 /dev/urandom > "$T.big"
check_eq "multipart" "$(s3 putfile hooks in/big "$T.big")" ok
check_eq "delete" "$(s3 rm hooks in/a)" ok
wait_ev 5 || true
check_eq "five events delivered" "$(nev)" 5
check_eq "1: name" "$(ev 0 "b['Records'][0]['eventName']")" ObjectCreated:Put
check_eq "1: path and query" "$(ev 0 "r['path']")" "/hook?src=fs3"
check_eq "1: bucket" "$(ev 0 "b['Records'][0]['s3']['bucket']['name']")" hooks
check_eq "1: key" "$(ev 0 "b['Records'][0]['s3']['object']['key']")" in/a
check_eq "1: size" "$(ev 0 "b['Records'][0]['s3']['object']['size']")" 5
check_eq "1: etag" "$(ev 0 "b['Records'][0]['s3']['object']['eTag']")" "$(printf hello | md5sum | cut -d' ' -f1)"
check_eq "1: source" "$(ev 0 "b['Records'][0]['eventSource']")" fs3:s3
check_eq "1: content type" "$(ev 0 "h['content-type']")" application/json
check_eq "1: event header" "$(ev 0 "h['x-fs3-event']")" ObjectCreated:Put
check_eq "1: delivery id" "$(ev 0 "h['x-fs3-delivery'].endswith('-1')")" True
check_eq "1: no auth header" "$(ev 0 "'authorization' in h")" False
check_eq "1: signature verifies" "$(ev 0 "__import__('hmac').new(b'$SECRET', r['body'].encode(), 'sha256').hexdigest() == h['x-fs3-signature'][7:]")" True
check_eq "2: spaced key URL-encoded" "$(ev 1 "b['Records'][0]['s3']['object']['key']")" "in/b+c%2Bd"
check_eq "3: copy" "$(ev 2 "b['Records'][0]['eventName']")" ObjectCreated:Copy
check_eq "4: multipart" "$(ev 3 "b['Records'][0]['eventName']")" ObjectCreated:CompleteMultipartUpload
check_eq "4: multipart etag" "$(ev 3 "b['Records'][0]['s3']['object']['eTag']")" "$(s3 etag hooks in/big)"
check_eq "4: multipart size" "$(ev 3 "b['Records'][0]['s3']['object']['size']")" 11000000
check_eq "5: delete" "$(ev 4 "b['Records'][0]['eventName']")" ObjectRemoved:Delete
check_eq "5: delete has no size" "$(ev 4 "'size' in b['Records'][0]['s3']['object']")" False
check_eq "sequencers increase" "$(python3 -c '
import json,sys
s=[json.loads(json.loads(l)["body"])["Records"][0]["s3"]["object"]["sequencer"] for l in open(sys.argv[1])]
print(s == sorted(s) and len(set(s)) == len(s))' "$EVLOG")" True
s=$(status)
check_eq "status: queue empty" "$(echo "$s" | jget "['queue']")" 0
check_eq "status: sent" "$(echo "$s" | jget "['sent']")" 5

# ---- suffix filter, events subset; secret kept when omitted ---------------
adm -X PUT --data '{"endpoint":"'$H'/hook?src=fs3","allow_plain_http":true,"suffix":".jpg","events":["s3:ObjectRemoved:*"]}' \
    "http://x/v1/buckets/hooks/notification" >/dev/null
check_eq "secret kept on update" "$(adm "http://x/v1/buckets/hooks/notification" | jget "['secret_set']")" True
s3 put hooks pic.jpg x >/dev/null; s3 put hooks pic.png x >/dev/null
s3 rm hooks pic.png >/dev/null; s3 rm hooks pic.jpg >/dev/null
wait_ev 6 || true
sleep 0.5
check_eq "only the .jpg delete" "$(nev)" 6
check_eq "6: key" "$(ev 5 "b['Records'][0]['s3']['object']['key']")" pic.jpg

# ---- versioned bucket: delete marker -------------------------------------
adm -X PUT --data "$RULE" "http://x/v1/buckets/hooks/notification" >/dev/null
check_eq "versioning on" "$(s3 versioning hooks)" ok
s3 put hooks in/v one >/dev/null
s3 rm hooks in/v >/dev/null
wait_ev 8 || true
check_eq "7: versioned put has a versionId" "$(ev 6 "len(b['Records'][0]['s3']['object'].get('versionId',''))>0")" True
check_eq "8: delete marker" "$(ev 7 "b['Records'][0]['eventName']")" ObjectRemoved:DeleteMarkerCreated
check_eq "8: marker versionId" "$(ev 7 "len(b['Records'][0]['s3']['object'].get('versionId',''))>0")" True

# ---- 503: retried in order ------------------------------------------------
echo 503 > "$MODE"
s3 put hooks in/r1 1 >/dev/null; s3 put hooks in/r2 2 >/dev/null
wait_ev 9 || true
sleep 1.5
s=$(status)
check_eq "backlog while failing" "$(echo "$s" | jget "['queue']")" 2
check_eq "failed attempts counted" "$(echo "$s" | jget "['failed_attempts'] > 0")" True
check_eq "last error recorded" "$(echo "$s" | jget "['last_error']")" "POST: HTTP 503"
echo 200 > "$MODE"
adm -X POST "http://x/v1/buckets/hooks/notification/test" >/dev/null   # also clears the backoff
for _ in $(seq 100); do [ "$(status | jget "['queue']")" = 0 ] && break; sleep 0.1; done
check_eq "backlog drained" "$(status | jget "['queue']")" 0
check_eq "redelivered in order" "$(python3 -c '
import json,sys
ok=[json.loads(json.loads(l)["body"]) for l in open(sys.argv[1]) if json.loads(l)["status"]==200]
print([r.get("Records",[{}])[0].get("s3",{}).get("object",{}).get("key") or r.get("Event") for r in ok[-3:]])' "$EVLOG")" \
    "['in/r1', 'in/r2', 's3:TestEvent']"

# ---- permanent 4xx: dropped and audited ----------------------------------
echo 400 > "$MODE"
before=$(status | jget "['dropped']")
s3 put hooks in/bad x >/dev/null
for _ in $(seq 50); do [ "$(status | jget "['dropped']")" != "$before" ] && break; sleep 0.1; done
check_eq "4xx dropped" "$(status | jget "['dropped']")" $((before + 1))
check_eq "drop audited" "$(grep -c 'dropped: POST: HTTP 400' "$AUDIT" || true)" 1
echo 200 > "$MODE"

# ---- outage + kill -9: the queue survives --------------------------------
stop_hook
s3 put hooks in/k1 1 >/dev/null; s3 put hooks in/k2 2 >/dev/null
sleep 0.5
check_eq "queued while the receiver is down" "$(status | jget "['queue']")" 2
check_eq "connection error recorded" "$(status | jget "['last_error'].startswith('POST:')")" True
kill -9 "$SP"; wait "$SP" 2>/dev/null || true; SP=""
: > "$EVLOG"
start_hook
start_fs3
for _ in $(seq 100); do [ "$(nev)" -ge 2 ] && break; sleep 0.1; done
check_eq "queued events delivered after restart" "$(nev)" 2
check_eq "k1 first" "$(ev 0 "b['Records'][0]['s3']['object']['key']")" in/k1
check_eq "k2 second" "$(ev 1 "b['Records'][0]['s3']['object']['key']")" in/k2
sleep 1
check_eq "no duplicates of already-delivered events" "$(nev)" 2

# ---- test event -----------------------------------------------------------
check_eq "test → 202" "$(acode -X POST "http://x/v1/buckets/hooks/notification/test")" 202
wait_ev 3 || true
check_eq "test event" "$(ev 2 "b['Event']")" s3:TestEvent
check_eq "test via GET refused" "$(acode "http://x/v1/buckets/hooks/notification/test")" 405

# ---- metrics, removal, hygiene -------------------------------------------
m=$(curl -s "http://127.0.0.1:$MPORT/metrics")
check_eq "queue metric" "$(echo "$m" | grep -c '^fs3_notify_queue_depth{bucket="hooks"} 0' || true)" 1
check_eq "sent metric" "$(echo "$m" | grep -c '^fs3_notify_events_total{bucket="hooks",result="sent"} 3' || true)" 1
ID=$(ls "$DATA/notify")
check_eq "queue dir exists" "$(test -d "$DATA/notify/$ID" && echo yes)" yes
check_eq "queue file is 0600" "$(stat -c %a "$DATA/notify/$ID/queue")" 600
check_eq "rule removed" "$(acode -X DELETE "http://x/v1/buckets/hooks/notification")" 200
check_eq "queue dir removed" "$(test -d "$DATA/notify/$ID" && echo yes || echo no)" no
check_eq "second delete → 404" "$(acode -X DELETE "http://x/v1/buckets/hooks/notification")" 404
n0=$(nev)
s3 put hooks in/after x >/dev/null
sleep 0.5
check_eq "no events after removal" "$(nev)" "$n0"
check_eq "secret not in the log" "$(grep -c "$SECRET" "$LOG" || true)" 0
check_eq "secret not in the audit log" "$(grep -c "$SECRET" "$AUDIT" || true)" 0
check_eq "rule changes audited" "$(grep -c 'notification set' "$AUDIT" || true)" 3
check_eq "removal audited" "$(grep -c 'notification removed' "$AUDIT" || true)" 1

# ---- --notify off ----------------------------------------------------------
stop_fs3
start_fs3 --notify off
check_eq "--notify off → 501" "$(v '{"endpoint":"'$H'/x","allow_plain_http":true}')" 501

echo
echo "notify e2e: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
