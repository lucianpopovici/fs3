# Agent runbook: SSE-S3, webhooks and the tile's object browser on the DS1515+

This runbook is for an autonomous agent. It is the hardware exit check
for the three features in PR #13 (SSE-S3, event notifications, the DSM
tile's object browser). The development host already passed every
suite, under both the release and the ASan/UBSan builds. This run
answers what only the NAS can:

1. **Suites on DSM:** whether the new suites pass on DSM's kernel,
   glibc, Btrfs and `/bin/sh`.
2. **Encryption cost:** what SSE-S3 costs in throughput and CPU on an
   Atom C2538 (which has AES-NI), and whether the package's key file has
   the right owner and mode.
3. **Webhooks under seccomp:** whether delivery works with the filter
   enforcing, to a LAN receiver over plain http and over https with a
   private CA, and whether the queue survives `kill -9` and a package
   restart.
4. **The object browser on real DSM:** whether the tile's sign-in gate,
   its admin-socket access, streamed uploads and downloads, and share
   links (on the LAN and behind the DSM reverse proxy) work. The key
   unknown is **how large an upload DSM's web server lets through to a
   CGI**, and whether it buffers the body on disk first.
5. **Resources:** memory and CPU of fs3, the CGI and its `curl` during
   large transfers.

Work through the sections in order. Every step has a **Check**: record
the result in the report template (§9), together with the evidence each
step tells you to keep. Wherever this file says "record", copy the
command output into the report verbatim.

This file builds on `docs/AGENT-BUILD-AND-DS1515-TEST.md` (called "the
main runbook" below). Its ground rules (§0), target facts (§1), access
steps (D0), troubleshooting (§2), NAS build procedure (Part B) and SPK
procedure (Part C, D6) all apply here. §1.2 reuses the LAN CA set-up
from `docs/AGENT-REPLICATION-DS1515-TEST.md` §1.2.

---

## 0. Ground rules

1. **Scratch only.** Use `/volume1/fs3-test` on the NAS and dedicated,
   empty buckets. The browser's *Delete* button and webhook tests
   create and delete objects.
2. **No third-party webhook services.** Receivers run on the build host
   (§1.2). Don't point a rule at a public request-capture site: events
   carry bucket and key names.
3. **The SSE-S3 key file is a secret.** Never print it, copy it off the
   NAS or put it in the report. Record only its mode, owner and line
   count. Likewise never record a webhook secret, an S3 secret or a
   full presigned URL (record it with the `X-Amz-Signature` value cut
   off).
4. **Ask the human before:**
   - installing the SPK over an existing fs3 installation (back it up
     first, as in main runbook D6.1);
   - changing DSM settings (reverse-proxy entries, Package Center trust
     level);
   - turning on *Server-side encryption keys* on a package that holds
     real data.
5. **A failing check is a finding, not an obstacle.** Don't weaken a
   test or skip a step to get past it. Collect the evidence §7 lists and
   carry on with the next independent step.

---

## 1. What you need

| item | how to get it |
|---|---|
| Binaries from the `sse-events-browser` branch (PR #13) or from `main` after it merges | Main runbook Part B: `fs3-tls-static` built against glibc ≤ the NAS's. Record `git rev-parse HEAD`. |
| The SPK built from the same commit | Main runbook Part C. |
| On the NAS | SSH as an administrator, Python 3 with `tests/requirements.txt`, the `make` shim and the repository tree at `/volume1/fs3-test/fs3` (main runbook D5 steps 1–3). |
| On the build host | `curl`, `openssl`, Python 3, a browser that can reach DSM (for §6; the agent can drive it, or ask the human to click through and report). |
| Test files | Created in §2: 100 MB, 1 GB and 4.5 GB random files on the build host for uploads. |

Variables used below:

```sh
export NAS=192.168.1.3                 # the NAS's LAN IP
export HOSTIP=<build host LAN IP>      # where the webhook receivers run
export T=/volume1/fs3-test             # on the NAS
```

### 1.1 Check the binary on the NAS

```sh
cd $T && ./fs3-tls --build-info && ./fs3-tls --help | grep -E 'sse-key-file|notify'
```

**Check:** `tls=yes`, and `--help` lists `--sse-key-file`, `--notify`
and `--notify-timeout`.

### 1.2 Webhook receivers (on the build host)

One receiver logs every POST as a JSON line and answers with the status
in `mode` (default 200). Run it twice: plain http on 9500, and https on
9543 with a private CA.

```sh
mkdir -p ~/hooks && cd ~/hooks
cat > hook.py <<'PY'
import sys, json, ssl
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
port, log, mode = int(sys.argv[1]), sys.argv[2], sys.argv[3]
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        try: st = int(open(mode).read().strip() or "200")
        except Exception: st = 200
        with open(log, "a") as f:
            f.write(json.dumps({"path": self.path, "status": st, "body": body,
                                "headers": {k.lower(): v for k, v in self.headers.items()}}) + "\n")
        self.send_response(st); self.send_header("Content-Length", "0"); self.end_headers()
    def log_message(self, *a): pass
srv = ThreadingHTTPServer(("0.0.0.0", port), H)
if len(sys.argv) > 4:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[4], sys.argv[5])
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PY
# Private CA + server certificate for $HOSTIP
printf '[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > ca.cnf
openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj "/CN=fs3 hook test CA" -config ca.cnf -keyout ca.key -out ca.pem
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=hooks" -keyout srv.key -out srv.csr
printf "subjectAltName=IP:$HOSTIP\nextendedKeyUsage=serverAuth\n" > srv.ext
openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 7 -extfile srv.ext -out srv.crt
echo 200 > mode
python3 hook.py 9500 plain.jsonl mode &
python3 hook.py 9543 tls.jsonl mode srv.crt srv.key &
scp -O ca.pem admin@$NAS:$T/hook-ca.pem
```

Open ports 9500 and 9543 in the build host's firewall for the NAS only.
**Check:** from the NAS, `curl -s -o /dev/null -w '%{http_code}\n' -X POST -d x http://$HOSTIP:9500/`
prints 200 (then `: > ~/hooks/plain.jsonl` on the build host to drop
that probe).

---

## 2. Facts to collect first

```sh
# on the NAS
cat /etc.defaults/VERSION | grep -E 'productversion|buildnumber|smallfixnumber'
uname -r; ldd --version | head -1
ls -l /bin/sh; readlink -f /bin/sh
grep -m1 -o -w aes /proc/cpuinfo || echo "no aes flag"
command -v curl && curl --version | head -1
openssl speed -evp aes-256-gcm -seconds 2 2>/dev/null | tail -1
ps -o user,args -C nginx | head -3
ls -d /etc/nginx /usr/syno/share/nginx 2>/dev/null
sudo grep -rhoE 'client_max_body_size[^;]*;|client_body_buffer_size[^;]*;|client_body_temp_path[^;]*;|proxy_request_buffering[^;]*;' \
     /etc/nginx /usr/syno/share/nginx 2>/dev/null | sort | uniq -c
```

```sh
# on the build host: upload test files
head -c 100M  /dev/urandom > /tmp/up100m.bin
head -c 1G    /dev/urandom > /tmp/up1g.bin
head -c 4600M /dev/urandom > /tmp/up4g5.bin
md5sum /tmp/up*.bin > /tmp/up.md5
```

**Check:** record each output. The `/bin/sh` target matters (the tile
CGI runs under it), as does `curl` (the browser streams through it). The
nginx lines show which body-size limits and buffering apply to the
tile's CGI.

---

## 3. The repository suites on the NAS

```sh
cd $T/fs3
export PATH=$HOME/bin:$HOME/.local/bin:$PATH
cp ../fs3-tls ./fs3-tls; cp ../fs3-tls ./fs3      # the e2e scripts use ./fs3 or ./fs3-tls
# Unit tests: build them in the Part B environment (same glibc) and copy
# tests/test_ssekeys and tests/test_notify here.
./tests/test_ssekeys 50000 | tail -1
./tests/test_notify 50000 | tail -1
./tests/test_e2e_sse_s3.sh 2>&1 | tail -2
./tests/test_e2e_notify.sh 2>&1 | tail -2
./tests/test_e2e_admin.sh 2>&1 | tail -2
./tests/test_e2e_subresources.sh 2>&1 | tail -2
sh ./tests/test_ui_cgi.sh 2>&1 | tail -2       # runs the CGI with the NAS's /bin/sh
./tests/test_spk_scripts.sh 2>&1 | tail -2
```

If a script's `make` step tries to rebuild the binary, prevent it by
`touch`ing the copied binaries after the sources, as in main runbook D5.

**Check:** every suite ends with `0 failed`. For a failure, rerun with
`bash -x` and keep the output. `FAIL: server died with SIGSYS` or exit
159 means a syscall is missing: follow main runbook D3. A
`test_ui_cgi.sh` failure that only happens on the NAS points at a
`/bin/sh`, `awk`, `sed` or `tr` difference; record which check and the
CGI's output.

---

## 4. SSE-S3 (standalone fs3, seccomp enforce)

### 4.1 Key file and start-up checks

```sh
cd $T && rm -rf sse-data && mkdir sse-data
umask 077; printf 'k1 %s\n' "$(openssl rand -hex 32)" > sse.keys; umask 022
stat -c '%a %U' sse.keys
chmod 644 sse.keys
./fs3-tls -a 127.0.0.1 -p 9600 -d $T/sse-data --sse-key-file $T/sse.keys 2>&1 | head -3   # must refuse
chmod 600 sse.keys
./fs3-tls -a 127.0.0.1 -p 9600 -d $T/sse-data --auth AKIANASSSE000001:nasSseSecret0123456789012345678901 \
    --require-auth --sse-key-file $T/sse.keys --admin-socket $T/sse.sock --metrics-port 9601 \
    > sse.log 2>&1 &
echo $! > sse.pid; sleep 1; grep -E 'seccomp|sse|listening' sse.log; curl -s 127.0.0.1:9600/_health
```

**Check:** the 0644 file is refused (`--sse-key-file: … must not be
readable by group or others (chmod 600)`, exit 2); the 0600 start
answers `/_health` and logs `seccomp: filter installed (… mode
enforce)`. (fs3 logs the key count only on SIGHUP reloads.)

Helper for the rest of §4:

```sh
s3e() { python3 - "$@" <<'PY'
import sys, time, hashlib, boto3; sys.modules.setdefault("awscrt", None)
from boto3.s3.transfer import TransferConfig
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:9600", aws_access_key_id="AKIANASSSE000001",
                  aws_secret_access_key="nasSseSecret0123456789012345678901", region_name="us-east-1")
cmd, *a = sys.argv[1:]
cfg = TransferConfig(multipart_threshold=64 << 20, multipart_chunksize=64 << 20)
if cmd == "mb": s3.create_bucket(Bucket=a[0]); print("ok")
elif cmd == "default":
    s3.put_bucket_encryption(Bucket=a[0], ServerSideEncryptionConfiguration={"Rules": [
        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}); print("ok")
elif cmd == "up":    # up <bucket> <key> <file> [sse]
    extra = {"ServerSideEncryption": "AES256"} if len(a) > 3 else {}
    t = time.time(); s3.upload_file(a[2], a[0], a[1], ExtraArgs=extra, Config=cfg)
    print("%.1f s" % (time.time() - t))
elif cmd == "down":  # down <bucket> <key>
    t = time.time(); h = hashlib.md5()
    for c in s3.get_object(Bucket=a[0], Key=a[1])["Body"].iter_chunks(1 << 20): h.update(c)
    print(h.hexdigest(), "%.1f s" % (time.time() - t))
elif cmd == "head":
    r = s3.head_object(Bucket=a[0], Key=a[1]); print(r.get("ServerSideEncryption", "-"), r["ETag"])
PY
}
```

### 4.2 Throughput, plain versus encrypted

Create the test file on the NAS (the volume, not `/tmp`, which is small
on DSM):

```sh
head -c 1G /dev/urandom > $T/g1.bin; md5sum $T/g1.bin
s3e mb plainb; s3e mb sseb; s3e default sseb
s3e up plainb g1 $T/g1.bin;  s3e up sseb g1 $T/g1.bin
s3e down plainb g1;           s3e down sseb g1
s3e head plainb g1;           s3e head sseb g1
```

Run the uploads and downloads twice each, and sample fs3 while the
encrypted ones run (second SSH session):

```sh
for i in $(seq 30); do ps -o rss=,pcpu=,nlwp= -p $(cat $T/sse.pid); sleep 1; done
```

**Check:**
- both downloads print the file's MD5;
- `head` shows `- <etag>` for `plainb` and `AES256 <etag>` for `sseb`,
  and the two ETags are **equal** (SSE-S3 keeps the plaintext MD5; a
  multipart ETag ends in `-16` for both);
- the object file on disk does not contain the plaintext (a 64-byte
  sample from the middle of the file is found in the plain bucket's
  object but not in the encrypted one):
  ```sh
  for b in plainb sseb; do f=$(find $T/sse-data/buckets/$b -type f -size +900M | head -1)
    python3 -c 'import sys; s=open(sys.argv[2],"rb").read()[500000000:500000064]; print(sys.argv[3], s in open(sys.argv[1],"rb").read())' "$f" $T/g1.bin $b; done
  ```
  prints `plainb True` and `sseb False`;
- record seconds and MB/s for each of the four transfers (best of two),
  and the peak CPU % and RSS during the encrypted ones. Expect the
  encrypted transfers within about 20% of plain if the CPU has AES-NI.

### 4.3 Rotation and refused reloads

```sh
cp sse.keys sse.keys.bak
printf 'k2 %s\n' "$(openssl rand -hex 32)" >> sse.keys
kill -HUP $(cat sse.pid); sleep 1; tail -3 sse.log
head -c 1M /dev/urandom > $T/m1.bin; s3e up sseb after-rotate $T/m1.bin
s3e down sseb g1 | cut -c1-32                                  # old key still decrypts
sed -i '/^k1 /d' sse.keys; kill -HUP $(cat sse.pid); sleep 1; tail -2 sse.log
s3e down sseb g1 | cut -c1-32                                  # still readable
cp sse.keys.bak sse.keys; printf 'k2 %s\n' "$(openssl rand -hex 32)" >> sse.keys   # k2 changed
kill -HUP $(cat sse.pid); sleep 1; tail -2 sse.log
```

**Check:** the first reload logs `SIGHUP: SSE key file reloaded (2
key(s))`; the reload that drops `k1` logs `SSE key file not reloaded
(keeping the old keys)` and the old ring stays, so `g1` still
decrypts; the reload that changes `k2` is refused too. Restore the
accepted two-key file before going on (`cp sse.keys.bak sse.keys` and
re-append the original `k2` line, or simply restart fs3 with
`sse.keys.bak` plus a fresh `k2` and re-upload `after-rotate`).

### 4.4 Restart and kill -9

```sh
kill -9 $(cat sse.pid); sleep 1
./fs3-tls -a 127.0.0.1 -p 9600 -d $T/sse-data --auth AKIANASSSE000001:nasSseSecret0123456789012345678901 \
    --require-auth --sse-key-file $T/sse.keys --admin-socket $T/sse.sock --metrics-port 9601 >> sse.log 2>&1 &
echo $! > sse.pid; sleep 1
s3e down sseb g1 | cut -c1-32; s3e head sseb after-rotate
```

**Check:** both objects read back after the crash and restart.

Stop the server and delete `$T/sse-data`, `$T/g1.bin`, `$T/m1.bin`,
`$T/sse.keys*` when §4 is done (`shred -u` the key files).

---

## 5. Webhooks (standalone fs3, seccomp enforce)

### 5.1 Start the source

```sh
cd $T && rm -rf ev-data && mkdir ev-data
./fs3-tls -a 127.0.0.1 -p 9700 -d $T/ev-data --auth AKIANASEVENTS001:nasEventsSecret012345678901234567890 \
    --require-auth --admin-socket $T/ev.sock --metrics-port 9701 --audit-log $T/ev-audit.log \
    --repl-ca-file $T/hook-ca.pem --notify-timeout 5 > ev.log 2>&1 &
echo $! > ev.pid; sleep 1; grep -E 'seccomp|notify|listening' ev.log
adm() { curl -sS --unix-socket $T/ev.sock "$@"; }
s3v() { python3 - "$@" <<'PY'
import sys, boto3; sys.modules.setdefault("awscrt", None)
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:9700", aws_access_key_id="AKIANASEVENTS001",
                  aws_secret_access_key="nasEventsSecret012345678901234567890", region_name="us-east-1")
cmd, *a = sys.argv[1:]
if cmd == "mb": s3.create_bucket(Bucket=a[0])
elif cmd == "put": s3.put_object(Bucket=a[0], Key=a[1], Body=a[2].encode())
elif cmd == "rm": s3.delete_object(Bucket=a[0], Key=a[1])
print("ok")
PY
}
st() { adm http://x/v1/buckets/$1/notification/status; echo; }
s3v mb evplain; s3v mb evtls
```

**Check:** the log shows the seccomp filter in enforce mode and no
SIGSYS.

### 5.2 Plain http to a LAN address

```sh
adm -X PUT http://x/v1/buckets/evplain/notification \
  -d '{"endpoint":"http://'$HOSTIP':9500/hook","allow_plain_http":true,"secret":"nas-hook-secret-1"}'; echo
s3v put evplain a.txt hello; s3v rm evplain a.txt; sleep 2; st evplain
```

On the build host:

```sh
python3 - <<'PY'
import json, hmac, hashlib
for l in open("/home/$USER/hooks/plain.jsonl".replace("$USER", __import__("getpass").getuser())):
    r = json.loads(l); b = json.loads(r["body"]); h = r["headers"]
    ok = hmac.new(b"nas-hook-secret-1", r["body"].encode(), hashlib.sha256).hexdigest() == h.get("x-fs3-signature", "")[7:]
    print(b["Records"][0]["eventName"], b["Records"][0]["s3"]["object"]["key"], h["x-fs3-delivery"], "sig", ok)
PY
```

**Check:** two lines, `ObjectCreated:Put a.txt … sig True` then
`ObjectRemoved:Delete a.txt … sig True`, and status shows `queue` 0,
`sent` 2. A public host with `allow_plain_http` is refused:
`adm -X PUT http://x/v1/buckets/evplain/notification -d '{"endpoint":"http://8.8.8.8/x","allow_plain_http":true}'`
answers 400.

### 5.3 https with a private CA

```sh
adm -X PUT http://x/v1/buckets/evtls/notification -d '{"endpoint":"https://'$HOSTIP':9543/hook"}'; echo
s3v put evtls b.txt hi; sleep 2; st evtls
```

**Check:** `tls.jsonl` on the build host has an `ObjectCreated:Put`
for `b.txt`, and status shows `sent` 1. Then restart fs3 **without**
`--repl-ca-file`, put another object and check that status shows a
certificate error in `last_error`, `failed_attempts` growing and the
event still queued (`queue` 1). Restart with the CA file again and
check the event arrives (POST `…/notification/test` to skip the
backoff).

### 5.4 Outage, 503 and kill -9

```sh
# on the build host: echo 503 > ~/hooks/mode
s3v put evplain r1 1; s3v put evplain r2 2; sleep 3; st evplain        # queue 2, last_error HTTP 503
# on the build host: stop the plain receiver (kill its python process)
s3v put evplain k1 1; s3v put evplain k2 2; sleep 1
kill -9 $(cat ev.pid); sleep 1
ls -la $T/ev-data/notify/*/
# on the build host: echo 200 > ~/hooks/mode; : > ~/hooks/plain.jsonl; restart the plain receiver
./fs3-tls -a 127.0.0.1 -p 9700 -d $T/ev-data --auth AKIANASEVENTS001:nasEventsSecret012345678901234567890 \
    --require-auth --admin-socket $T/ev.sock --metrics-port 9701 --audit-log $T/ev-audit.log \
    --repl-ca-file $T/hook-ca.pem --notify-timeout 5 >> ev.log 2>&1 &
echo $! > ev.pid; sleep 1; adm -X POST http://x/v1/buckets/evplain/notification/test; sleep 3; st evplain
```

**Check:** after the restart, `plain.jsonl` has `r1`, `r2`, `k1`, `k2`
in that order (then the test event), and no event from §5.2 again.
The queue files are mode 0600. Record the seconds from restart to the
last delivery.

### 5.5 A permanent 4xx, metrics and hygiene

```sh
# on the build host: echo 400 > ~/hooks/mode
s3v put evplain bad x; sleep 2; st evplain; grep -c 'dropped: POST: HTTP 400' $T/ev-audit.log
# on the build host: echo 200 > ~/hooks/mode
curl -s 127.0.0.1:9701/metrics | grep fs3_notify_
grep -c nas-hook-secret-1 $T/ev.log $T/ev-audit.log
stat -c '%a %U' $T/ev-data/buckets/evplain/notification.json
```

**Check:** `dropped` grew by 1 and the drop is audited once; the three
`fs3_notify_*` series are present for both buckets; the secret count is
0 in both files; the rule sidecar is mode 600.

### 5.6 Throughput

```sh
python3 - <<'PY'
import sys, time, boto3; sys.modules.setdefault("awscrt", None)
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:9700", aws_access_key_id="AKIANASEVENTS001",
                  aws_secret_access_key="nasEventsSecret012345678901234567890", region_name="us-east-1")
t = time.time()
for i in range(500): s3.put_object(Bucket="evplain", Key="burst/%04d" % i, Body=b"x")
print("500 PUTs in %.1f s" % (time.time() - t))
PY
sleep 5; st evplain
```

Repeat the 500 PUTs into a bucket **without** a rule (`s3v mb evnone`
first) for comparison.

**Check:** all 500 events arrive in order (`wc -l` and sequencers on the
build host), and record the PUT rate with and without a rule. The rule
should cost little per PUT (one `write()` under the key's lock, fsync
grouped).

Remove both rules (`adm -X DELETE …/notification`) and check
`$T/ev-data/notify/` is empty. Stop the server.

---

## 6. The SPK and the tile's object browser

Ask the human before installing over an existing fs3 package. Back it up
first (main runbook D6.1), then install as in main runbook D6.2–D6.3,
with authentication on and one throwaway key (`AKIATILETEST0001`, user
`tile`). Keep *Admin API socket* on (the default).

### 6.1 Package plumbing

1. **Settings.** Settings shows *Public host for share links* (empty)
   under the network section and *Server-side encryption keys (SSE-S3)*
   (off) under storage. Tick SSE-S3 and save.
   **Check:**
   ```sh
   sudo stat -c '%a %U %s' /var/packages/fs3/var/sse.keys
   sudo wc -l < /var/packages/fs3/var/sse.keys
   ps -o args= -C fs3 | tr ' ' '\n' | grep -A1 -E 'sse-key-file|admin-socket'
   sudo grep -i 'sse' /var/packages/fs3/var/fs3.log | tail -2
   ```
   `sse.keys` is mode 600, owned by the package user, one line; fs3 runs
   with `--sse-key-file /var/packages/fs3/var/sse.keys` and started
   (`/_health` answers). Untick and save: fs3 restarts **without** the flag and the file
   is left in place (record whether it is).
2. **Who the CGI runs as.** Don't edit the package to find out. While a
   large tile download runs (§6.3), run
   `ps -o user,args -C sh | grep index.cgi` and record the user. The
   browser needs the CGI to reach `admin.sock` (mode 0600, package user;
   fs3 also checks the peer uid). If the bucket table shows bucket links
   (§6.2) the socket is reachable.

### 6.2 Browse

Create bucket `tilebrowse` with any S3 client using the throwaway key,
and put `readme.txt`, `docs/a b.txt`, `docs/é&<>.txt` and
`docs/sub/z.bin` in it.

1. Open the tile. **Check:** the bucket name in the *Buckets* table is a
   link. Click it.
2. **Check:** the listing shows the folder `docs/` and `readme.txt` with
   size and a UTC date; clicking `docs/` shows the breadcrumbs
   `tilebrowse / docs`, `a b.txt`, `é&<>.txt` (rendered literally, not
   as markup) and the folder `sub/`.
3. Not signed in: open the tile URL in a private window. **Check:** 403
   with no listing; same for
   `…/index.cgi?v=browse&b=tilebrowse` and
   `…/index.cgi?v=get&b=tilebrowse&k=readme.txt`.

### 6.3 Downloads

1. Click `é&<>.txt`. **Check:** the browser saves it under that name
   (the UTF-8 filename survives) and the content matches.
2. Put the 1 GB file into the bucket with an S3 client and download it
   through the tile. While it runs, on the NAS:
   ```sh
   for i in $(seq 20); do ps -o user,rss=,pcpu=,args= -C curl,sh,nginx | grep -E 'curl|index.cgi|nginx' ; sleep 2; done
   ```
   **Check:** the MD5 matches; record MB/s, and that the CGI's `curl`
   RSS stays flat (it streams; it must not grow with the file).

### 6.4 Uploads (the main unknown)

Upload through the tile's *Upload* box, into `docs/`, one at a time:
the 100 MB, 1 GB and 4.5 GB files from §2. Watch on the NAS:

```sh
df -h /tmp /var /volume1 | cat
for i in $(seq 60); do ps -o user,rss=,pcpu=,args= -C curl,sh,nginx | grep -E 'curl|index.cgi|nginx'; \
    sudo du -sh /var/tmp/nginx /tmp/nginx 2>/dev/null; sleep 2; done
```

**Check, for each size:**
- the progress text reaches 100% and the page reloads with the object;
  the object's MD5 (download it with an S3 client) matches;
- record the result (`ok`, or the message the page shows, or the HTTP
  status in the browser's network tab, e.g. 413 from nginx);
- record whether nginx **buffers the body to disk first** (a growing
  file under an nginx temp directory, and the CGI's `curl` starting only
  after the browser finished sending), and peak RSS of nginx, `sh` and
  `curl`.

If the 4.5 GB upload fails at nginx, find the smallest size that fails
(bisect: 2 GB, 3 GB, …) and record the nginx limit you found in §2.
This decides whether the README's "up to 5 GiB" needs a DSM caveat or a
different upload path.

Also check the guards from the browser's devtools console (on the tile
page):

```js
fetch(location.pathname + '?a=upload&b=tilebrowse&k=x.txt', {method: 'POST', body: 'x'})
  .then(r => r.text()).then(console.log)          // no token → e_csrf
```

**Check:** `e_csrf`.

### 6.5 Share links

1. **LAN.** Set *Listen address* to `0.0.0.0` (ask the human; it exposes
   plain HTTP on the LAN) and save. Click *Share* (1 h) on `readme.txt`.
   **Check:** the share page shows `http://<the host you opened DSM
   with>:9000/tilebrowse/readme.txt?X-Amz-…`; it downloads from another
   LAN machine with `curl`; the fs3 log has an
   `admin: presign GET bucket tilebrowse key readme.txt` line. Set the
   listen address back to `127.0.0.1`.
2. **No public host.** With the listen address at `127.0.0.1` and
   *Public host for share links* empty, *Share* shows the
   "share links need a public host name" error.
3. **Behind the reverse proxy.** Ask the human for a host name that
   resolves to the NAS (or use the NAS's DSM DDNS name), and a DSM
   reverse-proxy entry `https://<name>:443` → `http://localhost:9000`
   (main runbook D6.7 uses port 9443; for this step the share link
   assumes 443, so either use 443 or record that a non-443 proxy port
   needs `host:port` support). Set *Public host for share links* to the
   name, save, and share `docs/a b.txt` for 1 day.
   **Check:** the link starts `https://<name>/tilebrowse/docs/a%20b.txt?`
   and downloads with `curl` from outside the NAS. If it answers 403
   `SignatureDoesNotMatch`, DSM's proxy changed the `Host` header: record
   the proxy's custom headers and the request fs3 logged (`-v` shows it).
4. **Expiry cap.** Set *Longest presigned URL* to 3600 and try a 7-day
   share. **Check:** the "expiry is longer than … allows" error.

### 6.6 Delete, keys and SSE-S3 through the tile

1. *Delete* `docs/sub/z.bin`. **Check:** "Object deleted." and the row
   is gone.
2. Disable the throwaway key (admin API
   `PATCH /v1/keys/AKIATILETEST0001 {"disabled":true}` over the socket
   with `sudo curl --unix-socket …`). **Check:** *Download*, *Share* and
   *Delete* now report that fs3 has no usable key; re-enable it.
3. With *Server-side encryption keys* on, set default encryption on
   `tilebrowse` (`aws s3api put-bucket-encryption …`), upload a file
   through the tile and download it again. **Check:** the content
   matches and `head-object` reports `ServerSideEncryption: AES256`.

### 6.7 Webhooks with the package

1. Over SSH, put a rule on `tilebrowse` pointing at the plain receiver
   (`sudo curl --unix-socket /var/packages/fs3/var/admin.sock -X PUT …`,
   as in §5.2). Upload a file through the tile. **Check:** the receiver
   logs `ObjectCreated:Put` for it.
2. Stop the receiver, upload two more files, restart the package from
   Package Center, start the receiver. **Check:** both events arrive, in
   order.
3. Remove the rule. **Check:** `<data folder>/notify/` is empty.

---

## 7. Resources and evidence on failure

Record peak RSS, CPU % and thread count of fs3:
- idle, with SSE-S3 on and two notification rules loaded;
- during the encrypted 1 GB transfers (§4.2);
- during the 4.5 GB tile upload (§6.4), together with nginx, `sh` and
  `curl`.

**For any failure, keep:**
- the fs3 log (`sse.log`, `ev.log` or `/var/packages/fs3/var/fs3.log`);
- the notification status JSON, and `ls -la <data>/notify/*/`;
- for the tile: the HTTP status and response body from the browser's
  network tab, the CGI's stderr in DSM's web server log
  (`sudo tail -50 /var/log/nginx/error.log`), and the page source
  around the failing element (never with the CSRF token or a full
  presigned URL);
- `dmesg | tail -20`;
- the exact command that failed.

---

## 8. Clean up

1. Remove every notification rule and stop the standalone servers and
   the receivers. Delete `$T/sse-data`, `$T/ev-data`, `$T/*.log`,
   `$T/hook-ca.pem`, the test files on the NAS and `/tmp/up*.bin` on the
   build host. `shred -u` any test `sse.keys` copy.
2. Delete the `tilebrowse` bucket's objects and the bucket.
3. In the package: untick *Server-side encryption keys* unless the human
   wants it; if it was a test install, `shred -u
   /var/packages/fs3/var/sse.keys` only after the human confirms no
   encrypted data needs it. Clear *Public host for share links*, put the
   listen address back, and set *Longest presigned URL* back to 86400.
4. Remove the reverse-proxy entry if you created one, and set Package
   Center's trust level back.
5. Delete the throwaway key. If you replaced an installed package,
   restore it as in main runbook D6, or keep the new one only if the
   human agrees.

---

## 9. Report template (fill in and return)

```
Commit / PR:        <git rev-parse HEAD> (sse-events-browser / main)
NAS:                DS1515+, DSM <version>-<build> Update <n>, kernel <uname -r>, glibc <x.y>
/bin/sh:            <target>; curl <version>; CPU aes flag: yes/no; openssl aes-256-gcm <MB/s>
nginx limits:       <client_max_body_size / buffering lines from §2>
§3 suites on NAS:   test_ssekeys <n/n>; test_notify <n/n>; sse_s3 <n/n>; notify <n/n>; admin <n/n>;
                    subresources <n/n>; ui_cgi <n/n>; spk_scripts <n/n>; skips: <…>
§4 SSE-S3:          0644 key file refused: PASS/FAIL; key loaded + seccomp enforce: PASS/FAIL
                    1 GB plain up/down <MB/s>/<MB/s>; encrypted up/down <MB/s>/<MB/s>
                    ETags equal: PASS/FAIL; ciphertext on disk: PASS/FAIL; peak CPU <%> RSS <MB>
                    rotation add accepted / remove refused / change refused: PASS/FAIL ×3
                    readable after kill -9: PASS/FAIL
§5 webhooks:        plain http LAN + HMAC: PASS/FAIL; public plain host refused: PASS/FAIL
                    https + --repl-ca-file: PASS/FAIL; without CA → cert error, kept: PASS/FAIL
                    503 retry + outage + kill -9: in order, no duplicates: PASS/FAIL; drain <s>
                    4xx dropped + audited: PASS/FAIL; metrics: PASS/FAIL; secret absent: PASS/FAIL
                    500 PUTs: <s> with rule, <s> without; all 500 delivered in order: PASS/FAIL
§6 SPK / tile:      SSE-S3 setting → sse.keys <mode owner lines>, flag passed: PASS/FAIL; untick → file <kept/removed>
                    CGI runs as <user>; socket reachable: yes/no
                    browse + escaping: PASS/FAIL; not signed in → 403 (3 URLs): PASS/FAIL
                    download UTF-8 name: PASS/FAIL; 1 GB download <MB/s>, curl RSS flat: yes/no
                    upload 100 MB: <ok/err>; 1 GB: <ok/err>; 4.5 GB: <ok/err>; smallest failing size: <…>
                    nginx buffers body to disk: yes/no (<where>); peak RSS nginx/sh/curl <MB>
                    no-token upload → e_csrf: PASS/FAIL
                    share LAN: PASS/FAIL; no public host → error: PASS/FAIL
                    share via reverse proxy: PASS/FAIL (<Host header notes>); expiry cap: PASS/FAIL
                    delete: PASS/FAIL; disabled key → no-usable-key: PASS/FAIL; SSE-S3 via tile: PASS/FAIL
                    webhook via package + survives restart: PASS/FAIL
§7 resources:       fs3 idle <MB>; during encrypted 1 GB <MB>/<%>; during tile upload fs3/nginx/sh/curl <MB>
Code changes needed: <e.g. upload path limited by nginx at <size>; Host rewritten by the proxy; syscall to add>
Open issues:        <bugs: exact commands, logs, expected vs actual>
Cleanup:            rules removed / scratch deleted / test keys shredded / settings restored: yes/no
```
