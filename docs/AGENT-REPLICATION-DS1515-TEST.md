# Agent runbook: bucket replication on the DS1515+

This runbook is for an autonomous agent. It is the hardware exit check
for bucket replication (item 2 of `docs/plan-logs-replication-compat.md`,
phase d). The development host already passed every suite. This run
answers what only the NAS can:

1. **CA bundle:** where DSM keeps its CA bundle, and whether the static
   TLS build finds it without `--repl-ca-file`.
2. **DNS under seccomp:** whether resolving a real host name (B2 or AWS)
   works with the seccomp filter enforcing, on DSM's kernel and glibc.
3. **Real targets:** whether replication to a real cloud target and to a
   LAN target works end to end, including multipart, metadata, deletes,
   backfill, an outage, a crash and the self-healing scrub.
4. **The package:** whether the SPK's replication settings, the tile's
   Replication section and `repl-ca.pem` work on DSM.
5. **Resources:** what replication costs on an Atom C2538 with 2 GB of RAM.

Work through the sections in order. Every step has a **Check**: record
the result in the report template (§9), together with the evidence each
step tells you to keep. Wherever this file says "record", copy the
command output into the report verbatim.

This file builds on `docs/AGENT-BUILD-AND-DS1515-TEST.md` (called "the
main runbook" below). Its ground rules (§0), target facts (§1), access
steps (D0), troubleshooting (§2) and NAS build procedure (Part B) all
apply here.

---

## 0. Ground rules

1. **Scratch only.** Use `/volume1/fs3-test` on the NAS and a dedicated,
   empty bucket on every target. Never point a rule at a bucket that
   holds real data: deletes replicate unless `deletes` is false.
2. **Throwaway cloud credentials.** Ask the human for a B2 (or AWS)
   application key that is limited to the scratch bucket. Keep it out of
   the report, out of shell history (put `HISTCONTROL=ignorespace` in
   the environment and prefix those commands with a space) and out of
   any committed file. §8 deletes the key's uploads; tell the human to
   revoke the key afterwards.
3. **Ask the human before:**
   - installing the SPK over an existing fs3 installation (back it up
     first, as in main runbook D6.1);
   - changing DSM settings;
   - uploading more than about 2 GB to a paid target.
4. **A failing check is a finding, not an obstacle.** Don't weaken a
   test or skip a step to get past it. Collect the logs that §7 lists
   and carry on with the next independent step.
5. **Never paste a secret into a GitHub issue or PR.** The fs3 log and
   audit log should never contain one; §6.4 checks exactly that.

---

## 1. What you need

| item | how to get it |
|---|---|
| Binaries from the `replication` branch (PR #11) or from `main` after it merges | Main runbook Part B: `fs3-tls-static`, `fs3-lockd-static` built against glibc ≤ the NAS's. Record `git rev-parse HEAD`. |
| The SPK built from the same commit | Main runbook Part C (`build-spk.sh` now packages `fs3-tls-static` and refuses a non-TLS binary). |
| A **cloud target** | Preferably a Backblaze B2 bucket in a region the human picks; AWS S3 also works. Get from the human: endpoint URL, region, bucket name, key id, application key. |
| A **LAN target** | A second fs3 on the build host (or any LAN machine) reachable from the NAS. §1.2 sets it up. |
| On the NAS | SSH access as an administrator, Python 3 with `tests/requirements.txt` installed, the `make` shim and the repository tree at `/volume1/fs3-test/fs3` (main runbook D5 steps 1–3). |
| On the build host | `aws` CLI (to inspect the cloud bucket), `openssl`, `curl`. |

Variables used below:

```sh
export NAS=192.168.1.3                 # the NAS's LAN IP
export HOSTIP=<build host LAN IP>      # where the LAN replica runs
export T=/volume1/fs3-test             # on the NAS
# Cloud target (from the human; set them with a leading space)
 export CEP=https://s3.<region>.backblazeb2.com CREG=<region> CBK=<bucket> CAK=<key id> CSK=<application key>
```

### 1.1 Check the binary on the NAS

```sh
cd $T && ./fs3-tls --build-info
strings fs3-tls | grep -m3 -E 'OPENSSLDIR|OpenSSL [0-9]'
```

**Check:** the output includes `tls=yes`. Record both outputs: OPENSSLDIR
is where the static OpenSSL looks for CA certificates by default.

### 1.2 Start the LAN replica (on the build host)

Use a private CA, so you can test `--repl-ca-file`:

```sh
mkdir -p ~/repl-lan && cd ~/repl-lan
printf '[req]\ndistinguished_name=dn\nx509_extensions=v3_ca\n[dn]\n[v3_ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' > ca.cnf
openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj "/CN=fs3 LAN test CA" -config ca.cnf -keyout ca.key -out ca.pem
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=lan-replica" -keyout srv.key -out srv.csr
printf "subjectAltName=IP:$HOSTIP\nextendedKeyUsage=serverAuth\n" > srv.ext
openssl x509 -req -in srv.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 7 -extfile srv.ext -out srv.crt
chmod 600 srv.key
~/src/fs3/fs3-tls -a 0.0.0.0 -p 9400 -d ~/repl-lan/data --auth AKIALANREPLICA01:lanReplicaSecret0123456789012345678 \
    --require-auth --tls-port 9443 --tls-cert srv.crt --tls-key srv.key --admin-socket ~/repl-lan/admin.sock \
    > lan.log 2>&1 &
python3 - <<'PY'
import boto3; s3=boto3.client("s3",endpoint_url="http://127.0.0.1:9400",aws_access_key_id="AKIALANREPLICA01",
  aws_secret_access_key="lanReplicaSecret0123456789012345678",region_name="us-east-1")
s3.create_bucket(Bucket="nas-copy"); print("ok")
PY
scp -O ca.pem admin@$NAS:$T/lan-ca.pem
```

Open ports 9400 and 9443 in the build host's firewall for the NAS only.
**Check:** from the NAS, `curl -s http://$HOSTIP:9400/health` answers.

---

## 2. Facts to collect first (no fs3 running)

Run these on the NAS and record every output. They answer questions 1
and 2 before you test anything.

```sh
cat /etc.defaults/VERSION | grep -E 'productversion|buildnumber|smallfixnumber'
uname -r
ldd --version 2>&1 | head -1
# CA bundles that exist on DSM
for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem \
         /usr/syno/etc/ssl/ca-bundle.crt /etc/ssl/certs/ca-bundle.crt; do
  [ -e "$f" ] && echo "EXISTS $f $(grep -c 'BEGIN CERTIFICATE' "$f") certs $(readlink -f "$f")"; done
ls -la /etc/ssl/certs | head -20
find / -xdev \( -name 'ca-certificates.crt' -o -name 'ca-bundle*.crt' -o -name 'cacert.pem' \) 2>/dev/null | head
# Does the bundle verify the cloud endpoint?
openssl version
echo | openssl s_client -connect ${CEP#https://}:443 -servername ${CEP#https://} 2>/dev/null | grep -E 'Verify return code|subject=|issuer='
# Name resolution path
cat /etc/nsswitch.conf | grep -E '^hosts'
cat /etc/resolv.conf
ls /lib/libnss_dns* /lib64/libnss_dns* /usr/lib/libnss_dns* 2>/dev/null
getent hosts ${CEP#https://} || nslookup ${CEP#https://}
```

fs3's TLS client calls `SSL_CTX_set_default_verify_paths()` (which uses
the OPENSSLDIR recorded in §1.1). It then also tries, in order:
`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`
and `/etc/ssl/cert.pem`.

**Check:** record which of these exist. If none of them exists but
another bundle turned up in the `find` output, that is the key finding of
this run. Report its path: it must be added to the list in
`tls_setup_ctx()` in `src/s3client.c`.

---

## 3. Outbound client on the NAS (the repository suites)

Run the two replication suites on the NAS. They exercise the real
kernel, glibc and Btrfs, with loopback targets only.

```sh
cd $T/fs3
export PATH=$HOME/bin:$HOME/.local/bin:$PATH      # make shim + pip --user
cp ../fs3-tls ./fs3-tls                            # prebuilt NAS binaries (Part B)
# s3c_cli is a test driver: build it in the Part B environment
# (same glibc) and copy it to tests/s3c_cli and tests/s3c_cli_tls:
#   make tests/s3c_cli tests/s3c_cli_tls   (inside the Part B container)
./tests/test_e2e_s3client.sh 2>&1 | tail -3
df -h /tmp
./tests/test_e2e_repl.sh 2>&1 | tail -3
```

`test_e2e_repl.sh` starts two `fs3-tls` instances on loopback and writes
about 40 MB under `/tmp`.

**Check:** both suites end with `passed, 0 failed`. If a check fails,
rerun the suite with `bash -x` and keep the output. If a server died
with SIGSYS (a `FAIL: server died with SIGSYS` line, or exit 159),
follow main runbook D3 to find the syscall.

---

## 4. Standalone replication to the cloud target (seccomp log, then enforce)

### 4.1 Start a source fs3 in seccomp **log** mode

```sh
cd $T && rm -rf src-data && mkdir src-data
./fs3-tls -a 127.0.0.1 -p 9300 -d $T/src-data --auth AKIANASSOURCE001:nasSourceSecret0123456789012345678:tester \
    --require-auth --metrics-port 9301 --admin-socket $T/admin.sock --audit-log $T/audit.log \
    --seccomp=log --scrub-interval-days 0 > src.log 2>&1 &
echo $! > src.pid; sleep 1; grep -E 'seccomp|replication|listening' src.log
```

**Check:** the log shows a `replication: 2 worker(s)` line and
`seccomp: filter installed (… mode log)`.

Helper functions for the rest of the run:

```sh
adm() { curl -sS --unix-socket $T/admin.sock "$@"; }
s3s() { python3 - "$@" <<'PY'
import sys, boto3; sys.modules.setdefault("awscrt", None)
s3 = boto3.client("s3", endpoint_url="http://127.0.0.1:9300", aws_access_key_id="AKIANASSOURCE001",
                  aws_secret_access_key="nasSourceSecret0123456789012345678", region_name="us-east-1")
cmd, *a = sys.argv[1:]
if cmd == "mb": s3.create_bucket(Bucket=a[0])
elif cmd == "put": s3.put_object(Bucket=a[0], Key=a[1], Body=open(a[2], "rb"), ContentType="application/x-fs3-test",
                                 Metadata={"origin": "ds1515"})
elif cmd == "rm": s3.delete_object(Bucket=a[0], Key=a[1])
print("ok")
PY
}
st() { adm http://x/v1/buckets/$1/replication/status | python3 -m json.tool; }
```

### 4.2 Point a bucket at the cloud target by **host name**

```sh
s3s mb photos
 adm -X PUT http://x/v1/buckets/photos/replication --data \
  "{\"endpoint\":\"$CEP\",\"region\":\"$CREG\",\"bucket\":\"$CBK\",\"access_key\":\"$CAK\",\"secret_key\":\"$CSK\",\"deletes\":false}"
head -c 1048576 /dev/urandom > /tmp/one.bin
s3s put photos small/one.bin /tmp/one.bin
sleep 5; st photos
grep -E 'seccomp: blocked|replication' src.log
```

**Check:**
- `status` shows `"replicated": 1`, `"queue": 0` and an empty
  `last_error`.
- `src.log` contains no `seccomp: blocked syscall` line.
- If `last_error` mentions `certificate`, the CA bundle was not found:
  record the message and go to §4.3.
- If `last_error` mentions `resolve`, record the message. Then try an IP
  literal from `getent hosts` as the endpoint (that changes TLS name
  checks, so note it), and report the failure.

On the build host, confirm the object arrived:

```sh
 AWS_ACCESS_KEY_ID=$CAK AWS_SECRET_ACCESS_KEY=$CSK aws --endpoint-url $CEP --region $CREG \
    s3api head-object --bucket $CBK --key small/one.bin
```

**Check:** `ContentLength` is 1048576 and `ContentType` is
`application/x-fs3-test`. `Metadata` holds `origin: ds1515` and an
`fs3-source-etag` equal to the MD5 of `/tmp/one.bin`
(`md5sum /tmp/one.bin` on the NAS).

### 4.3 If certificates failed: find the bundle that works

Repeat §4.1 with `--repl-ca-file <bundle>` for each bundle that §2
found, re-PUT the rule, and redo §4.2. Record which bundle works. This
tells us which path to add to `tls_setup_ctx()`.

### 4.4 Enforce mode

Stop the server (`kill $(cat src.pid)`) and start it again with the same
command **without** `--seccomp=log`. Then:

```sh
s3s put photos small/two.bin /tmp/one.bin; sleep 5; st photos
kill -0 $(cat src.pid) && echo alive
```

**Check:** `replicated` went up by one and the server is alive. If it
died, `dmesg | tail` should show a SIGSYS audit line: record it, map the
syscall (main runbook D3), and report it.

### 4.5 Multipart, deletes and rate

```sh
head -c 100000000 /dev/urandom > $T/big.bin      # 100 MB > 4 x 16 MiB → multipart
date +%s > /tmp/t0; s3s put photos big/100m.bin $T/big.bin
until [ "$(adm http://x/v1/buckets/photos/replication/status | python3 -c 'import sys,json;print(json.load(sys.stdin)["queue"])')" = 0 ]; do sleep 2; done
echo "seconds: $(( $(date +%s) - $(cat /tmp/t0) ))"
s3s rm photos small/one.bin; sleep 5; st photos
```

On the build host:

```sh
 AWS_ACCESS_KEY_ID=$CAK AWS_SECRET_ACCESS_KEY=$CSK aws --endpoint-url $CEP --region $CREG \
    s3api head-object --bucket $CBK --key big/100m.bin
 AWS_ACCESS_KEY_ID=$CAK AWS_SECRET_ACCESS_KEY=$CSK aws --endpoint-url $CEP --region $CREG \
    s3api head-object --bucket $CBK --key small/one.bin
```

**Check:**
- `big/100m.bin` has `ContentLength` 100000000 and an ETag ending in
  `-6` (100 MB in 16 MiB parts).
- `small/one.bin` still exists on the target (`deletes: false`).
- The elapsed time is at least 5 s: the default `--repl-rate` is 20 MiB/s
  (100 MB takes ≥ 4.8 s), unless the uplink is slower.

Record the time and the uplink speed the human expects. Download the big
object on the build host and compare MD5s with `$T/big.bin`.

### 4.6 Backfill

```sh
s3s mb archive
for i in 1 2 3; do s3s put archive old/$i.bin /tmp/one.bin; done        # before the rule
 adm -X PUT http://x/v1/buckets/archive/replication --data \
  "{\"endpoint\":\"$CEP\",\"region\":\"$CREG\",\"bucket\":\"$CBK\",\"access_key\":\"$CAK\",\"secret_key\":\"$CSK\",\"prefix\":\"old/\",\"deletes\":false}"
sleep 3; st archive                                          # replicated 0: a new rule copies nothing old
adm -X POST http://x/v1/buckets/archive/replication/sync; sleep 10; st archive
```

**Check:**
- Before the sync: `replicated` is 0.
- After the sync: `backfill.queued` is 3, `replicated` is 3 and
  `backfill.done` is non-zero.
- A second `sync` queues 0: the objects match (via `fs3-source-etag` /
  ETag).

---

## 5. LAN target over https with a private CA, outage and crash

### 5.1 Rule with `--repl-ca-file`

Restart the source with `--repl-ca-file $T/lan-ca.pem` (keep the other
flags). Then:

```sh
s3s mb lan
adm -X PUT http://x/v1/buckets/lan/replication --data \
  "{\"endpoint\":\"https://$HOSTIP:9443\",\"bucket\":\"nas-copy\",\"access_key\":\"AKIALANREPLICA01\",\"secret_key\":\"lanReplicaSecret0123456789012345678\"}"
s3s put lan a.bin /tmp/one.bin; sleep 3; st lan
```

**Check:** `replicated` is 1. Restart without `--repl-ca-file` and put
another object. `last_error` must now mention a certificate failure and
`queue` must stay at 1 (the record is kept). Restart with the flag again:
the queue drains.

### 5.2 Outage

Stop the LAN replica on the build host (`kill %1`, or its pid). Then on
the NAS:

```sh
for i in $(seq 1 30); do s3s put lan hot.bin /tmp/one.bin; done
s3s put lan while-down.bin /tmp/one.bin
sleep 3; st lan                      # queue > 0, last_error "connect … refused"
```

Start the LAN replica again with the same command as in §1.2. Within
about 60 s (the backoff doubles from 1 s):

**Check:** `queue` returns to 0. `replicated` rose by only 2 or 3: the
30 overwrites were coalesced. `curl -s http://127.0.0.1:9301/metrics |
grep fs3_repl_` shows `fs3_repl_queue_depth{bucket="lan"} 0`.

### 5.3 Crash recovery

First stop the LAN replica again on the build host, so the records stay
queued. Then on the NAS:

```sh
for i in 1 2 3; do s3s put lan crash$i.bin /tmp/one.bin; done
kill -9 $(cat src.pid)
ls -la $T/src-data/repl/*/          # one directory per replicated bucket (named by bucket id)
```

Restart the source (same flags), then start the LAN replica.

**Check:**
- No `clean` file existed in the bucket's `repl/<id>/` directory after
  the kill.
- The startup log says `recovery scan pending`, then `recovery scan done`.
- `crash1..3.bin` reach the replica.

Then stop the source normally (`kill`, not `-9`). **Check:** the `clean`
marker now exists, and after the next start it is gone again.

### 5.4 Self-healing scrub (Btrfs)

```sh
python3 -c 'print("healme-payload-" * 4000)' > /tmp/heal.txt
s3s put lan heal.txt /tmp/heal.txt; sleep 3
F=$(grep -rl healme-payload $T/src-data/data/lan | head -1)
python3 - "$F" <<'PY'
import sys; p=sys.argv[1]; b=bytearray(open(p,"rb").read()); i=b.index(b"healme-payload")+3; b[i]^=0x20; open(p,"r+b").write(b)
PY
adm -X POST http://x/v1/scrub; sleep 10; adm http://x/v1/scrub
tail -3 $T/src-data/scrub/corrupt.log
```

**Check:**
- The scrub status shows `"repaired": 1`.
- `corrupt.log` has a line with `"repaired":true` for `heal.txt`.
- Downloading `heal.txt` from the source gives back `/tmp/heal.txt`
  byte for byte.
- The audit log has a `repaired bucket=lan key=heal.txt` event.

---

## 6. The SPK and the tile

Ask the human before installing over an existing fs3 package. Back it up
first (main runbook D6.1), then install as in main runbook D6.2–D6.3.

1. **Settings.** In the tile: Settings → *Replication* shows *Replication
   threads* (2), *Replication upload rate* (20M) and *Replication timeout*
   (30). Under *Logging and hardening*, *Admin API socket* is ticked.
   **Check:** `ps -o args= -C fs3 | tr ' ' '\n' | grep -A1 -E 'admin-socket|repl-'`
   shows `--admin-socket /var/packages/fs3/var/admin.sock`, and no
   `--repl-` flags at the defaults.
2. **Rule from the tile.** Create bucket `tilebk` with any S3 client.
   In the tile's *Replication* section, fill in the form for the cloud
   target (bucket here `tilebk`, prefix empty, "Also delete on the target"
   unticked) and save. **Check:** the message says the rule was saved,
   the table lists `tilebk` with the target, and the page source contains
   no secret.
3. **Status in the tile.** Upload an object to `tilebk`, reload the page.
   **Check:** queued drops to 0 and the object is on the target. Press
   *Sync*: the message says the backfill started.
4. **Secret hygiene.**
   ```sh
   sudo grep -c "$CSK" /var/packages/fs3/var/fs3.log /var/packages/fs3/var/fs3.start.log \
        /var/packages/fs3/var/audit.log 2>/dev/null
   sudo stat -c '%a %U' <data folder>/buckets/tilebk/replication.json
   ```
   **Check:** every count is 0, and the sidecar is mode `600` owned by
   the package user.
5. **`repl-ca.pem`.** Copy `lan-ca.pem` to
   `/var/packages/fs3/var/repl-ca.pem` (owner: the package user, mode
   0644). Restart the package from the tile. **Check:** `ps` shows
   `--repl-ca-file /var/packages/fs3/var/repl-ca.pem`, and a tile rule to
   `https://$HOSTIP:9443` (bucket `nas-copy`) replicates.
6. **Persistence.** Stop the LAN replica, put three objects into the
   LAN-replicated bucket, and restart the package. Start the LAN replica
   again. **Check:** the queue survives the restart and drains.
7. **Remove.** Press *Remove* on each rule. **Check:** the rows
   disappear, and `<data folder>/repl/` is empty.
8. **Turned off.** Set *Replication threads* to 0 and save. **Check:**
   the tile says replication is off, and a rule PUT through the socket
   answers 501. Set it back to 2.

---

## 7. Resources and evidence on failure

**During §4.5** (the 100 MB multipart upload), sample once a second from
a second SSH session:

```sh
PID=$(cat $T/src.pid)    # or: pgrep -f 'fs3-tls|/fs3 '
for i in $(seq 30); do ps -o rss=,pcpu=,nlwp= -p $PID; sleep 1; done
```

**Check:** record the peak RSS in MB, the CPU % and the thread count.
Replication should add well under 10 MB of RSS (64 KiB buffers per
worker), and its CPU use should track the TLS throughput.

**For any failure, keep:**
- the fs3 log (`src.log` or `/var/packages/fs3/var/fs3.log`);
- the bucket's status JSON;
- `ls -la <data>/repl/*/` and `xxd <data>/repl/<id>/queue | head`;
- `dmesg | tail -20`;
- the exact command that failed.

Never include a secret.

---

## 8. Clean up

1. **Remove the rules.** Remove every rule (`adm -X DELETE …/replication`,
   or *Remove* in the tile).
2. **Stop the test servers.** Stop the standalone source and the LAN
   replica, and delete `$T/src-data`, `~/repl-lan` and `/tmp/*.bin`.
3. **Empty the cloud bucket.** Delete the test objects, including the
   versions if versioning is on there:
   ```sh
    AWS_ACCESS_KEY_ID=$CAK AWS_SECRET_ACCESS_KEY=$CSK aws --endpoint-url $CEP --region $CREG \
       s3 rm s3://$CBK --recursive
   ```
   On B2, also list hidden file versions and delete them, or ask the
   human to empty the bucket in the B2 console.
4. **Revoke the key.** Tell the human to revoke the application key.
5. **Restore the package.** If you replaced an installed package,
   restore it as in main runbook D6, or leave the new one only if the
   human agrees.

---

## 9. Report template (fill in and return)

```
Commit / PR:        <git rev-parse HEAD> (replication branch / main)
NAS:                DS1515+, DSM <version>-<build> Update <n>, kernel <uname -r>, glibc <x.y>
Binary:             fs3-tls sha256 <…>; --build-info: <…>; OPENSSLDIR: <…>; OpenSSL <version>
CA bundles on DSM:  <path: exists/cert count, for each path checked in §2>; extra found: <…>
Default CA lookup:  cloud endpoint verified without --repl-ca-file: yes/no (<error if no>)
                    working bundle if not: <path>
DNS under seccomp:  host-name endpoint resolved in log mode: yes/no; blocked syscalls: <none | numbers+names>
                    enforce mode alive after replication: yes/no
§3 suites on NAS:   test_e2e_s3client <n passed/failed>; test_e2e_repl <n passed/failed>; skips: <…>
§4 cloud target:    provider <B2/AWS>, region <…>
                    single PUT + metadata + fs3-source-etag: PASS/FAIL
                    100 MB multipart (ETag -6, MD5 match): PASS/FAIL; seconds <n>; uplink <Mbit/s>
                    deletes:false keeps target copy: PASS/FAIL
                    backfill queued 3 / second sync queued 0: PASS/FAIL
§5 LAN target:      https + --repl-ca-file: PASS/FAIL; without CA → certificate error, record kept: PASS/FAIL
                    outage: drained in <s>, uploads for 31 changes: <n>
                    kill -9 recovery scan: PASS/FAIL; clean marker behaviour: PASS/FAIL
                    self-healing scrub: PASS/FAIL
§6 SPK / tile:      settings shown: PASS/FAIL; admin socket default on: PASS/FAIL
                    rule via tile: PASS/FAIL; status/sync: PASS/FAIL; secret absent from logs+page: PASS/FAIL
                    sidecar mode/owner: <…>; repl-ca.pem picked up: PASS/FAIL
                    queue survives package restart: PASS/FAIL; remove: PASS/FAIL; threads=0 → 501: PASS/FAIL
§7 resources:       peak RSS <MB> (idle <MB>), CPU <%>, threads <n> during 100 MB upload
Code changes needed: <e.g. CA path to add to tls_setup_ctx(), syscall to add to ALLOW[], with evidence>
Open issues:        <bugs: exact commands, logs, expected vs actual>
Cleanup:            rules removed / scratch deleted / cloud bucket emptied / key revocation requested: yes/no
```
