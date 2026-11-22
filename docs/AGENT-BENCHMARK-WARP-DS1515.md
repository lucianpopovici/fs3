# Agent runbook: baseline benchmarks of fs3 on the DS1515+ with warp

This runbook is for an autonomous agent. It records a **baseline**:
how fast fs3 is on the DS1515+ *before* any performance work, measured
with MinIO's S3 benchmark tool [warp](https://github.com/minio/warp).
Nothing in this run changes fs3's code or settings to make it faster.
Its job is to produce numbers that later work can be compared against
(`warp cmp before after`), and evidence of where the time goes:

1. **Ceilings:** what the network, the disks and the CPU can do on
   their own, so fs3's numbers can be read as a fraction of the hardware.
2. **Throughput and latency** per operation (PUT, GET, HEAD, LIST,
   DELETE, multipart, mixed) across object sizes and concurrency, from
   the LAN and from the NAS itself.
3. **Where it saturates:** for each headline run, whether the limit is
   the 1 GbE link, the disks, fs3's event-loop thread, its I/O workers,
   or the client.
4. **Feature costs:** what TLS, SSE-S3, versioning, the DSM reverse
   proxy, payload hashing and a webhook rule cost on top of plain HTTP.

Work through the sections in order. Every step has a **Check**: record
the result in the report (§10), together with the evidence each step
tells you to keep. Wherever this file says "record", copy the output
into the report verbatim.

This file builds on `docs/AGENT-BUILD-AND-DS1515-TEST.md` (called "the
main runbook" below). Its ground rules (§0), target facts (§1), access
steps (D0), troubleshooting (§2) and NAS build procedure (Part B) all
apply here.

---

## 0. Ground rules

1. **Baseline only.** Use the binary from one commit, record it, and
   don't change fs3's code, defaults or the DSM tuning during the run. If
   you notice an obvious improvement, write it under "Observations" in
   the report; don't apply it.
2. **Scratch only.** warp deletes everything in its bucket before and
   after a run. Run a dedicated fs3 on a dedicated data folder
   (`/volume1/fs3-bench/data`) with a dedicated bucket (`warp-bench`).
   Never point warp at the package's data folder or at a bucket with
   real data.
3. **Quiet machine.** Benchmarks on a busy NAS measure the noise. Ask
   the human to pause, for the duration of the run: Btrfs data
   scrubbing and RAID consistency checks, Hyper Backup and Snapshot
   Replication schedules, Synology Photos/Drive indexing, antivirus
   scans, and other packages that use the volume. Record what was
   paused and what couldn't be.
4. **Ask the human before:** changing DSM settings, stopping packages,
   or running anything that writes more than about 100 GB in total (the
   full matrix below writes roughly 150–250 GB over its lifetime but
   keeps at most about 20 GB on disk at a time; check §2's free space).
5. **Same conditions every run.** Same client machine, same cable and
   switch port, same fs3 flags (§3.1) unless a step says otherwise. Run
   each headline workload three times and report the median; record
   the spread.
6. **Errors are results.** Any warp error (non-zero "errors" in its
   output, timeouts, connection resets) is a finding: keep the
   `.csv.zst` and fs3's log, and carry on.
7. **Secrets.** The benchmark key is throwaway; still, keep it out of
   the report and out of committed files.

---

## 1. What you need

| item | how to get it |
|---|---|
| Binaries from one commit of `main` | Main runbook Part B: `fs3-tls-static` built against glibc ≤ the NAS's. Record `git rev-parse HEAD` and `fs3-tls --build-info`. |
| warp, one pinned release, on the client and on the NAS | Download the latest `warp_Linux_x86_64.tar.gz` from the release page, check the published checksum, record the version (`warp --version`). Use the same version for every run and keep it for the "after" runs. It is a static Go binary and runs on DSM as is. |
| A client machine on the same switch as the NAS | Wired gigabit or faster, nothing else heavy running. Record its CPU, RAM, NIC and OS. Ideally the build host. |
| iperf3 | On the client; on the NAS from a static build if DSM lacks it (ask the human, or skip §2.2's iperf step and use the `nc` fallback). |
| On the NAS | SSH as an administrator, `/volume1/fs3-bench` with enough free space (§2.4), Python 3 (for the sampler, §4). |

Variables used below:

```sh
export NAS=192.168.1.3                    # the NAS's LAN IP
export B=/volume1/fs3-bench               # on the NAS
export WARP_ACCESS_KEY=AKIABENCHWARP001
export WARP_SECRET_KEY=benchWarpSecret01234567890123456789
export WARP_REGION=us-east-1
```

Common warp flags for every run (shell variable on both machines):

```sh
W="--lookup path --bucket warp-bench --region us-east-1"
```

Path-style lookup matches how fs3 is reached by IP. Name each result
file with `--benchdata` as `<section>-<workload>-<size>-c<conc>-r<rep>`
so the report can point at it.

---

## 2. Hardware ceilings (no fs3 running)

### 2.1 Machine facts

```sh
# on the NAS
cat /etc.defaults/VERSION | grep -E 'productversion|buildnumber|smallfixnumber'
uname -r; nproc; grep -m1 'model name' /proc/cpuinfo; free -m
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null
for i in /sys/class/net/eth*; do echo "$i $(cat $i/speed 2>/dev/null) Mb/s $(cat $i/operstate)"; done
cat /proc/mdstat
df -hT /volume1
sudo btrfs filesystem usage /volume1 2>/dev/null | head -12
sudo synodisk --enum 2>/dev/null | grep -E 'Disk path|Model|Size' || ls /sys/block | grep -E '^sd'
mount | grep ' /volume1 '
```

**Check:** record all of it: DSM version, CPU (Atom C2538, 4 cores),
RAM, governor, link speeds (which port the client uses, any bond), RAID
level and disks, filesystem (Btrfs or ext4), mount options (compression,
`nodatacow`), and the volume's fill level. Fill level and RAID level
change write speed a lot; a rerun on a different fill level is not
comparable.

### 2.2 Network

```sh
# on the NAS
iperf3 -s -1 &
# on the client
iperf3 -c $NAS -t 20; iperf3 -c $NAS -t 20 -R; iperf3 -c $NAS -t 20 -P 4
```

Fallback without iperf3 on the NAS: `nc -l -p 5001 > /dev/null` on the
NAS and `dd if=/dev/zero bs=1M count=4000 | nc -q1 $NAS 5001` on the
client (time it), and the reverse direction.

Also the round-trip time: `ping -c 20 $NAS` from the client.

**Check:** record MB/s in each direction and the RTT. On 1 GbE expect
about 110–117 MB/s. This is the ceiling for every LAN run below.

### 2.3 Disks

```sh
cd $B
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
dd if=/dev/zero of=$B/dd.bin bs=1M count=8192 conv=fdatasync 2>&1 | tail -1     # sequential write
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
dd if=$B/dd.bin of=/dev/null bs=1M 2>&1 | tail -1                                # sequential read
rm -f $B/dd.bin
# small files with fsync: what a 4 KiB PUT costs at the filesystem level
python3 - "$B" <<'PY'
import os, sys, time
d = os.path.join(sys.argv[1], "smallfiles"); os.makedirs(d, exist_ok=True)
buf = os.urandom(4096); n = 2000; t = time.time()
for i in range(n):
    p = os.path.join(d, "f%05d" % i); tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.write(fd, buf); os.fsync(fd); os.close(fd); os.rename(tmp, p)
    dfd = os.open(d, os.O_RDONLY); os.fsync(dfd); os.close(dfd)
dt = time.time() - t
print("%d create+fsync+rename+fsync(dir): %.1f/s, %.2f ms each" % (n, n / dt, 1000 * dt / n))
for f in os.listdir(d): os.unlink(os.path.join(d, f))
os.rmdir(d)
PY
```

If `fio` is available (from a static build), also run a 4 KiB random
read and write job with `--direct=1 --iodepth=16 --runtime=30`; it's
optional.

**Check:** record sequential write and read MB/s and the small-file
rate. fs3's 4 KiB PUT rate can't exceed the small-file rate by much,
since every PUT does that sequence (tmp file, fsync, rename, fsync of
the directory).

### 2.4 Space and temperature

```sh
df -h /volume1
cat /sys/class/hwmon/hwmon*/temp*_input 2>/dev/null | head; sudo syno_hdd_util --temperature 2>/dev/null | head
```

**Check:** at least 40 GB free on `/volume1` (the largest working set
below is about 20 GB, plus headroom). Record the temperatures now and
again at the end; note any throttling.

---

## 3. The fs3 under test

### 3.1 Standard instance

```sh
cd $B && rm -rf data && mkdir data
cp ../fs3-test/fs3-tls ./fs3-tls 2>/dev/null || true     # or wherever Part B put it
./fs3-tls --build-info
./fs3-tls -a 0.0.0.0 -p 9300 -d $B/data \
    --auth "$WARP_ACCESS_KEY:$WARP_SECRET_KEY:bench" --require-auth \
    --metrics-port 9301 --admin-socket $B/admin.sock \
    --scrub-interval-days 0 --lifecycle-hour -1 --repl-workers 0 \
    --log-file $B/fs3.log > $B/fs3.stderr 2>&1 &
echo $! > $B/fs3.pid; sleep 1
curl -s 127.0.0.1:9300/_health; grep -E 'seccomp|listening|reflink' $B/fs3.log
```

Everything else stays at fs3's defaults (`--io-threads 4`, seccomp
enforce, `--max-conns 512`, `--idle-timeout 60`). Background jobs are
off so they can't run in the middle of a measurement. Record the full
command line in the report.

**Check:** `/_health` answers; the log shows seccomp enforce.

Restart fs3 (same command) before each section, so one section's open
files and caches don't carry into the next. Record fs3's RSS right
after each start.

### 3.2 Which payload mode warp uses

minio-go (inside warp) signs plain-HTTP uploads with streaming chunked
SigV4 by default; `--disable-sha256-payload` switches it to
`UNSIGNED-PAYLOAD`. Confirm what fs3 actually receives:

```sh
# on the NAS, while a short warp put runs from the client
sudo timeout 15 tcpdump -i any -A -s 2000 -c 200 'tcp dst port 9300' 2>/dev/null \
    | grep -i -m3 -E 'x-amz-content-sha256|content-encoding'
# on the client, at the same time
warp put $W --host $NAS:9300 --obj.size 1MiB --concurrent 4 --duration 10s --benchdata probe-default
warp put $W --host $NAS:9300 --obj.size 1MiB --concurrent 4 --duration 10s --disable-sha256-payload --benchdata probe-unsigned
```

**Check:** record the `x-amz-content-sha256` value for each (expect
`STREAMING-AWS4-HMAC-SHA256-PAYLOAD` by default and `UNSIGNED-PAYLOAD`
with the flag). The matrix below uses the default; §8.4 measures the
difference.

---

## 4. Sampling while warp runs

Every headline run (marked **[sample]** below) needs resource samples
from the NAS. This script writes one CSV line per second: total and
per-thread CPU of fs3, its RSS, disk and network throughput.

```sh
cat > $B/sample.py <<'PY'
import os, sys, time
pid, out, secs = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
hz = os.sysconf("SC_CLK_TCK")
def cpu_total():
    v = open("/proc/stat").readline().split()[1:]; v = list(map(int, v)); return sum(v), v[3] + v[4]
def threads():
    r = {}
    for t in os.listdir("/proc/%d/task" % pid):
        try:
            s = open("/proc/%d/task/%s/stat" % (pid, t)).read()
            f = s[s.rindex(")") + 2:].split()
            name = "loop" if t == str(pid) else "other"   # fs3 threads are unnamed; the main thread is the event loop
            r[t] = (name, int(f[11]) + int(f[12]))
        except OSError: pass
    return r
def rss():
    for l in open("/proc/%d/status" % pid):
        if l.startswith("VmRSS"): return int(l.split()[1]) // 1024
def disk():
    rd = wr = 0
    for l in open("/proc/diskstats"):
        f = l.split()
        if f[2].startswith(("md", "dm-")) or (f[2].startswith("sd") and not f[2][-1].isdigit()):
            if f[2].startswith("sd"): rd += int(f[5]); wr += int(f[9])
    return rd * 512, wr * 512
def net():
    rx = tx = 0
    for l in open("/proc/net/dev").readlines()[2:]:
        n, v = l.split(":"); v = v.split()
        if n.strip().startswith(("eth", "bond")): rx += int(v[0]); tx += int(v[8])
    return rx, tx
with open(out, "w") as o:
    o.write("t,cpu_busy_pct,fs3_cpu_pct,fs3_top_thread,fs3_top_thread_pct,fs3_threads,rss_mb,disk_rd_mbs,disk_wr_mbs,net_rx_mbs,net_tx_mbs\n")
    a = cpu_total(); th = threads(); d = disk(); n = net(); t0 = time.time()
    for i in range(secs):
        time.sleep(1)
        try:
            b = cpu_total(); th2 = threads(); d2 = disk(); n2 = net()
        except FileNotFoundError: break
        busy = 100.0 * (1 - (b[1] - a[1]) / max(1, b[0] - a[0]))
        per = {k: (v[0], (v[1] - th.get(k, (v[0], v[1]))[1]) * 100.0 / hz) for k, v in th2.items()}
        tot = sum(p for _, p in per.values())
        top = max(per.values(), key=lambda x: x[1]) if per else ("-", 0)
        o.write("%d,%.0f,%.0f,%s,%.0f,%d,%d,%.1f,%.1f,%.1f,%.1f\n" % (i, busy, tot, top[0], top[1], len(per), rss(),
                (d2[0] - d[0]) / 1e6, (d2[1] - d[1]) / 1e6, (n2[0] - n[0]) / 1e6, (n2[1] - n[1]) / 1e6))
        o.flush(); a, th, d, n = b, th2, d2, n2
PY
sampl() { python3 $B/sample.py $(cat $B/fs3.pid) $B/samples/$1.csv ${2:-200} & }
mkdir -p $B/samples
```

Start `sampl <same name as --benchdata> <seconds>` on the NAS just
before starting warp on the client. Summarise each CSV with:

```sh
python3 - $B/samples/<name>.csv <<'PY'
import csv, sys, statistics as st
r = list(csv.DictReader(open(sys.argv[1])))[10:-5]          # drop ramp-up and tail
for k in ("cpu_busy_pct", "fs3_cpu_pct", "fs3_top_thread_pct", "rss_mb", "disk_wr_mbs", "disk_rd_mbs", "net_rx_mbs", "net_tx_mbs"):
    v = [float(x[k]) for x in r]; print("%-20s median %7.1f  max %7.1f" % (k, st.median(v), max(v)))
print("busiest thread:", max(set(x["fs3_top_thread"] for x in r), key=[x["fs3_top_thread"] for x in r].count))
PY
```

How to read it: CPU% is per core (400% = all four cores). A
`fs3_top_thread_pct` near 100 with `fs3_top_thread` = `loop` (the main
thread, which runs the event loop; fs3's other threads all carry the
process name, so the sampler labels them `other`) means the loop is the
bottleneck. A busy `other` thread is an I/O worker, the replication or
notification threads, or the scrub. `net_*` near the
§2.2 ceiling means the link is. `disk_wr_mbs` near §2.3 means the disks
are. Otherwise look at `cpu_busy_pct` (all cores busy, including warp
when it runs on the NAS) and at warp's own client CPU.

---

## 5. LAN, single-part operations (warp on the client)

Each run is 60 seconds unless marked; headline runs (**[H]**) are 3
minutes, run three times, sampled. Restart fs3 (§3.1) at the start of
the section.

### 5.1 PUT

```sh
for size in 4KiB 64KiB 1MiB 16MiB 64MiB; do
  for c in 1 4 16 64; do
    warp put $W --host $NAS:9300 --obj.size $size --concurrent $c --disable-multipart \
        --duration 60s --benchdata lan-put-$size-c$c-r1
  done
done
```

Headline **[H] [sample]**: `--obj.size 4KiB --concurrent 16` and
`--obj.size 64MiB --concurrent 16`, `--duration 3m`, repetitions r1–r3.

**Check:** for each run record ops/s, MB/s, and the request latency
average, p50, p90, p99 from warp's summary (`warp analyze --analyze.op PUT
<file>` prints them again). For the headline runs add the sampler
summary and name the bottleneck.

### 5.2 GET

```sh
for size in 4KiB 64KiB 1MiB 16MiB 64MiB; do
  case $size in 4KiB|64KiB) n=10000 ;; 1MiB) n=2000 ;; 16MiB) n=500 ;; 64MiB) n=200 ;; esac
  for c in 1 4 16 64; do
    warp get $W --host $NAS:9300 --obj.size $size --objects $n --concurrent $c \
        --duration 60s --benchdata lan-get-$size-c$c-r1
  done
done
```

The 64 MiB set is 12.5 GB, more than the NAS's RAM, so it reads from
disk; the small sets fit in the page cache. Also run the 64 MiB
headline once with caches dropped just before the measurement starts
(warp prints when its prepare phase ends; drop caches on the NAS then:
`sync; echo 3 | sudo tee /proc/sys/vm/drop_caches`), and say which
runs were cold.

Headline **[H] [sample]**: 4KiB c16 and 64MiB c16, 3 min, r1–r3.

**Check:** as §5.1, plus time to first byte (warp prints TTFB for GET).

### 5.3 HEAD, LIST, DELETE

```sh
warp stat   $W --host $NAS:9300 --obj.size 4KiB --objects 10000 --concurrent 16 --duration 60s --benchdata lan-stat-4KiB-c16-r1
warp list   $W --host $NAS:9300 --obj.size 1KiB --objects 10000 --concurrent 8  --duration 60s --benchdata lan-list-10k-c8-r1
warp list   $W --host $NAS:9300 --obj.size 1KiB --objects 50000 --concurrent 8  --duration 60s --benchdata lan-list-50k-c8-r1
warp delete $W --host $NAS:9300 --obj.size 4KiB --objects 20000 --batch 100 --concurrent 8 --duration 60s --benchdata lan-delete-4KiB-c8-r1
```

fs3's lister reads and sorts the bucket's keys at the start of every
listing (no index, by design), so the 10k versus 50k LIST pair shows how
listing cost grows with bucket size. **[sample]** the 50k LIST.

**Check:** record ops/s and latency percentiles for each, and the
ratio of 50k to 10k LIST latency.

### 5.4 Mixed

```sh
warp mixed $W --host $NAS:9300 --obj.size 1MiB --objects 2000 --concurrent 16 \
    --duration 3m --benchdata lan-mixed-1MiB-c16-r1          # warp's default distribution
```

**[H] [sample]**, r1–r3.

**Check:** per-operation ops/s and latencies, and the total.

---

## 6. LAN, multipart

```sh
warp multipart-put $W --host $NAS:9300 --part.size 16MiB --parts 16 --part.concurrent 4 \
    --concurrent 4 --duration 3m --benchdata lan-mpput-16MiBx16-c4-r1
warp multipart-put $W --host $NAS:9300 --part.size 5MiB --parts 100 --part.concurrent 8 \
    --concurrent 2 --duration 3m --benchdata lan-mpput-5MiBx100-c2-r1
```

**[sample]** both. While they run, also watch completion latency in
the fs3 log or with `curl -s 127.0.0.1:9301/metrics | grep -E 'mpu|reflink'`
(on Btrfs, completion clones parts instead of copying them; the
`fs3_reflink_clones_total` counter should grow).

**Check:** record MB/s, part latency percentiles, and whether the
reflink counter grew (if not, completion copied the data: say so).

---

## 7. On the NAS (no network), selected workloads

warp runs on the NAS against `127.0.0.1:9300`. This removes the 1 GbE
ceiling but warp now competes with fs3 for the four cores, so record
warp's CPU too (`ps -o pcpu= -C warp` in the sampler's window, or add a
second `sample.py` with warp's pid).

```sh
cd $B
./warp put $W --host 127.0.0.1:9300 --obj.size 64MiB --concurrent 16 --disable-multipart --duration 3m --benchdata nas-put-64MiB-c16-r1
./warp get $W --host 127.0.0.1:9300 --obj.size 64MiB --objects 200 --concurrent 16 --duration 3m --benchdata nas-get-64MiB-c16-r1
./warp put $W --host 127.0.0.1:9300 --obj.size 4KiB --concurrent 16 --disable-multipart --duration 3m --benchdata nas-put-4KiB-c16-r1
./warp get $W --host 127.0.0.1:9300 --obj.size 4KiB --objects 10000 --concurrent 16 --duration 3m --benchdata nas-get-4KiB-c16-r1
```

**[sample]** all four, once each.

**Check:** record the same figures as §5, plus warp's CPU. If the
64 MiB numbers are far above the §2.2 ceiling, the LAN runs were
network-bound; if they aren't, the NAS itself is the limit (look at the
sampler for which part).

---

## 8. Feature costs (LAN, one configuration change at a time)

Each step reruns two reference workloads, **R-small** (`put` 4KiB c16,
60 s) and **R-large** (`put` and `get` 64MiB c16, 60 s each), with one
change, then reverts it. Compare against the same workloads from §5
(use `warp cmp lan-put-64MiB-c16-r1.csv.zst <new>.csv.zst`).

### 8.1 Native TLS

Restart fs3 with a certificate (any self-signed EC P-256 for the NAS's
IP, as in the replication runbook §1.2) and `--tls-port 9343 --tls-cert …
--tls-key …`. Run the reference workloads with
`--host $NAS:9343 --tls --insecure`.

### 8.2 SSE-S3

Restart fs3 with `--sse-key-file $B/sse.keys` (make it as in
`docs/AGENT-SSE-EVENTS-BROWSER-DS1515-TEST.md` §4.1; `shred -u` it
afterwards). Run the reference workloads with `--sse-s3-encrypt`. If
this warp version rejects the flag or fs3 answers an error, set default
encryption on `warp-bench` instead (`aws s3api put-bucket-encryption`
after warp's first run creates the bucket, and add `--noclear` so the
bucket and its setting survive) and record which way you used.

### 8.3 Versioning

`warp versioned $W --host $NAS:9300 --objects 1000 --obj.size 64KiB
--concurrent 16 --duration 60s --benchdata lan-versioned-64KiB-c16-r1`,
and compare its PUT/GET/DELETE figures with §5 at the nearest size.

### 8.4 Payload hashing

Rerun R-small and R-large with `--disable-sha256-payload` (§3.2: the
client then sends `UNSIGNED-PAYLOAD`, and fs3 skips the chunk-signature
work).

### 8.5 Keep-alive off

Rerun R-small with `--disable-http-keepalive` (a TCP connection per
request). If this warp version lacks the flag, record that and skip.

### 8.6 Through the DSM reverse proxy

Ask the human for (or reuse) a reverse-proxy entry
`https://<nas>:9443` → `http://localhost:9300`. Run the reference
workloads with `--host $NAS:9443 --tls --insecure`. **[sample]**, and
also sample nginx's CPU.

### 8.7 With a webhook rule

Start a receiver on the client (the `hook.py` from the SSE/webhooks
runbook §1.2, plain http), then:

```sh
curl -sS --unix-socket $B/admin.sock -X PUT http://x/v1/buckets/warp-bench/notification \
  -d '{"endpoint":"http://<client-ip>:9500/hook","allow_plain_http":true}'
```

The rule must exist before warp runs, and warp clears the bucket but
keeps it, so run warp once first to create `warp-bench`, set the rule,
then run R-small with `--noclear`. Remove the rule afterwards.

### 8.8 I/O worker count (informational)

R-small and R-large with `--io-threads 0`, `2` and `8` (default 4).
This is an existing knob, not a code change, and shows whether the
default is in the right place for this CPU.

**Check (every step):** a table row per workload: ops/s and MB/s,
p50/p99 latency, and the change against the §5 baseline in percent.

---

## 9. Package and evidence

### 9.1 The package as installed

If the human allows it, run R-small and R-large once against the
**package's** fs3 (port 9000, `FS3_BIND=0.0.0.0` temporarily, a
throwaway key and a `warp-bench` bucket only), to confirm the package's
settings (log file, admin socket, watchdog) don't change the picture.
Delete the bucket and revert `FS3_BIND` afterwards.

### 9.2 Keep

- every `*.csv.zst` / `*.json.zst` warp wrote (both machines), the
  sampler CSVs, `fs3.log` and `fs3.stderr`;
- `curl -s 127.0.0.1:9301/metrics` after each section;
- for any run with errors: warp's full output and the matching part of
  `fs3.log`, plus `dmesg | tail -30`.

Pack them as `fs3-baseline-<date>-<commit>.tar.zst` and give it to the
human. Don't commit the raw files to the repository.

### 9.3 Clean up

Stop fs3 and remove `$B/data`, `$B/samples` (after packing) and any key
file (`shred -u`). Remove reverse-proxy entries and webhook rules you
created, resume what §0.3 paused, and delete the benchmark key.

---

## 10. Report

Write the report to `docs/benchmarks/ds1515-baseline-<YYYY-MM-DD>.md`
in the repository (a new directory; commit only this Markdown file) in
this shape, then give the human the path and the tarball:

```
# fs3 baseline on the DS1515+ (<date>)

Commit: <sha> (fs3-tls --build-info: …)      warp: <version> (client and NAS)
NAS: DS1515+, DSM <…>, kernel <…>, Atom C2538 4C, <RAM>, governor <…>
Volume: <RAID level>, <disks>, <Btrfs/ext4>, mount <opts>, <fill %>
Client: <CPU, RAM, NIC, OS>; link <speed>, same switch: yes/no; RTT <ms>
Paused during the run: <…>; could not pause: <…>
fs3 command line: <…>
Payload mode seen by fs3: default <…>; with --disable-sha256-payload <…>

## Ceilings
Network: <MB/s> to NAS, <MB/s> from NAS, <MB/s> 4 streams
Disk: seq write <MB/s>, seq read <MB/s>, small-file create+fsync <n/s>

## Single-part, LAN (median of 3 for [H], else single run)
| op | size | conc | ops/s | MB/s | p50 ms | p90 ms | p99 ms | errors | bottleneck |
|----|------|------|-------|------|--------|--------|--------|--------|------------|
| PUT | 4KiB | 1 | … |
…  (every run from §5.1–5.4; mark [H] rows, add spread "± x%")

## Multipart, LAN
| parts | conc | MB/s | part p50/p99 ms | reflink used |

## On the NAS (no network)
| op | size | conc | ops/s | MB/s | p50/p99 ms | fs3 CPU % | warp CPU % | bottleneck |

## Feature costs (vs. baseline)
| change | workload | ops/s | MB/s | p99 ms | Δ vs baseline |
(TLS, SSE-S3, versioning, unsigned payload, keep-alive off, reverse proxy, webhook, io-threads 0/2/8)

## Resources (headline runs)
| run | fs3 CPU % median/max | busiest thread % (name) | threads | RSS MB | disk MB/s | net MB/s |

## Observations
- Where each headline run saturates, with the evidence (sampler lines).
- Anything surprising (errors, outliers, run-to-run spread over 10%,
  latency tails, thermal throttling).
- Candidate performance work suggested by the data, ranked by expected
  gain. (Suggestions only: nothing was changed.)

## Files
fs3-baseline-<date>-<commit>.tar.zst: <list of benchdata and sample files>
```

**Check:** every row has a benchdata file name that exists in the
tarball, and every "bottleneck" entry cites a sampler figure.
