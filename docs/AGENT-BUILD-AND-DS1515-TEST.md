# Agent runbook: build fs3, then test it on a Synology DS1515+

This file is written for an autonomous agent. It walks you through three
stages:

- **Part A:** set up a development build host, build every artifact, and
  run the full test pyramid.
- **Part B:** produce binaries that actually run on a DS1515+ (old
  kernel, old glibc).
- **Parts C and D:** package them, then test them on the NAS.

Work through the parts in order. Each step has a **check**: do not move on
until it passes. Record every result in the report template at the end.

---

## 0. Ground rules

1. **Never point a test at real data.**
   - Use a scratch shared folder on the NAS (`/volume1/fs3-test`) and
     scratch directories on the build host.
   - Several formats are **one-way migrations**: object header schema 4,
     credential-file attributes, and layout-2 object-lock buckets. A data
     folder touched by this build cannot be read by an older fs3.
2. **Back up first if fs3 is already installed.** If the NAS already runs
   the fs3 package, back up `/var/packages/fs3/var/` and the configured
   data folder before installing anything new (see D6.1).
3. **Bind LAN-exposed servers only during tests**, with throwaway
   credentials, and stop them afterwards. The production setup is
   `127.0.0.1` behind DSM's HTTPS reverse proxy.
4. **Ask the human before:**
   - doing anything as root on the NAS beyond what this runbook lists;
   - changing DSM settings;
   - changing anything outside the scratch folder.
5. **Do not "fix" a failing test by weakening it.** Diagnose, and report
   what you found.

---

## 1. Facts about the target

| item | value | why it matters |
|---|---|---|
| Model | Synology DS1515+ | |
| CPU | Intel Atom C2538 (Silvermont, 4 cores, x86_64, SSE4.2, AES-NI) | plain `x86_64` code. Never build with `-march=native` on a newer host. |
| DSM platform string | `avoton` | listed in `packaging/synology/INFO.in` `arch=` |
| OS | DSM 7.x | the package requires `os_min_ver 7.0-40000` |
| Kernel | **3.10.x** (Synology-patched) | no `getrandom`, `clone3`, `statx`, `copy_file_range` or seccomp TSYNC. The code handles each of these, see §6. |
| glibc | **old: check it, don't assume** (DSM 7.0/7.1 toolchains ship glibc 2.26) | the #1 reason a binary built on a modern host will not start |
| RAM | 2 GB by default | keep `--io-threads` and `--scrub-rate` at their defaults |
| Volumes | Btrfs or ext4 | reflink, dedup and compression only work on Btrfs |

**Why the NAS needs a special build.** `make fs3-static` links libcrypto
statically, but **glibc stays dynamic**: fully static glibc has NSS/DNS
pitfalls. A binary built on Ubuntu 24.04 needs `GLIBC_2.38` and refuses
to start on DSM. You must link against a glibc **no newer than the
NAS's** (Part B).

---

## Part A: development host build and full test run

Use this host to build, run the complete test suite, and later to drive
remote tests against the NAS.

### A1. Host requirements

- Linux x86_64. Ubuntu 22.04/24.04 or Debian 12 are known to work.
- Root (or sudo) is needed for the reflink loopback and immutability
  suites.
- Network access to the Ubuntu/Debian mirrors and PyPI.

### A2. Install the toolchain and test dependencies

```sh
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev python3 python3-pip \
    curl openssl strace btrfs-progs e2fsprogs util-linux file binutils
# boto3 / botocore[crt] / awscli at the versions the suites expect
pip install --break-system-packages -r tests/requirements.txt
chmod +x tests/*.sh tests/tools/*.sh   # tar may drop +x
mkdir -p ~/.aws && cat > ~/.aws/config <<'EOF'
[default]
region = us-east-1
s3 =
    addressing_style = path
EOF
```

**Check:** `make check-test-deps` prints nothing and exits 0.

### A3. Build everything (release)

```sh
make clean && make            # ./fs3 and ./fs3-lockd
make fs3-tls                  # native-TLS variant (dynamic libssl)
make fs3-static               # libcrypto static; host glibc (NOT for the NAS, see Part B)
```

**Check:**
- No compiler warnings (the code builds clean under `-Wall -Wextra
  -Wpedantic`).
- `./fs3 --help` lists `--seccomp`, `--reflink`, `--dedup`,
  `--fs-compress`, `--lock-immutable` and `--scrub-*`.

> Release and sanitizer builds share object files. **Always
> `make clean` when switching between `make` and `make DEBUG=1`.**
> Mixing them produces link errors (`__asan_*`) or, worse, a silently
> mixed binary.

### A4. Full test run (release)

Provide a reflink-capable directory so the Btrfs-only suite runs instead
of skipping:

```sh
sudo truncate -s 400M /tmp/btr.img && sudo mkfs.btrfs -q -f /tmp/btr.img
sudo mkdir -p /mnt/btr && sudo mount -o loop /tmp/btr.img /mnt/btr
sudo FS3_REFLINK_DIR=/mnt/btr make test 2>&1 | tee /tmp/fs3-make-test.log
```

- Run as root so `test_e2e_immutable.sh` also runs. It drops fs3 to uid
  65534 itself.
- **The loopback mount does not survive a reboot or container restart.**
  If the reflink suite prints `SKIP: … is not reflink-capable`, re-mount
  it.

**Check:**
- `make test` exits 0.
- `grep -E "FAIL|SIGSYS" /tmp/fs3-make-test.log` finds nothing.
- The only acceptable `SKIP` line is `rclone not installed`. If you can,
  install rclone so that case runs too.
- `FS3_TEST_STRICT=1` turns every skip into a failure; use it once you
  have rclone installed and the Btrfs directory mounted.

### A5. Sanitizer run

```sh
make clean
sudo UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 FS3_REFLINK_DIR=/mnt/btr \
    make test DEBUG=1 2>&1 | tee /tmp/fs3-make-test-debug.log
make clean && make             # back to release objects
```

**Check:** exit 0, and `grep -E "runtime error|AddressSanitizer|FAIL"` finds
nothing.

Notes:
- seccomp is compiled out of sanitizer builds; that is expected.
- `t_commit_races_bucket_delete` in `test_store` is a known rare
  DEBUG-only flake (see CLAUDE.md). Re-run once before reporting it.

### A6. Seccomp evidence (optional on the host, mandatory for the NAS binary)

```sh
make seccomp-profile     # e2e suites under strace -f; diff vs `fs3 --seccomp-list`
```

**Check:** the last section, "used but not allowed", lists only
startup-only calls: `execve`, `bind`, `listen`, `epoll_create1`,
`set_tid_address`, `arch_prctl`, `chmod`. These happen before the filter
is installed.

---

## Part B: build binaries for the DS1515+

### B1. Learn the NAS's glibc and kernel first

On the NAS (SSH, see D0):

```sh
uname -r                                   # expect 3.10.x
ls -l /lib/libc.so.6 /lib64/libc.so.6 2>/dev/null
/lib/libc.so.6 2>/dev/null | head -1 || ldd --version 2>/dev/null | head -1
cat /etc.defaults/VERSION                  # DSM productversion / buildnumber
```

Write down the glibc version as **`NAS_GLIBC`** (e.g. `2.26`), plus the
DSM version and build number.

### B2. Choose a build environment with glibc ≤ NAS_GLIBC

**Option 1 (preferred): Synology's official toolchain** for your exact
DSM version and the `avoton` platform.
- Download it from Synology's "Toolchain" download area. The file looks
  like `avoton-gcc850_glibc226_x86_64-GPL.txz` for DSM 7.0/7.1.
- Pick the one whose `glibcNNN` matches `NAS_GLIBC`.
- It is a cross toolchain with its own sysroot. That sysroot has **kernel
  3.10 headers**; fs3 compiles against them (fallbacks for `FICLONE`,
  `FICLONERANGE`, `__NR_getrandom` and `__NR_copy_file_range` are in the
  code).

**Option 2: a container with an old glibc.** `debian:stretch` (glibc
2.24, gcc 6.3) works for any `NAS_GLIBC ≥ 2.24`. Its archive needs the
`archive.debian.org` sources. Avoid `centos:7`: its gcc 4.8 lacks
`-fstack-protector-strong`.

With either option, **build OpenSSL from source, statically** (1.1.1w or
3.0.x; fs3 needs ≥ 1.1.0, and the TLS binary wants ≥ 1.1.1). That way no
system libssl or libcrypto is involved.

Example for option 2 with Docker, run from the repository root:

```sh
docker run --rm -it -v "$PWD":/src -w /src debian:stretch bash -euxc '
  printf "deb http://archive.debian.org/debian stretch main\n" > /etc/apt/sources.list
  apt-get -o Acquire::Check-Valid-Until=false update
  apt-get install -y --no-install-recommends build-essential perl curl ca-certificates file binutils
  # Static OpenSSL into /opt/ossl. Do NOT install libssl-dev: its headers would shadow ours.
  curl -fsSLo /tmp/ossl.tgz https://www.openssl.org/source/openssl-1.1.1w.tar.gz
  tar -C /tmp -xzf /tmp/ossl.tgz && cd /tmp/openssl-1.1.1w
  ./config --prefix=/opt/ossl --libdir=lib no-shared no-tests -fPIC
  make -j"$(nproc)" && make install_sw
  cd /src && make clean
  export C_INCLUDE_PATH=/opt/ossl/include LIBRARY_PATH=/opt/ossl/lib
  make -j"$(nproc)" fs3-static fs3-tls-static fs3-lockd-static fs3-dedup-estimate-static
'
```

- With option 1, set `CC` to the toolchain's
  `x86_64-pc-linux-gnu-gcc`.
- Configure OpenSSL with `--cross-compile-prefix=` pointing at the
  toolchain.
- Then run the same `make` line with `CC=…`.

Artifacts:

| file | purpose |
|---|---|
| `fs3-static` | main server, libcrypto static, glibc dynamic (old) |
| `fs3-tls-static` | native TLS variant (SSE-C needs TLS), libssl + libcrypto static |
| `fs3-lockd` (from `make fs3-lockd-static`) | fully static root helper for `--lock-immutable` |
| `fs3-dedup-estimate` (from `make fs3-dedup-estimate-static`) | optional, read-only block-dedup estimator; not in the SPK, copy it to the NAS by hand (added after the 2026-11-18 run) |

### B3. Verify the artifacts before copying them anywhere

```sh
for b in fs3-static fs3-tls-static fs3-lockd; do
  echo "== $b"; file $b
  objdump -T $b 2>/dev/null | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1
  ldd $b || true
done
```

**Check:**
- Each binary is an `ELF 64-bit … x86-64` executable.
- The highest `GLIBC_x.y` is **≤ NAS_GLIBC**. `fs3-lockd` is fully static
  and shows none.
- `ldd` lists only `libc.so.6` and `ld-linux-x86-64.so.2` (and
  `libpthread`/`libdl` on old glibc). **No `libssl` and no `libcrypto`.**

### B4. Prove the NAS binaries pass the suites (on the build host)

The test scripts launch `$ROOT/fs3` and `$ROOT/fs3-tls`. Substitute the
NAS binaries (a newer host glibc runs older-glibc binaries fine):

```sh
cp fs3 fs3.dev; cp fs3-static fs3; cp fs3-tls-static fs3-tls; touch fs3 fs3-tls
for t in test_e2e test_e2e_auth test_e2e_mpu test_e2e_parts test_e2e_metadata \
         test_e2e_quota test_e2e_scrub test_e2e_keys test_e2e_versioning \
         test_e2e_objlock test_e2e_tls test_e2e_ssec; do
  echo "== $t: $(./tests/$t.sh 2>&1 | grep -E '=====|SIGSYS' | tail -1)"; done
sudo FS3_REFLINK_DIR=/mnt/btr ./tests/test_e2e_reflink.sh | tail -1
sudo ./tests/test_e2e_immutable.sh | tail -1
mv fs3.dev fs3; rm -f fs3-tls; make fs3-tls     # restore dev binaries
```

**Check:** every line ends in `passed, 0 failed` or `done`, and no line
mentions SIGSYS.

---

## Part C: build the Synology package

```sh
make fs3-lockd-static            # ships inside the SPK (not started by it)
cd packaging/synology
FS3_SPK_VERSION=0.9.0-1 ./build-spk.sh ../../fs3-tls-static
```

- Bump `FS3_SPK_VERSION` above the version installed on the NAS, so
  Package Center treats this as an upgrade.
- The SPK runs **`fs3-tls-static`** as `bin/fs3` (since the replication
  work: outbound HTTPS to replication targets needs libssl).
  `build-spk.sh` checks `bin/fs3 --build-info` for `tls=yes` and refuses
  a non-TLS binary unless `FS3_SPK_ALLOW_NO_TLS=1`. Incoming HTTPS in
  production is still DSM's reverse proxy; the package doesn't configure
  a TLS listener.

**Check:**
- `fs3-<version>.spk` exists.
- `tar tf fs3-*.spk` lists bare names (`INFO`, `package.tgz`, …), not
  `./INFO`; DSM 7.1 rejects the `./` form with error 263.
- `tar xOf fs3-*.spk package.tgz | tar tz` contains `bin/fs3`,
  `bin/fs3-lockd`, `lib/fs3-conf.sh` and `ui/`.

---

## Part D: test on the DS1515+

### D0. Access and preparation (ask the human for credentials)

1. **Turn on SSH.** In DSM: Control Panel → Terminal & SNMP → Enable SSH.
   Log in as an administrator account (`ssh admin@<nas-ip>`); root work
   uses `sudo -i`.
2. **Turn on file transfer.** Control Panel → File Services → FTP → SFTP
   on. DSM's `scp` needs `scp -O` (legacy protocol) from newer OpenSSH
   clients.
3. **Create the scratch folder.** Control Panel → Shared Folder →
   Create, named `fs3-test` on a **Btrfs** volume if one exists (needed
   for the reflink, dedup and compression checks). Give your SSH user
   read/write. The path is then `/volume1/fs3-test` (adjust the volume
   number).
4. **Note the NAS's LAN IP** as `NAS`, and pick a free port, e.g. `9300`.
   DSM itself uses 5000/5001; the fs3 package defaults to 9000 (S3) and
   9101 (metrics).
5. **If the fs3 package is installed, stop it** for the standalone
   tests: Package Center → fs3 → Stop.

### D1. Copy the artifacts

```sh
scp -O fs3-static fs3-tls-static fs3-lockd admin@$NAS:/volume1/fs3-test/
ssh admin@$NAS 'cd /volume1/fs3-test && mv fs3-static fs3 && mv fs3-tls-static fs3-tls && chmod 755 fs3 fs3-tls fs3-lockd'
```

### D2. Compatibility probe (on the NAS)

```sh
cd /volume1/fs3-test
uname -r; grep -m1 -o -w -e aes -e sse4_2 /proc/cpuinfo | sort -u
./fs3 --help | head -3                     # must run: no "GLIBC_x not found"
./fs3 --seccomp-list | wc -l
grep Seccomp /proc/self/status             # "Seccomp: 0" = field exists (filters supported)
df -T /volume1/fs3-test                    # btrfs or ext4
```

**Check:** `./fs3 --help` and `./fs3-tls --help` both print usage. A
`version 'GLIBC_2.xx' not found` error means Part B was built against
too new a glibc; go back to B2.

### D3. First run in seccomp *log* mode (find missing syscalls safely)

The DSM kernel and glibc may make syscalls that this host's profile never
saw. Start with `--seccomp=log`, which prints the blocked syscall number
and exits with 159 instead of killing silently:

```sh
cd /volume1/fs3-test && mkdir -p data
./fs3 -a 0.0.0.0 -p 9300 -d /volume1/fs3-test/data \
      --auth AKIATESTNAS00001:testNasSecret012345678901234567890:tester \
      --require-auth --metrics-port 9301 --seccomp=log --scrub-interval-days 0 \
      > fs3.log 2>&1 &
echo $! > fs3.pid; sleep 1; cat fs3.log
```

**Check the startup log for:**
- `store: reflink supported (headers padded to 4 KiB)` on Btrfs, or
  `not supported (plain copies)` on ext4.
- `seccomp: filter installed (N instructions, mode log)`. If you see
  instead `kernel refused the filter … running unfiltered`, the DSM kernel
  lacks seccomp filters. Record it: `enforce` will then run unfiltered,
  and `--seccomp=require` would refuse to start.
- `io pool: 4 worker thread(s)` and `listening on 0.0.0.0:9300`.

Run the remote smoke test (D4) from the build host now. Afterwards,
check on the NAS:

```sh
grep "seccomp: blocked syscall" fs3.log || echo "no blocked syscalls"
kill $(cat fs3.pid)
```

If a syscall was blocked:
1. Map the number: `grep -w <N> /usr/include/x86_64-linux-gnu/asm/unistd_64.h`
   on the build host, or `ausyscall <N>`.
2. Decide whether it is legitimate at runtime.
3. Add it to `ALLOW[]` in `src/sandbox.c`, guarded with
   `#ifdef __NR_<name>` if old headers may lack it.
4. Rebuild (Part B), recopy, and repeat D3 until the log is clean.
5. Report every syscall you added and why.

Then restart **without** `--seccomp=log` (the default is `enforce`) and
run D4 again. **Check:** the server is still running afterwards:
`kill -0 $(cat fs3.pid)`. If it died, `wait` shows status 159 or
`dmesg | tail` shows a SIGSYS audit line.

### D4. Remote smoke test (run on the build host against the NAS)

Save as `/tmp/nas_smoke.py` and run
`python3 /tmp/nas_smoke.py http://$NAS:9300`:

```python
import sys, os, hashlib, datetime, boto3, botocore
from botocore.config import Config
url = sys.argv[1]
s3 = boto3.client("s3", endpoint_url=url, region_name="us-east-1",
                  aws_access_key_id="AKIATESTNAS00001",
                  aws_secret_access_key="testNasSecret012345678901234567890",
                  config=Config(signature_version="s3v4", retries={"max_attempts": 2}))
ok = lambda name: print("PASS", name)
b = "nas-smoke"
s3.create_bucket(Bucket=b)
body = os.urandom(3 * 1024 * 1024 + 7)
s3.put_object(Bucket=b, Key="obj", Body=body, Metadata={"mtime": "1700000000"}, CacheControl="max-age=60")
g = s3.get_object(Bucket=b, Key="obj"); assert g["Body"].read() == body; ok("put/get 3 MiB")
assert g["Metadata"] == {"mtime": "1700000000"} and g["CacheControl"] == "max-age=60"; ok("metadata")
assert s3.get_object(Bucket=b, Key="obj", Range="bytes=100-199")["Body"].read() == body[100:200]; ok("range")
parts = [os.urandom(5 * 1024 * 1024) for _ in range(2)] + [os.urandom(1234)]
u = s3.create_multipart_upload(Bucket=b, Key="mp")["UploadId"]
es = [s3.upload_part(Bucket=b, Key="mp", UploadId=u, PartNumber=i + 1, Body=p)["ETag"] for i, p in enumerate(parts)]
assert len(s3.list_parts(Bucket=b, Key="mp", UploadId=u)["Parts"]) == 3; ok("list parts")
s3.complete_multipart_upload(Bucket=b, Key="mp", UploadId=u,
    MultipartUpload={"Parts": [{"PartNumber": i + 1, "ETag": e} for i, e in enumerate(es)]})
assert s3.get_object(Bucket=b, Key="mp")["Body"].read() == b"".join(parts); ok("multipart 10 MiB")
s3.copy_object(Bucket=b, Key="copy", CopySource=f"{b}/mp")
assert s3.head_object(Bucket=b, Key="copy")["ContentLength"] == sum(map(len, parts)); ok("server-side copy")
keys = [f"many/{i:05d}" for i in range(1105)]
for k in keys: s3.put_object(Bucket=b, Key=k, Body=b"x")
got = [o["Key"] for pg in s3.get_paginator("list_objects_v2").paginate(Bucket=b, Prefix="many/") for o in pg["Contents"]]
assert got == keys; ok("ListObjectsV2 pagination over 1000 keys")
s3.create_bucket(Bucket=b + "-ver"); s3.put_bucket_versioning(Bucket=b + "-ver",
    VersioningConfiguration={"Status": "Enabled"})
v1 = s3.put_object(Bucket=b + "-ver", Key="k", Body=b"1")["VersionId"]; s3.put_object(Bucket=b + "-ver", Key="k", Body=b"2")
assert s3.get_object(Bucket=b + "-ver", Key="k", VersionId=v1)["Body"].read() == b"1"; ok("versioning")
s3.create_bucket(Bucket=b + "-lock", ObjectLockEnabledForBucket=True)
s3.put_object(Bucket=b + "-lock", Key="k", Body=b"locked", ObjectLockMode="GOVERNANCE",
              ObjectLockRetainUntilDate=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5))
try:
    vid = s3.head_object(Bucket=b + "-lock", Key="k")["VersionId"]
    s3.delete_object(Bucket=b + "-lock", Key="k", VersionId=vid); raise SystemExit("FAIL object lock")
except botocore.exceptions.ClientError: ok("object lock (layout 2)")
import urllib.request
pu = s3.generate_presigned_url("get_object", Params={"Bucket": b, "Key": "obj"}, ExpiresIn=60)
assert urllib.request.urlopen(pu).read() == body; ok("presigned GET")
print("ALL SMOKE CHECKS PASSED")
```

Also check:
- `curl -s http://$NAS:9300/_health` → `OK`.
- On the NAS: `curl -s 127.0.0.1:9301/metrics | grep -E 'fs3_up|fs3_reflink|fs3_bucket_bytes'`.

**Check:** `ALL SMOKE CHECKS PASSED`, and D3's log shows no blocked
syscall and no `[ERR]` line.

### D5. Run the repository's e2e suites on the NAS (strongly recommended)

This exercises the real DSM kernel, glibc and Btrfs: reflink, dedup and
compression ioctls on Synology's patched Btrfs; seccomp under the DSM
kernel; quotas and the scrub on real disks.

1. **Python.** Install "Python 3.9" (or newer) from Package Center, then:
   ```sh
   python3 -m ensurepip --user 2>/dev/null || true
   python3 -m pip install --user -r tests/requirements.txt
   export PATH=$HOME/.local/bin:$PATH
   ```
   awscrt ships manylinux wheels for x86_64. If pip has to compile it,
   ask the human for help rather than skip it.
2. **The repository and binaries.** Copy the repository tree to
   `/volume1/fs3-test/fs3` (git archive or rsync, without build outputs).
   Put the Part B binaries in it as `fs3`, `fs3-tls` and `fs3-lockd`.
3. **A `make` shim.** DSM has no `make`, and every suite starts with
   `(cd $ROOT && make … fs3)`, which aborts the script under `set -e`
   when `make` is missing. Provide a no-op `make` that keeps the
   prebuilt binaries:
   ```sh
   mkdir -p ~/bin && printf '#!/bin/sh\nexit 0\n' > ~/bin/make && chmod +x ~/bin/make
   export PATH=$HOME/bin:$PATH
   ```
4. **Tools.** Check `bash curl openssl lsattr filefrag setpriv`. DSM
   ships bash, curl and openssl. Suites that need a missing tool skip
   themselves or fail with an obvious message; record which.
5. **Space.** `/tmp` sits on DSM's small system partition (≈2 GB), and
   the suites write their scratch data there. Run them one at a time and
   check `df -h /tmp` between suites.
6. **Run:**
   ```sh
   cd /volume1/fs3-test/fs3
   mkdir -p /volume1/fs3-test/reflink
   for t in test_e2e test_e2e_auth test_e2e_mpu test_e2e_parts test_e2e_metadata \
            test_e2e_listing test_e2e_quota test_e2e_scrub test_e2e_keys \
            test_e2e_phase9 test_e2e_phase10 test_e2e_phase12 test_e2e_isolation \
            test_e2e_versioning test_e2e_objlock test_e2e_checksum test_e2e_tls test_e2e_ssec; do
     echo "== $t: $(./tests/$t.sh 2>&1 | grep -E '=====|SIGSYS|SKIP' | tail -1)"; done
   FS3_REFLINK_DIR=/volume1/fs3-test/reflink ./tests/test_e2e_reflink.sh 2>&1 | tail -3
   ```
   `test_e2e_reflink.sh` needs the Btrfs folder. Its compression phase
   needs `lsattr`/`filefrag`; without them it reports which tool is
   missing.
7. **Immutability (root).** Run `sudo -i`, then
   `cd /volume1/fs3-test/fs3 && ./tests/test_e2e_immutable.sh`. It skips
   if `setpriv` is absent or the filesystem refuses `chattr +i`. A pass
   proves that `FS_IMMUTABLE_FL` and `fs3-lockd` work on the DSM kernel.

**Check:**
- Every suite ends in `passed, 0 failed` or `done`.
- Explain any skip.
- Any SIGSYS line feeds back into D3, and any FAIL becomes a bug report
  with the suite's output.

### D6. Install and exercise the SPK

1. **Back up (if fs3 is already installed).**
   ```sh
   sudo tar czf /volume1/fs3-test/fs3-var-backup.tgz -C /var/packages/fs3 var
   ```
   Back up the configured data folder too. The upgrade migrates the
   on-disk format one-way.
2. **Install.**
   - Package Center → Settings → General → Trust Level: "Any publisher".
     Ask the human first; set it back afterwards.
   - Then Manual Install → `fs3-<version>.spk`.
3. **Wizard answers for the test:**
   - port `9000`;
   - data folder `/volume1/fs3-test/pkgdata` (grant the `fs3` package
     user write access under Shared Folder → Permissions), or keep the
     default;
   - LAN exposure off;
   - authentication on, with throwaway keys.
4. **Lifecycle checks (over SSH):**
   ```sh
   sudo synopkg status fs3            # running
   sudo cat /var/packages/fs3/var/fs3.log | tail -20
   curl -s 127.0.0.1:9000/_health; curl -s 127.0.0.1:9101/healthz
   sudo synopkg stop fs3 && sudo synopkg status fs3   # stopped
   sudo synopkg start fs3
   ```
   - The log shows `seccomp: filter installed (…, mode enforce)` and the
     reflink line.
   - The package runs as user `fs3`: `ps -o user,args -C fs3`.
5. **DSM console tile.**
   - Open fs3 from the DSM main menu.
   - The bucket table, with Objects/Size/Quota columns, loads.
   - Add a second key with a user, then remove it.
   - The status column shows `active`.
6. **Watchdog.** `sudo kill -9 $(cat /var/packages/fs3/var/fs3.child.pid)`.
   Within a few seconds a new fs3 PID is running and the log says
   `fs3 exited unexpectedly … restarting`.
7. **HTTPS through the DSM reverse proxy.**
   - Control Panel → Login Portal → Advanced → Reverse Proxy:
     `https://<nas>:9443` → `http://localhost:9000`.
   - Run D4 against `https://$NAS:9443`. Add `verify=False` only if DSM
     uses a self-signed certificate; say so in the report.
8. **Upgrade path.**
   - Build a second SPK with a higher `FS3_SPK_VERSION` and install it
     over the first.
   - **Check:** `fs3.conf` and `credentials` are unchanged, and
     `FS3_REQUIRE_AUTH=1` is still set (postinst must not reset it on
     upgrade).
9. **Uninstall.**
   - Remove the package.
   - **Check:** the data folder still exists; postuninst only removes the
     pid file and log.

### D7. Synology-specific feature checks

Run each against a standalone server on the scratch folder (as in D3,
with the extra flags), driving it with boto3 from the build host:

| feature | how | expected |
|---|---|---|
| reflink Complete / copy | multipart upload 3×5 MiB, then CopyObject | `fs3_reflink_clones_total` rises by 4 on Btrfs, stays 0 on ext4 |
| dedup | `--dedup owner`; PUT the same 3 MiB body under two keys | `fs3_dedup_hits_total` = 1; `/volume1/fs3-test/data/cas/` exists |
| compression | `--fs-compress auto`; PUT a large text file | log line `fs-compress: auto`; `lsattr` on the object file shows `c` (if `lsattr` exists) |
| scrub | `--scrub-now --scrub-rate 20M`; then `GET /v1/scrub` on `--admin-socket` | finishes with `"corrupt":0`; CPU stays reasonable on the Atom |
| quotas | admin API `PUT /v1/buckets/<b>/quota {"max_bytes":1048576}` | the next 2 MiB PUT → `403 QuotaExceeded` |
| SSE-C | run `./fs3-tls` with `--tls-port 9443 --tls-cert/--tls-key` (self-signed) | D4-style SSE-C PUT/GET with `SSECustomerKey` works over TLS, and is refused over HTTP |
| lock-immutable | as root: `./fs3-lockd --root <data> --socket /volume1/fs3-test/lockd.sock --journal /root/fs3-lockd.journal --peer-uid <fs3 uid>`; fs3 with `--lock-immutable --lockd-socket …` | COMPLIANCE version file shows `i` in `lsattr`; `rm` as the fs3 user fails |

### D8. Resource sanity on 2 GB / Atom

While uploading a 1 GiB object (`aws s3 cp` with the multipart
threshold at 64 MiB), sample `ps -o rss,pcpu -C fs3` on the NAS every few
seconds.

**Expected:**
- RSS stays in the tens of MB.
- No OOM.
- No `[ERR]` lines in the log.

### D9. Clean up

1. Stop all standalone servers (`kill $(cat fs3.pid)`) and any
   `fs3-lockd`.
2. Clear immutable flags as root
   (`find /volume1/fs3-test -type f -exec chattr -i {} +`).
3. Remove `/volume1/fs3-test` contents if the human agrees.
4. Restore the Package Center trust level and any SSH/SFTP settings you
   changed.
5. Restart the production package if you stopped it.

---

### D10. Related runbooks

- `docs/AGENT-REPLICATION-DS1515-TEST.md`: bucket replication on this
  NAS (cloud and LAN targets, CA bundle, DNS under seccomp).
- `docs/AGENT-COMPAT-HYPERBACKUP-VEEAM.md`: recorded runs of Synology
  Hyper Backup and Veeam against fs3 (the GUI part of the compatibility
  matrix in `docs/compatibility.md`).
- `docs/AGENT-SSE-EVENTS-BROWSER-DS1515-TEST.md`: SSE-S3 cost and key
  file, webhooks under seccomp, and the tile's object browser (upload
  limits of DSM's web server, share links behind the reverse proxy).
- `docs/AGENT-BENCHMARK-WARP-DS1515.md`: baseline benchmarks with
  MinIO's warp (hardware ceilings, PUT/GET/HEAD/LIST/DELETE/multipart/
  mixed across sizes and concurrency, feature costs), to run before any
  performance work.

## 2. Troubleshooting

| symptom | cause / fix |
|---|---|
| `version 'GLIBC_2.xx' not found` | built against too new a glibc; redo Part B with a toolchain or container whose glibc ≤ NAS_GLIBC |
| `cannot execute binary file: Exec format error` | wrong architecture; DS1515+ is x86_64 |
| server exits with status **159**, or `seccomp: blocked syscall N` in the log | a syscall missing from `ALLOW[]` (see D3); never ship with `--seccomp=off` as the "fix" |
| `seccomp: kernel refused the filter` | DSM kernel without `CONFIG_SECCOMP_FILTER`; record it; enforce degrades to unfiltered |
| `store: reflink not supported` on a Btrfs volume | the share may be ext4, or Synology's Btrfs may refuse `FICLONE`; record `df -T` and the DSM version |
| package does not start | read `/var/packages/fs3/var/fs3.log`. Most common: the data folder isn't writable by the `fs3` user (the message names the folder and the fix), or the port is taken |
| DSM 7.1 install error 263 | SPK members prefixed with `./`; `build-spk.sh` avoids this, so rebuild with it |
| suite aborts immediately on the NAS | the `make` shim is missing from `PATH` (D5.3) |
| botocore stalls 60 s after a refused upload | fixed in this tree (a connection refused before `100 Continue` is closed); if seen, report it |
| `--lock-immutable … refusing to start` | `fs3-lockd` isn't running, its socket isn't owned by the fs3 uid, or the filesystem refuses `chattr +i` |
| `RNDGETENTCNT on /dev/urandom indicates that the entropy pool does not have enough entropy` in Python test output on DSM | `awscrt` (`aws-c-common`) checks `RNDGETENTCNT` on kernel 3.10 when `getrandom()` is absent and writes a warning to `stdout`; SigV4 test helpers set `sys.modules["awscrt"] = None` before importing `botocore` |
| `CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate` in `test_e2e_tls.sh` / `test_e2e_ssec.sh` on DSM | DSM's `/etc/ssl/openssl.cnf` already defines `[v3_ca]`; using `openssl req -x509 -addext` on OpenSSL 1.1.1t emits duplicate `Basic Constraints` / `Subject Key Identifier` extensions. Use `-config` with a clean `[v3_ca]` section |
| `sudo: synopkg: command not found` | DSM's `sudo` `secure_path` omits `/usr/syno/bin`; invoke `/usr/syno/bin/synopkg` with its full path |

---

## 3. Report template (fill in and return)

```
Build host:        <distro, kernel, gcc, OpenSSL used for Part B>
NAS:               DS1515+, DSM <version>-<build>, kernel <uname -r>, glibc <NAS_GLIBC>, volume <btrfs|ext4>
Binaries:          fs3 <sha256>, fs3-tls <sha256>, fs3-lockd <sha256>; max GLIBC symbol <x.y>
Part A make test:  PASS/FAIL (<n> suites); DEBUG run: PASS/FAIL; skips: <list>
Part B B4 suites:  PASS/FAIL per suite
NAS D2 probe:      runs: yes/no; seccomp filter supported: yes/no; reflink: yes/no
NAS D3 seccomp:    blocked syscalls found: <none | list + what you changed>
NAS D4 smoke:      PASS/FAIL
NAS D5 e2e:        <suite: result> …  skips with reasons
NAS D6 SPK:        install / start-stop / tile / watchdog / reverse proxy / upgrade / uninstall: PASS/FAIL each
NAS D7 features:   reflink / dedup / compression / scrub / quotas / SSE-C / lock-immutable: PASS/FAIL/N.A.
NAS D8 resources:  peak RSS <MB>, CPU <%> during 1 GiB upload
Open issues:       <bugs with exact commands, logs, expected vs actual>
```

---

## 4. Recorded Test Run (2026-11-18)

```
Build host:        Fedora Linux 45 (kernel 7.3.4-300.fc45.x86_64, gcc 16); Part B container: debian:stretch (glibc 2.24, gcc 6.3.0, static OpenSSL 1.1.1w)
NAS:               DS1515+ (192.168.1.3), DSM 7.1.1-42962 (Update 9), kernel 3.10.108, glibc 2.26, volume btrfs (/volume1)
Binaries:          fs3-static 021fc8f77e9e73d73afef0f7b81421d943a23090c697e1a4e8f4a4e51c786cdd,
                   fs3-tls-static 1dbbdf24c40b24eaf41907ffe35331c01e8c76f148f92b5be89f132c1299fd4a,
                   fs3-lockd a6ce617150c766014725cb252d63b9e21af8a6a93e678558ae6b0d1322db99ae;
                   max GLIBC symbol 2.17 (fs3-lockd: fully static)
Part A make test:  PASS (15 C unit/fuzz suites + 29 e2e suites); DEBUG run: PASS (after 1 retry of known test_store flake); skips: test_e2e_immutable.sh on host (non-root)
Part B B4 suites:  test_e2e: PASS (23/23), test_e2e_auth: PASS (28/28), test_e2e_mpu: PASS (26/26),
                   test_e2e_parts: PASS (53/53), test_e2e_metadata: PASS (46/46 + rclone),
                   test_e2e_quota: PASS (61/61), test_e2e_scrub: PASS (30/30), test_e2e_keys: PASS (30/30),
                   test_e2e_versioning: PASS (38/38), test_e2e_objlock: PASS (26/26),
                   test_e2e_tls: PASS (19/19), test_e2e_ssec: PASS (43/43),
                   test_e2e_reflink: PASS (45/45 + fs-compress auto/all),
                   test_e2e_immutable: SKIP on host (non-root), PASS on NAS (25/25)
NAS D2 probe:      runs: yes; seccomp filter supported: no (no Seccomp field in /proc/self/status; kernel 3.10.108 lacks CONFIG_SECCOMP_FILTER); reflink: yes (Btrfs)
NAS D3 seccomp:    blocked syscalls found: none on NAS (kernel lacks CONFIG_SECCOMP_FILTER, so enforce logs a warning and runs unfiltered).
                   In Part B4 on the 7.3 host, building src/sandbox.c against debian:stretch's 4.9 kernel headers omitted post-4.9 syscall numbers
                   (__NR_clone3, __NR_rseq, __NR_statx, __NR_faccessat2, __NR_epoll_pwait2); added #ifndef __NR_* x86_64 definitions in src/sandbox.c.
NAS D4 smoke:      PASS (both --seccomp=log and default --seccomp=enforce; /_health OK; fs3_reflink_clones_total=4)
NAS D5 e2e:        test_e2e: PASS (23/23), test_e2e_auth: PASS (28/28), test_e2e_mpu: PASS (26/26),
                   test_e2e_parts: PASS (53/53), test_e2e_metadata: PASS (46/46; rclone sub-case skipped: rclone not installed on NAS),
                   test_e2e_listing: PASS (20/20), test_e2e_quota: PASS (61/61), test_e2e_scrub: PASS (30/30),
                   test_e2e_keys: PASS (30/30), test_e2e_phase9: PASS (57/57), test_e2e_phase10: PASS (28/28),
                   test_e2e_phase11: PASS (18/18), test_e2e_phase12: PASS (39/39), test_e2e_isolation: PASS (74/74),
                   test_e2e_subresources: PASS (113/113), test_e2e_versioning: PASS (38/38),
                   test_e2e_objlock: PASS (26/26), test_e2e_checksum: PASS (75/75), test_e2e_audit: PASS (10/10),
                   test_e2e_policy: PASS (29/29), test_e2e_admin: PASS (33/33), test_e2e_website: PASS (35/35),
                   test_e2e_lifecycle: PASS (20/20), test_e2e_cors: PASS (24/24), test_e2e_presign: PASS (23/23),
                   test_e2e_tls: PASS (19/19), test_e2e_ssec: PASS (43/43),
                   test_e2e_reflink: PASS (45/45 + fs-compress auto/all),
                   test_e2e_immutable: PASS (25/25 as root on Btrfs with Python setpriv shim),
                   test_ui_cgi: PASS (60/60)
NAS D6 SPK:        install: PASS (0.9.0-5 via /usr/syno/bin/synopkg)
                   start-stop: PASS (status running/stopped, runs as user `fs3`, /_health & /healthz OK)
                   tile: PASS (bucket table with Objects/Size/Quota loaded; credential add/remove via CGI verified; 60/60 in test_ui_cgi.sh)
                   watchdog: PASS (kill -9 of child PID 14827 respawned as PID 15172 within 2s)
                   reverse proxy: PASS (D4 smoke suite passed over https://s3.beci.local:8443 -> http://localhost:9000 with verify=False for self-signed cert)
                   upgrade: PASS (0.9.0-5 -> 0.9.0-6 preserved fs3.conf, credentials, and FS3_REQUIRE_AUTH=1)
                   uninstall: PASS (synopkg uninstall preserved data folder /volume1/fs3-test/pkgdata; production package and config restored afterwards)
NAS D7 features:   reflink: PASS (fs3_reflink_clones_total +4)
                   dedup: PASS (fs3_dedup_hits_total=1, cas/u-746573746572/... created)
                   compression: PASS (fs-compress: auto logged; lsattr shows --------c-------------)
                   scrub: PASS (6 files, 42,110,979 bytes verified in 5s, corrupt: 0, RSS 1.4 MB, CPU 4.3%–8.5%)
                   quotas: PASS (PUT /v1/buckets/d7-reflink/quota 1 MiB → 2 MiB PUT rejected with 403 QuotaExceeded)
                   SSE-C: PASS (AES256 PUT/GET over TLS 9343 succeeded; plain HTTP refused with InvalidRequest)
                   lock-immutable: PASS (COMPLIANCE version file shows ----i----------------- in lsattr; rm as non-root failed with Operation not permitted)
NAS D8 resources:  peak RSS 2.67 MB (2,672 KB), CPU 74.2%–84.7% during 1 GiB multipart upload (sustained 46.7 MiB/s, 0 [ERR] lines)
Open issues:       1. Fixed in tree (Makefile): LLHTTP_CFLAGS lacked -fPIE (failed PIE link on Fedora GCC 16) and kept -D_FORTIFY_SOURCE=2 under DEBUG=1 (-O0).
                   2. Fixed in tree (src/sigv4.c, third_party/xml/xml_parser.c): fixed-size char[64] string initializers triggered GCC 16 -Wunterminated-string-initialization.
                   3. Fixed in tree (src/scrub.c): scrub_run called state_save_locked (2 fsyncs) on all 256 shards per bucket/tree even when the shard directory did not exist (4,608 fsyncs across 3 buckets), timing out test_e2e_reflink.sh on physical Btrfs.
                   4. Fixed in tree (src/sandbox.c, src/store_fs.c): added #ifndef __NR_* x86_64 definitions for post-3.10/4.9 syscalls (clone3, rseq, statx, faccessat2, epoll_pwait2, etc.) and guarded -Wstringop-overread for GCC < 11.
                   5. Fixed in tree (tests/sign_request.py, tests/sign_slow_put.py, tests/test_e2e_auth.sh, tests/test_e2e_tls.sh, tests/test_e2e_ssec.sh, tests/test_e2e_immutable.sh): avoided importing awscrt on Linux 3.10 (where aws-c-common prints an RNDGETENTCNT warning to stdout when /dev/urandom entropy is low), used explicit -config for test CA generation on DSM's OpenSSL 1.1.1t (avoiding duplicate [v3_ca] extensions), and used FS3_REFLINK_DIR in test_e2e_immutable.sh when /tmp is tmpfs.
                   6. Open observation (kernel 3.10 Btrfs): when --dedup and --fs-compress auto are enabled together on DSM's 3.10.108 Btrfs, dedup_commit runs before xfsync(w->fd) while delalloc compression pages are still uncommitted and tf (the pool file) lacks FS_COMPR_FL, causing FICLONERANGE into cas/ to return -1 (leaving objects intact as normal copies with 0 dedup hits).
```
