# Agent runbook: Hyper Backup and Veeam against fs3 (recorded runs)

This runbook is for an agent working with a human. The scripted
compatibility matrix (`make compat`, `docs/compatibility.md`) covers
restic, rclone, Kopia, Duplicati and the AWS CLI. Two important clients
are GUI-only and need hands-on runs:

- **Synology Hyper Backup** on the DS1515+, pointed at fs3 on the same
  NAS and at fs3 on a second box;
- **Veeam Backup & Replication Community Edition** on a Windows VM,
  using fs3 as an object storage repository with immutability.

GUI steps are done by the human, or by the agent through remote desktop
if that is available. The agent's job is to prepare the fs3 side, give
the exact settings to enter, watch fs3 while the client runs, and record
the results. Every result goes into the report template (§5), then into
`docs/compatibility.md` (the results table and caveats).

The main runbook (`docs/AGENT-BUILD-AND-DS1515-TEST.md`) covers access,
the NAS build and the SPK install. Its ground rules apply here.

---

## 0. Ground rules

1. **Scratch data only.** Use dedicated buckets (`hb-test`, `hb-lock`,
   `veeam-test`) and a small source: a 2–5 GB shared folder or VM. Never
   point a test at production backups.
2. **Throwaway credentials.** Use one fs3 key per client, created for
   the test and removed afterwards.
3. **Ask the human before:**
   - installing Hyper Backup or Veeam;
   - changing DSM settings (reverse proxy, firewall, certificate);
   - running anything that takes more than an hour.
4. **COMPLIANCE retention can't be shortened or removed, even by you.**
   For the Veeam immutability test use a **1-day** retention on a
   scratch bucket only, and budget the disk space until it expires.
5. **A client failure is a finding.** Record the client's exact error
   text, the matching fs3 audit-log lines (§1.3) and the fs3 log. Don't
   change fs3 settings to make a client pass without recording that you
   did.

---

## 1. Prepare fs3 and the observation tools

### 1.1 Targets

| Target | How |
|---|---|
| **A. fs3 on the same NAS** | The installed SPK on the DS1515+ (port 9000 on `127.0.0.1`), reached through the DSM reverse proxy over HTTPS with the DSM certificate: `https://fs3.<nas-domain>` → `http://localhost:9000` (README, "HTTPS via the DSM reverse proxy"). Hyper Backup on the same NAS uses this. |
| **B. fs3 on a second box** | `fs3-tls` on the build host or another LAN machine, with native TLS and a certificate the clients trust (a private CA imported into DSM and Windows), **or** plain HTTP on the LAN if the client allows it. |

### 1.2 Turn on the audit log

The audit log records one JSON line per request (action, path, status,
S3 error and duration) and is the main observation tool.

- **SPK:** in the tile, Settings → *Logging and hardening* → *Audit
  log* on. The file is `/var/packages/fs3/var/audit.log`.
- **Standalone:** add `--audit-log /path/audit.log`.

Create the buckets and keys (on the box where fs3 runs; for the SPK, use
the tile's *Credentials* section for the keys):

```sh
export AWS_ACCESS_KEY_ID=<admin key> AWS_SECRET_ACCESS_KEY=<secret> AWS_DEFAULT_REGION=us-east-1
EP=http://127.0.0.1:9000
aws --endpoint-url $EP s3api create-bucket --bucket hb-test
aws --endpoint-url $EP s3api create-bucket --bucket hb-lock --object-lock-enabled-for-bucket
aws --endpoint-url $EP s3api create-bucket --bucket veeam-test --object-lock-enabled-for-bucket
```

### 1.3 Summarise what a client did

Save this script as `audit-summary.py` and run it after each scenario:
`python3 audit-summary.py /var/packages/fs3/var/audit.log <since-ISO-time>`.

```python
import json, sys, collections
path, since = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""
acts, errs, slow, codes = collections.Counter(), collections.Counter(), [], collections.Counter()
for line in open(path, encoding="utf-8", errors="replace"):
    try: r = json.loads(line)
    except ValueError: continue
    if "action" not in r or r.get("ts", "") < since: continue
    acts[r["action"]] += 1; codes[r["status"]] += 1
    if r["status"] >= 400: errs[(r["action"], r["status"], r.get("error", ""))] += 1
    if r.get("ms", 0) > 5000: slow.append((r["ts"], r["action"], r["path"][:80], r["ms"]))
print("requests by action:"); [print(f"  {a:32s} {n}") for a, n in acts.most_common()]
print("status codes:", dict(codes))
print("errors:"); [print(f"  {a} {s} {e}: {n}") for (a, s, e), n in errs.most_common()]
print("slow (>5 s):"); [print("  ", *x) for x in slow[:20]]
```

**Record:** for every scenario, the script's output. Errors that the
client recovered from still matter: a stream of `NotImplemented` (501)
answers tells us which API is missing. Slow requests point at
keep-alive or timeout problems.

### 1.4 See addressing and signing (one short capture per client)

The audit log doesn't record the `Host` header or the signing mode.
Capture the first few requests on the hop that reaches fs3 in plain HTTP
(for target A that is loopback, behind the reverse proxy). Run it as
root on the box running fs3:

```sh
timeout 60 tcpdump -i lo -A -s 1500 'tcp port 9000' 2>/dev/null |
  grep -E '^(GET|PUT|POST|HEAD|DELETE) |^Host:|^Authorization:|^x-amz-content-sha256:|^User-Agent:|^Expect:' |
  sed -E 's/Signature=[0-9a-f]+/Signature=<redacted>/; s/Credential=[^/]+/Credential=<key>/' | head -60
```

**Record:**
- `User-Agent` (client name and version);
- path-style (`/bucket/key` with `Host: host`) or virtual-hosted
  (`Host: bucket.host`);
- `x-amz-content-sha256`: `UNSIGNED-PAYLOAD`, a hex hash,
  `STREAMING-AWS4-HMAC-SHA256-PAYLOAD…` (chunked), or `AWS4-HMAC-SHA256`
  versus `AWS ` (SigV2!) in `Authorization`;
- whether `Expect: 100-continue` is used.

---

## 2. Synology Hyper Backup

DSM: Hyper Backup → Create → Data backup task → **S3 Storage**.

### 2.1 Connection settings to try (record what the UI offers)

| Field | Value |
|---|---|
| S3 Server | **Custom Server URL** |
| Server address | target A: `fs3.<nas-domain>` (reverse proxy, port 443); target B: `<host>:<port>` |
| Signature version | **v4** (if the UI offers v2/v4; record the options) |
| Request style | **Path style** (if offered; record whether "Virtual hosted style" is the only choice) |
| Access key / Secret key | the `hb` test key |
| Bucket name | `hb-test` (choose existing) |
| Directory | `ds1515` |

**Check:** the wizard connects and lists the bucket.
- If it fails, record the exact error dialog and the §1.3 summary, which
  shows whether it called `GetBucketLocation`, `ListBuckets` or a
  virtual-host request that fs3 answered with `NoSuchBucket`.
- If Hyper Backup insists on virtual-hosted addressing, stop. That is
  the key finding: it becomes a feature request for host-based bucket
  resolution, and §5 records it.

### 2.2 Scenario

1. **Back up.** Choose the scratch shared folder (2–5 GB, mixed file
   sizes). Turn on **Backup rotation**: "From earliest versions",
   keep 2. Turn on client-side encryption if offered (record the
   choice). Run the backup. **Check:** it succeeds. Record the duration,
   the §1.3 summary and the bucket size
   (`aws s3 ls --recursive --summarize s3://hb-test/ds1515 | tail -2`).
2. **Second version.** Change about 10 files, add some, delete some,
   then run the backup again. **Check:** it succeeds and Hyper Backup
   shows 2 versions.
3. **Integrity check.** Hyper Backup → task → *Check backup integrity*
   (choose the full/data check if offered). **Check:** it completes with
   no errors. Record the §1.3 summary (`GetObject` and `Range` reads).
4. **Restore.** Restore version 1 to a new folder (`/volume1/fs3-test/hb-restore`)
   and compare it with a copy of the original data:
   `diff -r <original-copy> /volume1/fs3-test/hb-restore/...`.
   **Check:** no differences. Also restore one file from version 2
   through *Backup Explorer*.
5. **Rotation.** Run a third backup. **Check:** rotation deletes the
   oldest version. The §1.3 summary shows `DeleteObject`/`DeleteObjects`
   with status 2xx.
6. **Relink (lost-NAS case).** Remove the task in Hyper Backup without
   deleting its data. Create a new task → S3 → same bucket and
   directory → "Relink". **Check:** the versions show up, and a restore
   from them works.
7. **Lock bucket.** Repeat steps 1–2 against `hb-lock`. **Check:**
   whether Hyper Backup works with a versioned/Object Lock bucket (it
   only adds delete markers on rotation), and whether DSM offers
   immutability settings for S3 (record them). Record the version count:
   `aws s3api list-object-versions --bucket hb-lock --query 'length(Versions)'`.
8. **Target B.** Repeat steps 1–4 against the second box. If target B
   uses a private CA, import it first in DSM (Control Panel → Security →
   Certificate → Import), and record whether Hyper Backup trusts it.

---

## 3. Veeam Backup & Replication (Community Edition)

On a Windows VM on the LAN. Ask the human for the Veeam version to
install. Record the exact version and build.

### 3.1 Object storage repository

Backup Infrastructure → Backup Repositories → Add → **Object storage**
→ **S3 compatible**.

| Field | Value |
|---|---|
| Service point | `https://<fs3 host>:<port>` (target B with a CA that Windows trusts, or target A via the reverse proxy) |
| Region | `us-east-1` |
| Credentials | the `veeam` test key |
| Bucket | `veeam-test`; folder `vbr` |
| Make recent backups immutable for | **1 day** (the minimum; see ground rule 4) |

**Check:** the wizard accepts the repository and the immutability
option.
- **Capacity probe:** Veeam's Smart Object Storage API writes
  `.system-*/system.xml` and reads `capacity.xml` if present. Record
  whether the wizard shows capacity, and the §1.3 summary for the wizard
  steps.
- **Error dialogs:** record any dialog that mentions versioning, Object
  Lock or `GetObjectLockConfiguration` verbatim.

### 3.2 Scenario

1. **Backup job.** Back up a small VM or a Windows agent backup of a test
   machine to the repository. Run it. **Check:** it succeeds. Record the
   §1.3 summary, the number of objects, and whether objects carry
   retention:
   ```sh
   aws --endpoint-url $EP s3api list-objects-v2 --bucket veeam-test --max-items 3 --query 'Contents[].Key'
   aws --endpoint-url $EP s3api get-object-retention --bucket veeam-test --key '<one of them>'
   ```
   Expect `Mode: COMPLIANCE` with a retain-until date at least 1 day
   out. Veeam may add up to 10 days of "block generation" to the period
   you set; record the actual date.
2. **Incremental.** Change some data on the source and run the job again.
   **Check:** it succeeds.
3. **Immutability is enforced.**
   - Try to delete the backup from Veeam (*Delete from disk*).
     **Check:** Veeam refuses, saying the backup is immutable.
   - Then try from the fs3 side:
     `aws s3api delete-object --bucket veeam-test --key <key> --version-id <vid>`.
     **Check:** fs3 refuses with `AccessDenied`.
   - Record both messages.
4. **Restore.** Restore the VM or some files to a new location.
   **Check:** it completes. Compare a few files with checksums
   (`certutil -hashfile <f> SHA256` on Windows).
5. **Health check.** Job settings → Storage → Advanced → Maintenance →
   *Perform backup files health check*, then run it. **Check:** no
   errors.
6. **Rescan after repository loss.** Remove the repository from Veeam
   (keeping the data), add it again, and import the backups. **Check:**
   the restore points appear.
7. **Expiry (next day).** After the retention date passes, run the job
   again with retention policy 1 restore point. **Check:** Veeam
   deletes the expired objects, and fs3 allows it (2xx in the audit
   log).

---

## 4. Clean up

1. Remove the Hyper Backup tasks and the Veeam repository, deleting the
   backup data where the client allows it.
2. After the COMPLIANCE retention has expired, delete every version in
   `hb-lock` and `veeam-test`, then delete the buckets.
   - Until then, leave them in place and say so in the report.
   - A sketch for the deletion:
     `aws s3api list-object-versions` → `delete-object --version-id`
     for each version.
3. Remove the test keys from fs3, and turn the audit log back off if it
   was off before.
4. Remove the reverse-proxy rule and any imported CA if they were added
   only for this test.

---

## 5. Report template (fill in and return)

```
fs3:               commit <sha>, binary fs3 / fs3-tls, SPK version <…>
Targets:           A = <reverse proxy URL> ; B = <host:port, TLS/plain, CA>

Hyper Backup:      DSM <version>, Hyper Backup <version>
  UI options:      signature: <v2/v4 offered/chosen>; request style: <path/virtual offered/chosen>
  Wire (§1.4):     User-Agent <…>; addressing <path|virtual>; payload <UNSIGNED|hash|streaming>; SigV2 seen: yes/no
  Connect:         A PASS/FAIL, B PASS/FAIL (<error text>)
  Backup v1/v2:    PASS/FAIL; duration <…>; size <…>
  Integrity check: PASS/FAIL
  Restore v1 diff: PASS/FAIL; Backup Explorer single file: PASS/FAIL
  Rotation:        PASS/FAIL
  Relink:          PASS/FAIL
  Lock bucket:     PASS/FAIL; immutability options offered: <…>; versions after rotation <n>
  fs3 errors:      <§1.3 errors section, per scenario>

Veeam B&R:         <version/build>, Windows <version>
  Wire (§1.4):     User-Agent <…>; addressing; payload mode
  Repository:      PASS/FAIL; immutability accepted: yes/no; capacity shown: yes/no
  Backup / incr:   PASS/FAIL; objects <n>; retention on objects: <mode, until>
  Delete refused:  Veeam: <message>; fs3: <message>
  Restore:         PASS/FAIL (checksums match: yes/no)
  Health check:    PASS/FAIL
  Rescan/import:   PASS/FAIL
  Expiry (day 2):  PASS/FAIL/not yet
  fs3 errors:      <§1.3 errors section, per scenario>

Feature requests:  <e.g. virtual-hosted addressing, an unimplemented API, with the request lines>
Bugs:              <client error text, audit lines, fs3 log excerpt, steps to reproduce>
Cleanup:           tasks/repo removed; buckets: deleted / waiting for retention until <date>; keys removed
```
