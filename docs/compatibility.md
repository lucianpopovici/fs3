# Backup-tool compatibility

This page records which backup clients have been tested against fs3, the
settings that work, and the caveats. The scripted part runs with
`make compat` (`tests/compat/`). The GUI tools (Synology Hyper Backup,
Veeam) are checked by hand, with a recorded run
(`docs/AGENT-COMPAT-HYPERBACKUP-VEEAM.md`).

## Results

Last scripted run: 2026-11-22, fs3 `main` + the keep-alive fix below, on
Ubuntu 24.04 x86_64.

| Tool | Version | plain HTTP | native TLS | versioning | Object Lock | crash mid-backup |
|---|---|---|---|---|---|---|
| restic | 0.20.0 | ✅ | ✅ | ✅ | ✅ | ✅ |
| rclone | 1.76.0 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Kopia | 0.23.1 | ✅ | ✅ | ✅ | ✅ (COMPLIANCE retention set by Kopia) | ✅ |
| Duplicati | 2.4.1.0 stable | ✅ | ✅ | ✅ | ✅ (`--s3-lock-mode=Compliance`) | ✅ |
| AWS CLI v2 | 2.42.1 | ✅ | ✅ | ✅ | ✅ | ✅ |
| Synology Hyper Backup | — | not yet recorded | | | | |
| Veeam B&R Community | — | not yet recorded | | | | |

### What each scripted run checks

Every variant runs against a fresh fs3 with authentication on. Each one
ends with the tool's own verification, followed by a byte-for-byte
restore compared with `diff -r`.

The test data covers:
- 150 small files;
- 12 files of 0.1–1.2 MB;
- one 24 MiB file, multipart for every tool;
- names with spaces, Unicode and `+&=`;
- an empty file, a nine-level-deep path, and a fixed mtime.

The second generation of the data changes 15 files, adds 5 and deletes 2.

| Tool | Scenario |
|---|---|
| restic | `init`; two snapshots; `check --read-data`; restore the latest and the first snapshot; `forget --keep-last 1 --prune`; `check --read-data` again; restore |
| rclone | `sync` with `--s3-upload-cutoff 5M`; `check --download`; restore; modification time kept (`x-amz-meta-mtime`); server-side copy (CopyObject); second `sync` with changes and deletions; `check --download`; restore; with versioning, `--s3-versions` lists old versions |
| Kopia | `repository create s3`; two snapshots; `snapshot verify --verify-files-percent=100`; restore both; `snapshot delete`; `maintenance run --full --safety=none`; verify; restore. Object Lock variant: `--retention-mode COMPLIANCE --retention-period 24h`, then checks that blobs carry COMPLIANCE retention and that a locked version can't be deleted |
| Duplicati | two backups with 5 MB volumes; `test all --full-remote-verification=true`; restore versions 0 and 1; `delete --version=1`; `compact`; test again; rebuild the local database from the bucket (`repair` with a new `--dbpath`, the lost-NAS case); restore from it. Object Lock variant: `--s3-lock-mode=Compliance --remote-file-lock-duration=1D`, then checks that volumes carry COMPLIANCE retention |
| AWS CLI v2 | default flexible checksums (aws-chunked with a CRC trailer); `s3 sync` up, down and `--delete`; multipart; `put-object --checksum-algorithm` CRC32, CRC32C, SHA1, SHA256 and CRC64NVME, with `head-object --checksum-mode ENABLED`; presigned GET with curl; versions; `put-object-retention` COMPLIANCE and a refused version delete; legal hold |
| crash variant (all) | a 160 MiB backup is started; fs3 gets SIGKILL once 40 MiB is stored and is restarted on the same data; the tool reruns (after `restic unlock` or Duplicati `repair`), verifies and restores |

## Settings that work

All of these tools use **path-style** addressing against fs3, and any
region name (fs3 accepts `us-east-1`). Use the endpoint as
`http(s)://host:port` with no bucket in the host name.

| Tool | Settings |
|---|---|
| restic | `-r s3:https://nas.lan:9000/bucket/path`; `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`. Private CA: `--cacert ca.pem`. |
| rclone | `type = s3`, `provider = Other`, `endpoint = https://nas.lan:9000`, `force_path_style = true` (the default for `Other`), `region = us-east-1`. Private CA: `--ca-cert ca.pem`. |
| Kopia | `kopia repository create s3 --endpoint nas.lan:9000 --bucket … --region us-east-1` (add `--disable-tls` for plain HTTP; `--root-ca-pem-path ca.pem` for a private CA). The endpoint has **no scheme**. Immutability: `--retention-mode COMPLIANCE --retention-period <d>` on a bucket created with Object Lock. |
| Duplicati | Storage type "S3 compatible"; server `nas.lan:9000` (custom server URL); "Use SSL" to match the listener; client library AWS (default); advanced option `s3-ext-forcepathstyle=true`; leave the bucket region (`s3-location-constraint`) empty. Immutability: `--s3-lock-mode=Compliance` (or Governance) and `--remote-file-lock-duration`. The bucket must be created with Object Lock. |
| AWS CLI v2 | `--endpoint-url https://nas.lan:9000` and path-style (`s3 = addressing_style = path` in the config). The default checksum mode (`when_supported`) works; nothing needs turning off. |

The bucket itself is created with any S3 client (`aws s3api
create-bucket`, add `--object-lock-enabled-for-bucket` for an
immutable target). Duplicati and rclone can also create it.

## Caveats

- **Object Lock buckets must be created with Object Lock.** fs3 doesn't
  turn it on for an existing bucket. Restic, rclone and the AWS CLI work
  on a lock bucket without setting retention themselves; Kopia and
  Duplicati set COMPLIANCE or GOVERNANCE retention per object.
  - Pruning on a lock bucket only adds delete markers. The old versions
    stay until their retention ends.
  - With versioning alone (no lock), pruned data also stays as
    noncurrent versions. Add a lifecycle rule with
    `NoncurrentVersionExpiration` to reclaim space.
- **Duplicati exit codes:** `backup` exits 1 when nothing changed. That
  is success, not an error.
- **Crash consistency:** after fs3 is killed mid-backup, every tool
  recovered:
  - restic: `restic unlock` if its lock is stale;
  - Duplicati: `repair` before the next backup;
  - Kopia and rclone simply rerun;
  - AWS CLI: an interrupted multipart upload may stay behind and is
    listed by `list-multipart-uploads`; fs3's MPU GC reaps it after
    `--mpu-gc-max-age`.
- **Virtual-hosted addressing is not supported.** A tool that insists
  on `bucket.host` names needs a DNS-free path-style option.

## Bugs found and fixed

| Found by | Bug | Fix | Regression test |
|---|---|---|---|
| restic (minio-go) | A request sent while the previous response was still being written on a keep-alive connection was swallowed: the paused HTTP parser was fed the new bytes and returned the old pause position. The client then waited for the 60 s idle timeout, so restic took 60 s for some backups and restores over plain HTTP. | `conn_on_readable` buffers bytes that arrive while a response is going out and the parser is paused at the end of the message; `conn_on_writable` parses them once the response is done. | `tests/test_e2e_keepalive.sh` (fails on the old code) |
| (replication work) | Error responses to `HEAD` carried an XML body. | Fixed in the replication PR. | `test_e2e_repl` |

## Running it

```sh
sudo tests/compat/install-tools.sh          # pinned versions into /opt/compat-tools
make compat                                 # all tools × all variants (~6 minutes)
COMPAT_ONLY="restic kopia" COMPAT_VARIANTS="plain lock" make compat
```

- A missing tool prints `SKIP`, or fails under `FS3_TEST_STRICT=1`.
- Failing variants copy the tool's log and the fs3 log to
  `tests/compat/logs/`.
- The summary is written to `tests/compat/last-run.txt`.
