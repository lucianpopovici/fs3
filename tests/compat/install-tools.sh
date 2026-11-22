#!/usr/bin/env bash
#
# tests/compat/install-tools.sh — install the pinned backup tools the
# compatibility matrix runs against, into $PREFIX (default
# /opt/compat-tools; add $PREFIX/bin to PATH or set COMPAT_TOOLS).
# Linux x86_64. Needs curl, unzip, bunzip2, git and python3-venv.
#
set -eu
PREFIX=${PREFIX:-/opt/compat-tools}
RESTIC=0.20.0
RCLONE=1.76.0
KOPIA=0.23.1
DUPLICATI=2.4.1.0_stable_2026-10-29
AWSCLI=2.42.1

mkdir -p "$PREFIX/bin"
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
cd "$W"
gh=https://github.com

curl -fsSL -o restic.bz2 "$gh/restic/restic/releases/download/v$RESTIC/restic_${RESTIC}_linux_amd64.bz2"
bunzip2 restic.bz2 && install -m755 restic "$PREFIX/bin/restic"

curl -fsSL -o rclone.zip "$gh/rclone/rclone/releases/download/v$RCLONE/rclone-v$RCLONE-linux-amd64.zip"
unzip -q rclone.zip && install -m755 "rclone-v$RCLONE-linux-amd64/rclone" "$PREFIX/bin/rclone"

curl -fsSL -o kopia.tgz "$gh/kopia/kopia/releases/download/v$KOPIA/kopia-$KOPIA-linux-x64.tar.gz"
tar xzf kopia.tgz && install -m755 "kopia-$KOPIA-linux-x64/kopia" "$PREFIX/bin/kopia"

curl -fsSL -o dup.zip "$gh/duplicati/duplicati/releases/download/v$DUPLICATI/duplicati-$DUPLICATI-linux-x64-cli.zip"
rm -rf "$PREFIX/duplicati" && mkdir -p "$PREFIX/duplicati" && unzip -q dup.zip -d "$PREFIX/duplicati"
ln -sf "$(find "$PREFIX/duplicati" -name duplicati-cli -type f | head -1)" "$PREFIX/bin/duplicati-cli"

# AWS CLI v2 isn't published as a release asset; build it from its tag.
git clone -q --depth 1 -b "$AWSCLI" https://github.com/aws/aws-cli awscli
python3 -m venv "$PREFIX/awsv2"
"$PREFIX/awsv2/bin/pip" install -q ./awscli
ln -sf "$PREFIX/awsv2/bin/aws" "$PREFIX/bin/aws2"

"$PREFIX/bin/restic" version
"$PREFIX/bin/rclone" version | head -1
"$PREFIX/bin/kopia" --version
echo "duplicati $DUPLICATI"
"$PREFIX/bin/aws2" --version
