#!/bin/sh
# build-spk.sh — assemble a Synology .spk for fs3.
#
# Prereqs: a statically-linked (libcrypto) fs3 binary at ../../fs3-static,
# or pass the binary path as $1. Produces fs3-<version>.spk in this dir.
#
# Run from packaging/synology/:   ./build-spk.sh [path-to-fs3-binary]
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
PROJ_ROOT="$(cd "${HERE}/../.." && pwd)"

VERSION="${FS3_SPK_VERSION:-0.8.0-1}"
BIN="${1:-${PROJ_ROOT}/fs3-static}"

if [ ! -f "${BIN}" ]; then
    echo "error: fs3 binary not found at ${BIN}" >&2
    echo "build it first with: make fs3-static" >&2
    exit 1
fi

BUILD="$(mktemp -d)"
trap 'rm -rf "${BUILD}"' EXIT

# ---- package.tgz: everything that lands under SYNOPKG_PKGDEST ----
mkdir -p "${BUILD}/pkg/bin"
cp "${BIN}" "${BUILD}/pkg/bin/fs3"
chmod 755 "${BUILD}/pkg/bin/fs3"
cp "${PROJ_ROOT}/README.md"  "${BUILD}/pkg/README.md"  2>/dev/null || true
cp "${PROJ_ROOT}/LICENSE"    "${BUILD}/pkg/LICENSE"     2>/dev/null || true

# ui directory ships inside package.tgz and is linked into webman by DSM
cp -r "${HERE}/ui" "${BUILD}/pkg/ui"

( cd "${BUILD}/pkg" && tar czf "${BUILD}/package.tgz" . )

# ---- INFO with version + computed checksum ----
sed "s/__VERSION__/${VERSION}/" "${HERE}/INFO.in" > "${BUILD}/INFO"
EXTRACTSIZE="$(du -sk "${BUILD}/pkg" | cut -f1)"
echo "extractsize=\"${EXTRACTSIZE}\"" >> "${BUILD}/INFO"
CHECKSUM="$(md5sum "${BUILD}/package.tgz" | cut -d' ' -f1)"
echo "checksum=\"${CHECKSUM}\"" >> "${BUILD}/INFO"

# ---- assemble spk tree ----
mkdir -p "${BUILD}/spk/scripts" "${BUILD}/spk/conf" "${BUILD}/spk/WIZARD_UIFILES"
cp "${BUILD}/INFO"          "${BUILD}/spk/INFO"
cp "${BUILD}/package.tgz"   "${BUILD}/spk/package.tgz"
cp "${HERE}/scripts/"*      "${BUILD}/spk/scripts/"
cp "${HERE}/conf/"*         "${BUILD}/spk/conf/"
cp "${HERE}/WIZARD_UIFILES/"* "${BUILD}/spk/WIZARD_UIFILES/"
cp "${HERE}/PACKAGE_ICON.PNG"     "${BUILD}/spk/PACKAGE_ICON.PNG"
cp "${HERE}/PACKAGE_ICON_256.PNG" "${BUILD}/spk/PACKAGE_ICON_256.PNG"
cp "${PROJ_ROOT}/LICENSE" "${BUILD}/spk/LICENSE" 2>/dev/null || echo "fs3" > "${BUILD}/spk/LICENSE"
chmod 755 "${BUILD}/spk/scripts/"*

# ---- the .spk is an (uncompressed) tar of the spk tree ----
# Entry names must be bare ("INFO", "package.tgz"), not "./INFO" —
# DSM 7.1's installer rejects ./-prefixed members with "failed to sort
# spks, the spk might not exist or invalid format" (error 263).
OUT="${HERE}/fs3-${VERSION}.spk"
( cd "${BUILD}/spk" && tar cf "${OUT}" -- * )

echo "built: ${OUT}"
echo "  version:     ${VERSION}"
echo "  extractsize: ${EXTRACTSIZE} KB"
echo "  checksum:    ${CHECKSUM}"
