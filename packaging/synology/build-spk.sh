#!/bin/sh
# build-spk.sh — assemble a Synology .spk for fs3.
#
# Prereqs: the static TLS build of fs3 at ../../fs3-tls-static (libssl and
# libcrypto linked in: `make fs3-tls-static`), or pass the binary path as
# $1. The package ships the TLS build so replication can reach HTTPS
# targets (B2, AWS, another NAS behind HTTPS) and native TLS is available.
# Produces fs3-<version>.spk in this dir.
#
# Run from packaging/synology/:   ./build-spk.sh [path-to-fs3-binary]
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
PROJ_ROOT="$(cd "${HERE}/../.." && pwd)"

VERSION="${FS3_SPK_VERSION:-0.8.0-1}"
BIN="${1:-${PROJ_ROOT}/fs3-tls-static}"

if [ ! -f "${BIN}" ]; then
    echo "error: fs3 binary not found at ${BIN}" >&2
    echo "build it first with: make fs3-tls-static" >&2
    exit 1
fi
# Refuse a non-TLS binary by default: replication to HTTPS targets would
# silently fail. FS3_SPK_ALLOW_NO_TLS=1 builds one anyway.
if ! "${BIN}" --build-info 2>/dev/null | grep -qx 'tls=yes'; then
    if [ "${FS3_SPK_ALLOW_NO_TLS:-0}" != "1" ]; then
        echo "error: ${BIN} is not a TLS build (make fs3-tls-static)," >&2
        echo "       or set FS3_SPK_ALLOW_NO_TLS=1 to package it anyway" >&2
        exit 1
    fi
fi

BUILD="$(mktemp -d)"
trap 'rm -rf "${BUILD}"' EXIT

# ---- package.tgz: everything that lands under SYNOPKG_PKGDEST ----
mkdir -p "${BUILD}/pkg/bin"
cp "${BIN}" "${BUILD}/pkg/bin/fs3"
chmod 755 "${BUILD}/pkg/bin/fs3"
# Optional root helper for --lock-immutable (round 2, item 9). It is not
# started by the package: DSM runs packages unprivileged (see CHANGELOG).
if [ -f "${PROJ_ROOT}/fs3-lockd" ]; then
    cp "${PROJ_ROOT}/fs3-lockd" "${BUILD}/pkg/bin/fs3-lockd"
    chmod 755 "${BUILD}/pkg/bin/fs3-lockd"
fi
cp "${PROJ_ROOT}/README.md"  "${BUILD}/pkg/README.md"  2>/dev/null || true
cp "${PROJ_ROOT}/LICENSE"    "${BUILD}/pkg/LICENSE"     2>/dev/null || true

# ui directory ships inside package.tgz and is linked into webman by DSM
cp -r "${HERE}/ui" "${BUILD}/pkg/ui"
# conf schema shared by start-stop-status and the tile (ui/index.cgi)
mkdir -p "${BUILD}/pkg/lib"
cp "${HERE}/lib/fs3-conf.sh" "${BUILD}/pkg/lib/fs3-conf.sh"
chmod 644 "${BUILD}/pkg/lib/fs3-conf.sh"

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
