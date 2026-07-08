#!/bin/sh
# Build and install pfSense-pkg-NetScanner on this firewall.
# Run in pfSense: Diagnostics → Command Prompt (as root), or SSH:
#   fetch -qo - https://raw.githubusercontent.com/tgoliveira11/netscanner/main/integrations/pfsense/tools/build-on-pfsense.sh | sh
set -eu

REPO="${NETSCANNER_REPO:-https://github.com/tgoliveira11/netscanner.git}"
BRANCH="${NETSCANNER_BRANCH:-main}"
BUILD_ROOT="/tmp/netscanner-pkg-build"
PKG_DIR="${BUILD_ROOT}/integrations/pfsense/pfSense-pkg-NetScanner"
PFSENSE_VER="$(cat /etc/version | awk '{print $1}')"

if [ "$(id -u)" -ne 0 ]; then
	echo "Run as root" >&2
	exit 1
fi

echo "==> pfSense ${PFSENSE_VER}"

if [ -f "${PKG_DIR}/Makefile" ]; then
	echo "==> Using existing source at ${PKG_DIR}"
else
	echo "==> Fetching source from ${REPO} (${BRANCH})..."
	rm -rf "${BUILD_ROOT}"
	mkdir -p "${BUILD_ROOT}"
	if command -v git >/dev/null 2>&1; then
		git clone --depth 1 --branch "${BRANCH}" "${REPO}" "${BUILD_ROOT}"
	else
		TGZ="/tmp/netscanner-src.tgz"
		fetch -qo "${TGZ}" "https://github.com/tgoliveira11/netscanner/archive/refs/heads/${BRANCH}.tar.gz"
		tar xf "${TGZ}" -C "${BUILD_ROOT}" --strip-components 1
	fi
fi

if [ ! -f "${PKG_DIR}/Makefile" ]; then
	echo "Package source missing at ${PKG_DIR}" >&2
	exit 1
fi

export ALLOW_UNSUPPORTED_SYSTEM=yes
cd "${PKG_DIR}"
echo "==> Building package..."
make clean package

BUILT="$(ls work/pkg/*.pkg | head -1)"
RELEASE="/tmp/pfSense-${PFSENSE_VER}-pkg-NetScanner.pkg"
cp "${BUILT}" "${RELEASE}"

echo "==> Installing..."
pkg-static -C /dev/null add "${BUILT}"

echo ""
echo "Done."
echo "  Installed : ${BUILT}"
echo "  Release   : ${RELEASE}  (upload this file to GitHub releases)"
echo "  GUI       : Services → NetScanner Settings"
echo ""
echo "Configure Agent URL + Push token, then Save."
