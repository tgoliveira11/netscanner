#!/bin/sh
# Build and install pfSense-pkg-NetScanner on the firewall (run as root on pfSense).
#
# Usage:
#   fetch -qo - https://raw.githubusercontent.com/netscanner/netscanner/main/integrations/pfsense/tools/install-on-pfsense.sh | sh
#
set -eu

PFSENSE_VERSION="$(cat /etc/version 2>/dev/null | awk '{print $1}')"
PKG_RELEASE_URL="${NETSCANNER_PKG_URL:-https://github.com/netscanner/netscanner/releases/latest/download/pfSense-${PFSENSE_VERSION}-pkg-NetScanner.pkg}"

if [ "$(id -u)" -ne 0 ]; then
	echo "Run as root on pfSense" >&2
	exit 1
fi

if [ -f /etc/version ] && pkg-static -C /dev/null add "${PKG_RELEASE_URL}" 2>/dev/null; then
	echo "Installed from ${PKG_RELEASE_URL}"
	echo "Open pfSense GUI: Services → NetScanner Settings"
	exit 0
fi

echo "Release package not found at ${PKG_RELEASE_URL}" >&2
echo "Building from source on this firewall..." >&2

SRC="${NETSCANNER_PKG_SRC:-/tmp/pfSense-pkg-NetScanner}"
if [ ! -f "${SRC}/Makefile" ]; then
	echo "Copy pfSense-pkg-NetScanner/ to ${SRC} first, e.g.:" >&2
	echo "  scp -r integrations/pfsense/pfSense-pkg-NetScanner root@firewall:${SRC}" >&2
	exit 1
fi

export ALLOW_UNSUPPORTED_SYSTEM=yes
cd "${SRC}"
make clean package
BUILT="$(ls work/pkg/*.pkg | head -1)"
pkg-static -C /dev/null add "${BUILT}"
echo ""
echo "Installed ${BUILT}"
echo "Open pfSense GUI: Services → NetScanner Settings"
