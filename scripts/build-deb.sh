#!/usr/bin/env bash
# Skeleton .deb packager for dedicated Linux installs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${VERSION:-0.2.0}"
ARCH="${ARCH:-amd64}"
OUT="$ROOT/dist"
PKG="netscanner_${VERSION}_${ARCH}"
STAGE="$OUT/$PKG"

rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN" \
  "$STAGE/opt/netscanner" \
  "$STAGE/etc/netscanner" \
  "$STAGE/var/lib/netscanner" \
  "$STAGE/lib/systemd/system"

cat >"$STAGE/DEBIAN/control" <<EOF
Package: netscanner
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: NetScanner <dev@localhost>
Depends: nodejs (>= 20), nmap
Description: NetScanner dedicated LAN agent (multi-agent capable)
EOF

cat >"$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
mkdir -p /var/lib/netscanner /etc/netscanner
if [ ! -f /etc/netscanner/config.env ]; then
  cp /opt/netscanner/deploy/linux/env.dedicated.example /etc/netscanner/config.env || true
fi
systemctl daemon-reload
systemctl enable netscanner.service || true
echo "NetScanner installed. Edit /etc/netscanner/config.env then: systemctl start netscanner"
EOF
chmod 755 "$STAGE/DEBIAN/postinst"

# Copy repo snapshot (production builds should prune node_modules / use release tarball)
rsync -a --exclude node_modules --exclude .git --exclude dist \
  "$ROOT/" "$STAGE/opt/netscanner/"

cp "$ROOT/deploy/linux/netscanner.service" "$STAGE/lib/systemd/system/netscanner.service"
cp "$ROOT/deploy/linux/env.dedicated.example" "$STAGE/etc/netscanner/config.env.example"

mkdir -p "$OUT"
dpkg-deb --build "$STAGE" "$OUT/${PKG}.deb"
echo "Built $OUT/${PKG}.deb"
