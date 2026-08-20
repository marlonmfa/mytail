#!/usr/bin/env bash
set -euo pipefail

VERSION="${MYTAIL_VERSION:-0.2.0-alpha.1}"
ARCH="${MYTAIL_ARCH:-amd64}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT
PKG="$BUILD_DIR/mytail-agent"
CLOUDFLARED_VERSION="${CLOUDFLARED_VERSION:-2026.8.2}"
CLOUDFLARED_SHA256="fcfb02b575a52ca1af2e3267af4e1517bcdeb30ac48c834c69abaed3c0576ad2"

mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/lib/systemd/system" "$PKG/etc/mytail"
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$PKG/usr/bin/mytail-agent" "$ROOT_DIR/cmd/mytail-agent"
curl -fsSL "https://github.com/cloudflare/cloudflared/releases/download/$CLOUDFLARED_VERSION/cloudflared-linux-$ARCH" -o "$PKG/usr/bin/cloudflared"
echo "$CLOUDFLARED_SHA256  $PKG/usr/bin/cloudflared" | sha256sum -c -
chmod 0755 "$PKG/usr/bin/cloudflared"
install -m 0644 "$ROOT_DIR/packaging/linux/mytail-agent.service" "$PKG/lib/systemd/system/mytail-agent.service"
install -m 0755 "$ROOT_DIR/packaging/linux/postinst" "$PKG/DEBIAN/postinst"
install -m 0755 "$ROOT_DIR/packaging/linux/prerm" "$PKG/DEBIAN/prerm"
cat > "$PKG/DEBIAN/control" <<EOF
Package: mytail-agent
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Hirable AI Agents <admin@hirableaiagents.com>
Depends: openssh-client
Description: Transparent consent agent for MyTail remote support
 Runs with root privileges, creates an outbound reverse SSH tunnel only during
 a customer-approved window, and revokes the in-memory operator key at expiry.
EOF
mkdir -p "$ROOT_DIR/dist"
dpkg-deb --root-owner-group --build "$PKG" "$ROOT_DIR/dist/MyTail-Linux-amd64.deb"
