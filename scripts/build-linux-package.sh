#!/usr/bin/env bash
set -euo pipefail

VERSION="${MYTAIL_VERSION:-0.1.0-alpha.1}"
ARCH="${MYTAIL_ARCH:-amd64}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT
PKG="$BUILD_DIR/mytail-agent"

mkdir -p "$PKG/DEBIAN" "$PKG/usr/bin" "$PKG/lib/systemd/system" "$PKG/etc/mytail"
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$PKG/usr/bin/mytail-agent" "$ROOT_DIR/cmd/mytail-agent"
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
Description: Transparent consent agent for MyTail remote support
 Shows customer-approved support windows in a local dashboard. This alpha
 does not execute commands or create network tunnels.
EOF
mkdir -p "$ROOT_DIR/dist"
dpkg-deb --root-owner-group --build "$PKG" "$ROOT_DIR/dist/MyTail-Linux-amd64.deb"
