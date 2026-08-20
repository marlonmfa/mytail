#!/usr/bin/env bash
set -euo pipefail

VERSION="${MYTAIL_VERSION:-0.2.0-alpha.1}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
XAR_BIN="${XAR_BIN:?Set XAR_BIN to a xar 1.6 executable}"
MKBOM_BIN="${MKBOM_BIN:?Set MKBOM_BIN to the bomutils mkbom executable}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PAYLOAD="$WORK/root"
FLAT="$WORK/flat"
SCRIPTS="$WORK/scripts"
CLOUDFLARED_VERSION="${CLOUDFLARED_VERSION:-2026.8.2}"

mkdir -p "$PAYLOAD/usr/local/lib/mytail" "$PAYLOAD/Library/LaunchDaemons" "$FLAT" "$SCRIPTS"
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$PAYLOAD/usr/local/lib/mytail/mytail-agent-x86_64" "$ROOT_DIR/cmd/mytail-agent"
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$PAYLOAD/usr/local/lib/mytail/mytail-agent-arm64" "$ROOT_DIR/cmd/mytail-agent"
curl -fsSL "https://github.com/cloudflare/cloudflared/releases/download/$CLOUDFLARED_VERSION/cloudflared-darwin-amd64.tgz" -o "$WORK/cloudflared-amd64.tgz"
curl -fsSL "https://github.com/cloudflare/cloudflared/releases/download/$CLOUDFLARED_VERSION/cloudflared-darwin-arm64.tgz" -o "$WORK/cloudflared-arm64.tgz"
echo "f1727723c586500e2092368ae21871b3df7ddfd2cb097f22d81bee4a9c458bb4  $WORK/cloudflared-amd64.tgz" | sha256sum -c -
echo "9042c2c5d8b2de78e60f313d5fb31b6c5c1cebde787a3caf1f2c9588084ac442  $WORK/cloudflared-arm64.tgz" | sha256sum -c -
tar -xzf "$WORK/cloudflared-amd64.tgz" -C "$WORK"
mv "$WORK/cloudflared" "$PAYLOAD/usr/local/lib/mytail/cloudflared-x86_64"
tar -xzf "$WORK/cloudflared-arm64.tgz" -C "$WORK"
mv "$WORK/cloudflared" "$PAYLOAD/usr/local/lib/mytail/cloudflared-arm64"
chmod 0755 "$PAYLOAD/usr/local/lib/mytail/cloudflared-"*
install -m 0644 "$ROOT_DIR/packaging/macos/com.hirableaiagents.mytail.plist" "$PAYLOAD/Library/LaunchDaemons/com.hirableaiagents.mytail.plist"
install -m 0755 "$ROOT_DIR/packaging/macos/postinstall" "$SCRIPTS/postinstall"

"$MKBOM_BIN" -u 0 -g 0 "$PAYLOAD" "$FLAT/Bom"
(cd "$PAYLOAD" && find . -print | LC_ALL=C sort | cpio -o --quiet --format odc --owner 0:0 | gzip -9) > "$FLAT/Payload"
(cd "$SCRIPTS" && find . -print | LC_ALL=C sort | cpio -o --quiet --format odc --owner 0:0 | gzip -9) > "$FLAT/Scripts"
file_count=$(find "$PAYLOAD" -mindepth 1 | wc -l)
install_kbytes=$(du -sk "$PAYLOAD" | awk '{print $1}')
cat > "$FLAT/PackageInfo" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<pkg-info format-version="2" identifier="com.hirableaiagents.mytail" version="$VERSION" install-location="/" auth="root" overwrite-permissions="true">
  <payload numberOfFiles="$file_count" installKBytes="$install_kbytes"/>
  <scripts><postinstall file="./postinstall"/></scripts>
</pkg-info>
EOF
mkdir -p "$ROOT_DIR/dist"
(cd "$FLAT" && "$XAR_BIN" -cf "$ROOT_DIR/dist/MyTail-macOS-universal.pkg" Bom PackageInfo Payload Scripts)
test -s "$ROOT_DIR/dist/MyTail-macOS-universal.pkg"
