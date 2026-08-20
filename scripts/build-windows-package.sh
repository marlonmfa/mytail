#!/usr/bin/env bash
set -euo pipefail
VERSION="${MYTAIL_VERSION:-0.2.0-alpha.1}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLOUDFLARED_VERSION="${CLOUDFLARED_VERSION:-2026.8.2}"
CLOUDFLARED_SHA256="c29eee2b121f5436a642eed69fd9767da7e7b8c510fa50aaa130337f931357b5"
mkdir -p "$ROOT_DIR/dist"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=$VERSION" -o "$ROOT_DIR/dist/mytail-agent-windows-amd64.exe" "$ROOT_DIR/cmd/mytail-agent"
curl -fsSL "https://github.com/cloudflare/cloudflared/releases/download/$CLOUDFLARED_VERSION/cloudflared-windows-amd64.exe" -o "$ROOT_DIR/dist/cloudflared-windows-amd64.exe"
echo "$CLOUDFLARED_SHA256  $ROOT_DIR/dist/cloudflared-windows-amd64.exe" | sha256sum -c -
(cd "$ROOT_DIR/packaging/windows" && makensis -V2 mytail.nsi)
test -s "$ROOT_DIR/dist/MyTail-Setup-Windows-x64.exe"
