#!/usr/bin/env bash
set -euo pipefail
VERSION="${MYTAIL_VERSION:-0.1.0-alpha.1}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
mkdir -p "$ROOT_DIR/dist"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -H windowsgui -X main.version=$VERSION" -o "$ROOT_DIR/dist/mytail-agent-windows-amd64.exe" "$ROOT_DIR/cmd/mytail-agent"
(cd "$ROOT_DIR/packaging/windows" && makensis -V2 mytail.nsi)
test -s "$ROOT_DIR/dist/MyTail-Setup-Windows-x64.exe"
