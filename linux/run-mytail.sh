#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run-mytail.sh [--server URL] [--token TOKEN] [--no-open]

Enroll this Linux machine and run MyTail directly in the foreground.
Run without options to be prompted for the server URL and machine token.
EOF
}

server_url="${MYTAIL_SERVER_URL:-}"
machine_token="${MYTAIL_MACHINE_TOKEN:-}"
open_dashboard=1

while (($#)); do
  case "$1" in
    --server) [[ $# -ge 2 ]] || { echo "--server requires a URL" >&2; exit 2; }; server_url=$2; shift 2 ;;
    --token) [[ $# -ge 2 ]] || { echo "--token requires a token" >&2; exit 2; }; machine_token=$2; shift 2 ;;
    --no-open) open_dashboard=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# The agent stores its device identity in /etc/mytail and must run as root.
# Elevate before prompting so the token is not copied into sudo's command line.
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || { echo "MyTail requires root; install sudo or run this script as root." >&2; exit 1; }
  export MYTAIL_SERVER_URL="$server_url" MYTAIL_MACHINE_TOKEN="$machine_token"
  elevate_args=()
  ((open_dashboard)) || elevate_args+=(--no-open)
  exec sudo --preserve-env=MYTAIL_SERVER_URL,MYTAIL_MACHINE_TOKEN bash "$0" "${elevate_args[@]}"
fi

agent="${MYTAIL_AGENT:-}"
if [[ -z "$agent" ]]; then
  if command -v mytail-agent >/dev/null 2>&1; then
    agent=$(command -v mytail-agent)
  elif [[ -x "$(dirname "$0")/mytail-agent" ]]; then
    agent="$(dirname "$0")/mytail-agent"
  else
    echo "mytail-agent was not found. Install MyTail or place mytail-agent beside this script." >&2
    exit 1
  fi
fi

[[ -n "$server_url" ]] || read -r -p "MyTail server URL: " server_url
if [[ -z "$machine_token" ]]; then
  read -r -s -p "Machine enrollment token: " machine_token
  echo
fi
[[ -n "$server_url" && -n "$machine_token" ]] || { echo "Server URL and token are required." >&2; exit 2; }

export MYTAIL_SERVER_URL="$server_url" MYTAIL_MACHINE_TOKEN="$machine_token"
args=()
((open_dashboard)) && args+=(--open)
echo "Starting MyTail. Press Ctrl+C to disconnect this directly-run agent."
exec "$agent" "${args[@]}"
