#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INNEXO_ENV="${INNEXO_ENV:-$ROOT_DIR/../innexo.solutions/.env}"

if [[ ! -f "$INNEXO_ENV" ]]; then
  echo "Missing Innexo env file: $INNEXO_ENV" >&2
  exit 1
fi

set -a
source "$INNEXO_ENV"
set +a

: "${VPS_HOST:?VPS_HOST missing from $INNEXO_ENV}"
: "${VPS_USER:?VPS_USER missing from $INNEXO_ENV}"

REMOTE="${VPS_USER}@${VPS_HOST}"
APP_DIR="/opt/mytail"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

cp "$ROOT_DIR/Dockerfile" "$TMP_DIR/"
cp "$ROOT_DIR/server.py" "$TMP_DIR/"
mkdir -p "$TMP_DIR/infrastructure"
cp "$ROOT_DIR/infrastructure/docker-compose.prod.yml" "$TMP_DIR/infrastructure/docker-compose.prod.yml"
cp "$ROOT_DIR/infrastructure/.env.example" "$TMP_DIR/infrastructure/.env.example"

echo "Uploading app bundle to $REMOTE:$APP_DIR"
ssh "$REMOTE" "mkdir -p $APP_DIR/infrastructure"
scp "$TMP_DIR/Dockerfile" "$REMOTE:$APP_DIR/Dockerfile"
scp "$TMP_DIR/server.py" "$REMOTE:$APP_DIR/server.py"
scp "$TMP_DIR/infrastructure/docker-compose.prod.yml" "$REMOTE:$APP_DIR/docker-compose.prod.yml"

echo "Deploy files uploaded."
echo "Next steps on the server:"
echo "1. Create $APP_DIR/.env from infrastructure/.env.example"
echo "2. docker compose -f $APP_DIR/docker-compose.prod.yml up -d --build"
echo "3. Install infrastructure/nginx/support.innexo.solutions.conf into sites-enabled"
