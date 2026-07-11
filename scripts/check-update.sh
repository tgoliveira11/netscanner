#!/usr/bin/env bash
# Optional auto-update for dedicated installs (compose or git pull + restart).
set -euo pipefail
ROOT="${NETSCANNER_ROOT:-/opt/netscanner}"
MODE="${NETSCANNER_UPDATE_MODE:-compose}" # compose | git

if [[ "$MODE" == "compose" ]]; then
  cd "$ROOT/deploy/linux"
  docker compose pull
  docker compose up -d
  exit 0
fi

cd "$ROOT"
git fetch --tags origin
LOCAL="$(git rev-parse HEAD)"
REMOTE="$(git rev-parse origin/main)"
if [[ "$LOCAL" != "$REMOTE" ]]; then
  git merge --ff-only origin/main
  (cd "$ROOT" && pnpm install --frozen-lockfile)
  systemctl restart netscanner || true
fi
