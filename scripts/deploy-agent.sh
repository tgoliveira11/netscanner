#!/usr/bin/env bash
#
# Deploy local changes to ~/.netscanner and restart the agent.
# No sudo when the agent is running (restart via localhost API).
#
#   bash scripts/deploy-agent.sh
#   NETSCANNER_SRC=~/Projects/netscanner bash scripts/deploy-agent.sh
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export NETSCANNER_SRC="${NETSCANNER_SRC:-$ROOT}"

if [ -x /usr/local/bin/netscanner-ctl ]; then
  exec /usr/local/bin/netscanner-ctl deploy
fi

exec bash "$ROOT/scripts/netscanner-ctl.sh" deploy
