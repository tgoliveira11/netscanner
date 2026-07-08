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

# Always use the repo ctl for deploy so BUILD_STATIC / rsync steps stay current.
# (An older /usr/local/bin/netscanner-ctl may omit the static web build.)
exec bash "$ROOT/scripts/netscanner-ctl.sh" deploy
