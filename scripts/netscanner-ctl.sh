#!/usr/bin/env bash
#
# Control the NetScanner root LaunchDaemon without typing a password each time.
# Installed to /usr/local/bin/netscanner-ctl by install-root-service.sh (NOPASSWD).
#
# Usage:
#   netscanner-ctl status
#   netscanner-ctl restart    # HTTP when agent is up; launchctl fallback when down
#   netscanner-ctl deploy     # rsync repo → ~/.netscanner, pnpm install, db push, restart
#
set -euo pipefail

LABEL="com.netscanner.agent"
DAEMON_PLIST="/Library/LaunchDaemons/com.netscanner.agent.plist"
REAL_USER="${NETSCANNER_USER:-${SUDO_USER:-$USER}}"
REAL_HOME="$(eval echo "~${REAL_USER}")"
NS="${NETSCANNER_HOME:-$REAL_HOME/.netscanner}"
PORT="${NETSCANNER_PORT:-4000}"
TOKEN_FILE="$NS/.agent-control-token"
SRC="${NETSCANNER_SRC:-$REAL_HOME/Projects/netscanner}"

auth_headers() {
  if [ -f "$TOKEN_FILE" ]; then
    printf 'Authorization: Bearer %s' "$(tr -d '\n' < "$TOKEN_FILE")"
  fi
}

api_restart() {
  local headers=()
  local auth
  auth="$(auth_headers)"
  [ -n "$auth" ] && headers=(-H "$auth")
  curl -fsS -X POST "${headers[@]}" "http://127.0.0.1:$PORT/api/agent/restart"
}

launchctl_restart() {
  if [ "$(id -u)" = 0 ]; then
    launchctl kickstart -k "system/$LABEL"
  else
    sudo -n /usr/local/bin/netscanner-ctl _launchctl_restart
  fi
}

cmd_status() {
  local health=""
  health="$(curl -fsS "http://127.0.0.1:$PORT/api/health" 2>/dev/null || true)"
  if [ -n "$health" ]; then
    echo "agent: up ($health)"
  else
    echo "agent: down (no response on :$PORT)"
  fi
  if [ -f "$DAEMON_PLIST" ]; then
    launchctl print "system/$LABEL" 2>/dev/null | rg "state =|last exit code|active count" || true
  else
    echo "LaunchDaemon: not installed ($DAEMON_PLIST)"
  fi
}

cmd_restart() {
  if api_restart 2>/dev/null; then
    echo
    echo "[netscanner-ctl] restarted via API (LaunchDaemon KeepAlive)"
    return 0
  fi
  echo "[netscanner-ctl] API unavailable — using launchctl…"
  launchctl_restart
  echo "[netscanner-ctl] launchctl kickstart sent"
}

cmd_deploy() {
  [ -d "$SRC" ] || { echo "repo não encontrado em $SRC — defina NETSCANNER_SRC"; exit 1; }
  echo "[netscanner-ctl] rsync $SRC → $NS"
  rsync -a --exclude node_modules --exclude .next --exclude out --exclude '*.db' \
    "$SRC/packages" "$SRC/services" "$SRC/apps" "$NS/"
  echo "[netscanner-ctl] pnpm install"
  (cd "$NS" && pnpm install --prod=false --config.confirmModulesPurge=false)
  echo "[netscanner-ctl] prisma db push"
  (cd "$NS/services/inventory" && DATABASE_URL="file:./netscanner.db" pnpm db:push)
  cmd_restart
}

case "${1:-}" in
  status) cmd_status ;;
  restart) cmd_restart ;;
  deploy) cmd_deploy ;;
  _launchctl_restart) launchctl kickstart -k "system/$LABEL" ;;
  *)
    echo "uso: netscanner-ctl {status|restart|deploy}"
    exit 1
    ;;
esac
