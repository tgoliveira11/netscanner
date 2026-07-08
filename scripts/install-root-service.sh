#!/usr/bin/env bash
#
# Promote the NetScanner agent to a ROOT service (macOS LaunchDaemon) so nmap OS
# detection (-O) is always available. Replaces the per-user LaunchAgent.
#
# Run once, preserving your PATH so node/pnpm resolve under root:
#   sudo env "PATH=$PATH" bash scripts/install-root-service.sh
#
# Revert to the unprivileged per-user service later:
#   sudo env "PATH=$PATH" bash scripts/install-root-service.sh uninstall
#   # then re-run the normal installer: bash apps/onboarding/install.sh (NETSCANNER_SRC=...)
#
set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "Rode como root:  sudo env \"PATH=\$PATH\" bash $0"; exit 1; }

REAL_USER="${SUDO_USER:-root}"
REAL_HOME="$(eval echo "~${REAL_USER}")"
NS="${NETSCANNER_HOME:-$REAL_HOME/.netscanner}"
PORT="${NETSCANNER_PORT:-4000}"
USER_UID="$(id -u "$REAL_USER")"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DAEMON_PLIST="/Library/LaunchDaemons/com.netscanner.agent.plist"
AGENT_PLIST="$REAL_HOME/Library/LaunchAgents/com.netscanner.agent.plist"
CTL_DST="/usr/local/bin/netscanner-ctl"
SUDOERS_FILE="/etc/sudoers.d/netscanner"
TOKEN_FILE="$NS/.agent-control-token"

remove_user_agent() {
  launchctl bootout "gui/$USER_UID/com.netscanner.agent" 2>/dev/null || true
  rm -f "$AGENT_PLIST"
}

if [ "${1:-}" = "uninstall" ]; then
  echo "[root-svc] removendo o LaunchDaemon…"
  launchctl bootout system "$DAEMON_PLIST" 2>/dev/null || true
  rm -f "$DAEMON_PLIST" "$NS/agent-run-root.sh" "$CTL_DST" "$SUDOERS_FILE"
  chown -R "$REAL_USER" "$NS" 2>/dev/null || true
  echo "[root-svc] pronto. Reinstale o serviço de usuário com o install.sh normal."
  exit 0
fi

command -v node >/dev/null 2>&1 || { echo "node fora do PATH do root. Rode:  sudo env \"PATH=\$PATH\" bash $0"; exit 1; }
command -v pnpm >/dev/null 2>&1 || { echo "pnpm fora do PATH do root. Rode:  sudo env \"PATH=\$PATH\" bash $0"; exit 1; }
[ -d "$NS" ] || { echo "instalação não encontrada em $NS — rode o install.sh normal primeiro."; exit 1; }

NODE_BIN="$(dirname "$(command -v node)")"
PNPM_BIN="$(dirname "$(command -v pnpm)")"
# Homebrew nmap lives outside root's default PATH; include common macOS locations.
BREW_BIN=""
for d in /opt/homebrew/bin /usr/local/bin; do
  [ -x "$d/nmap" ] && BREW_BIN="$d:$BREW_BIN"
done
echo "[root-svc] usuário: $REAL_USER | instalação: $NS | node: $NODE_BIN | pnpm: $PNPM_BIN"

echo "[root-svc] removendo o LaunchAgent de usuário…"
remove_user_agent
lsof -ti "tcp:$PORT" 2>/dev/null | xargs kill 2>/dev/null || true

echo "[root-svc] gerando runner root…"
if [ ! -f "$TOKEN_FILE" ]; then
  uuidgen > "$TOKEN_FILE"
fi
chmod 644 "$TOKEN_FILE"
chown "$REAL_USER" "$TOKEN_FILE"
AGENT_TOKEN="$(tr -d '\n' < "$TOKEN_FILE")"

RUNNER="$NS/agent-run-root.sh"
cat > "$RUNNER" <<EOF
#!/usr/bin/env bash
export PATH="$BREW_BIN$NODE_BIN:$PNPM_BIN:\$PATH"
export GATEWAY_PORT="$PORT"
export GATEWAY_HOST="127.0.0.1"
export DATABASE_URL="file:./netscanner.db"
export NODE_ENV="production"
export AGENT_CONTROL_TOKEN="$AGENT_TOKEN"
cd "$NS"
exec pnpm --filter @netscanner/gateway start
EOF
chmod +x "$RUNNER"

echo "[root-svc] instalando netscanner-ctl (restart sem senha quando agente está down)…"
install -m 755 "$SCRIPT_DIR/netscanner-ctl.sh" "$CTL_DST"
cat > "$SUDOERS_FILE" <<EOF
# NetScanner — allow $REAL_USER to kickstart the root LaunchDaemon without a password.
$REAL_USER ALL=(root) NOPASSWD: $CTL_DST _launchctl_restart
EOF
chmod 440 "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE"

echo "[root-svc] instalando LaunchDaemon (roda como root no boot)…"
cat > "$DAEMON_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.netscanner.agent</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$RUNNER</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$NS/agent.log</string>
  <key>StandardErrorPath</key><string>$NS/agent.log</string>
</dict></plist>
EOF
chown root:wheel "$DAEMON_PLIST"; chmod 644 "$DAEMON_PLIST"

launchctl bootout system "$DAEMON_PLIST" 2>/dev/null || true
launchctl bootstrap system "$DAEMON_PLIST" 2>/dev/null || launchctl load -w "$DAEMON_PLIST"

echo "[root-svc] aguardando o agente responder…"
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && break; sleep 1; done
HEALTH="$(curl -fsS "http://127.0.0.1:$PORT/api/health" 2>/dev/null || true)"
echo "[root-svc] health: $HEALTH"
case "$HEALTH" in
  *'"elevated":true'*) echo "[root-svc] ✓ agente elevado — OS detection habilitada. Rode um scan 'deep' no dashboard.";;
  *) echo "[root-svc] AVISO: não confirmou elevação — veja $NS/agent.log";;
esac
echo "[root-svc] dashboard: http://localhost:$PORT"
echo "[root-svc] controle:  netscanner-ctl status | restart | deploy"
echo "[root-svc] token API:  $TOKEN_FILE (Bearer para POST /api/agent/restart)"
