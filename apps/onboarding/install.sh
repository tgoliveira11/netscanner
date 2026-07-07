#!/usr/bin/env bash
#
# NetScanner agent installer (macOS / Linux).
#   curl -fsSL https://<host>/install.sh | bash
#
# Installs prerequisites (Node 20+, pnpm, optionally nmap), fetches NetScanner,
# builds the bundled dashboard, and registers a background service (launchd on
# macOS, systemd --user on Linux) that runs the agent on 127.0.0.1:4000.
#
# Env overrides:
#   NETSCANNER_HOME  install dir           (default: $HOME/.netscanner)
#   NETSCANNER_REPO  git URL to clone      (default: the public repo)
#   NETSCANNER_SRC   local source to copy  (skips git clone; for offline/dev)
#   NETSCANNER_PORT  agent port            (default: 4000)
#   NO_SERVICE=1     skip service install; run in foreground instead
set -euo pipefail

NETSCANNER_HOME="${NETSCANNER_HOME:-$HOME/.netscanner}"
NETSCANNER_REPO="${NETSCANNER_REPO:-https://github.com/netscanner/netscanner.git}"
NETSCANNER_PORT="${NETSCANNER_PORT:-4000}"

c_info='\033[36m'; c_ok='\033[32m'; c_warn='\033[33m'; c_err='\033[31m'; c_off='\033[0m'
log()  { printf "${c_info}[netscanner]${c_off} %s\n" "$*"; }
ok()   { printf "${c_ok}[netscanner]${c_off} %s\n" "$*"; }
warn() { printf "${c_warn}[netscanner]${c_off} %s\n" "$*"; }
die()  { printf "${c_err}[netscanner]${c_off} %s\n" "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

case "$(uname -s)" in
  Darwin) OS=macos ;;
  Linux)  OS=linux ;;
  *) die "SO não suportado por este script: $(uname -s). Veja o README." ;;
esac
log "SO detectado: $OS"

# --- prerequisites ---------------------------------------------------------
ensure_node() {
  if have node && [ "$(node -v | sed 's/v//; s/\..*//')" -ge 20 ]; then
    ok "Node $(node -v) presente"; return
  fi
  log "instalando Node.js 20+…"
  if [ "$OS" = macos ]; then
    have brew || die "Homebrew não encontrado. Instale em https://brew.sh e rode de novo."
    brew install node@20 && brew link --overwrite --force node@20 || true
  else
    if have apt-get; then
      curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - && sudo apt-get install -y nodejs
    elif have dnf; then sudo dnf install -y nodejs
    elif have pacman; then sudo pacman -Sy --noconfirm nodejs npm
    else warn "gerenciador de pacotes não reconhecido — instale Node 20+ manualmente"; fi
  fi
  have node || die "Node 20+ é obrigatório."
}

ensure_pnpm() {
  if have pnpm; then ok "pnpm $(pnpm -v) presente"; return; fi
  log "instalando pnpm…"
  if have corepack; then corepack enable >/dev/null 2>&1 || true; corepack prepare pnpm@9.15.9 --activate
  elif have npm; then npm install -g pnpm@9.15.9
  else die "não foi possível instalar o pnpm (sem corepack/npm)"; fi
  have pnpm || die "pnpm não disponível após a instalação"
  ok "pnpm $(pnpm -v)"
}

ensure_git() {
  have git && return
  log "instalando git…"
  if [ "$OS" = macos ]; then brew install git
  elif have apt-get; then sudo apt-get install -y git
  elif have dnf; then sudo dnf install -y git
  elif have pacman; then sudo pacman -Sy --noconfirm git; fi
}

ensure_nmap() { # optional — enables deep fingerprinting
  have nmap && { ok "nmap presente"; return; }
  log "instalando nmap (opcional)…"
  if [ "$OS" = macos ]; then brew install nmap || warn "nmap não instalado (segue sem ele)"
  elif have apt-get; then sudo apt-get install -y nmap || warn "nmap não instalado"
  elif have dnf; then sudo dnf install -y nmap || warn "nmap não instalado"
  elif have pacman; then sudo pacman -Sy --noconfirm nmap || warn "nmap não instalado"
  else warn "instale nmap manualmente para fingerprint profundo"; fi
}

ensure_node
ensure_pnpm
ensure_nmap

# --- fetch source ----------------------------------------------------------
if [ -n "${NETSCANNER_SRC:-}" ]; then
  log "copiando fonte de $NETSCANNER_SRC…"
  mkdir -p "$NETSCANNER_HOME"
  rsync -a --delete --exclude node_modules --exclude .next --exclude out --exclude '*.db' \
    "$NETSCANNER_SRC"/ "$NETSCANNER_HOME"/
elif [ -d "$NETSCANNER_HOME/.git" ]; then
  log "atualizando instalação em $NETSCANNER_HOME…"
  git -C "$NETSCANNER_HOME" pull --ff-only
else
  ensure_git
  log "clonando $NETSCANNER_REPO → $NETSCANNER_HOME…"
  git clone --depth 1 "$NETSCANNER_REPO" "$NETSCANNER_HOME"
fi

# --- build -----------------------------------------------------------------
cd "$NETSCANNER_HOME"
# Prisma CLI reads DATABASE_URL from the env; resolves relative to the schema dir.
export DATABASE_URL="file:./netscanner.db"
log "instalando dependências…";           pnpm install
log "preparando banco (Prisma/SQLite)…";   pnpm --filter @netscanner/inventory db:generate && pnpm --filter @netscanner/inventory db:push
log "compilando o dashboard…";             BUILD_STATIC=1 pnpm --filter @netscanner/web build
ok "build concluído"

# --- run / service ---------------------------------------------------------
NODE_BIN="$(dirname "$(command -v node)")"
RUNNER="$NETSCANNER_HOME/agent-run.sh"
cat > "$RUNNER" <<EOF
#!/usr/bin/env bash
export PATH="$NODE_BIN:\$PATH"
export GATEWAY_PORT="$NETSCANNER_PORT"
export GATEWAY_HOST="127.0.0.1"
export DATABASE_URL="file:./netscanner.db"
export NODE_ENV="production"
cd "$NETSCANNER_HOME"
exec pnpm --filter @netscanner/gateway start
EOF
chmod +x "$RUNNER"

if [ "${NO_SERVICE:-0}" = "1" ]; then
  ok "iniciando em foreground (Ctrl+C para sair)…"
  exec "$RUNNER"
fi

if [ "$OS" = macos ]; then
  PLIST="$HOME/Library/LaunchAgents/com.netscanner.agent.plist"
  mkdir -p "$HOME/Library/LaunchAgents"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.netscanner.agent</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$RUNNER</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$NETSCANNER_HOME/agent.log</string>
  <key>StandardErrorPath</key><string>$NETSCANNER_HOME/agent.log</string>
</dict></plist>
EOF
  launchctl unload "$PLIST" >/dev/null 2>&1 || true
  launchctl load -w "$PLIST"
  ok "serviço launchd instalado e iniciado"
else
  UNIT_DIR="$HOME/.config/systemd/user"; mkdir -p "$UNIT_DIR"
  cat > "$UNIT_DIR/netscanner.service" <<EOF
[Unit]
Description=NetScanner local agent
After=network-online.target

[Service]
ExecStart=/bin/bash $RUNNER
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now netscanner.service
  loginctl enable-linger "$USER" >/dev/null 2>&1 || warn "não foi possível habilitar linger (o agente para ao deslogar)"
  ok "serviço systemd (--user) instalado e iniciado"
fi

# --- wait for health -------------------------------------------------------
log "aguardando o agente responder…"
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$NETSCANNER_PORT/api/health" >/dev/null 2>&1; then
    ok "agente no ar → http://localhost:$NETSCANNER_PORT"
    have open && open "http://localhost:$NETSCANNER_PORT" 2>/dev/null || true
    have xdg-open && xdg-open "http://localhost:$NETSCANNER_PORT" 2>/dev/null || true
    exit 0
  fi
  sleep 1
done
warn "o agente ainda não respondeu — veja o log em $NETSCANNER_HOME/agent.log"
