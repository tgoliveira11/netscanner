#!/usr/bin/env bash
#
# One-off DEEP scan with OS detection (nmap -O), which requires root.
#
# Spins up a TEMPORARY root agent on port 4011 that shares the installed agent's
# database, runs a deep scan (all ports + OS detection), waits for it to finish,
# then shuts itself down and returns DB ownership to your user. The normal agent
# on :4000 keeps running untouched — just refresh it afterwards to see the OS.
#
# Run it like this (the `env "PATH=$PATH"` keeps node/pnpm resolvable under sudo):
#
#   sudo env "PATH=$PATH" bash scripts/deep-scan-root.sh [CIDR]
#
set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "Rode como root:  sudo env \"PATH=\$PATH\" bash $0"; exit 1; }
command -v node >/dev/null 2>&1 || { echo "node não está no PATH do root. Rode:  sudo env \"PATH=\$PATH\" bash $0"; exit 1; }
command -v pnpm >/dev/null 2>&1 || { echo "pnpm não está no PATH do root. Rode:  sudo env \"PATH=\$PATH\" bash $0"; exit 1; }

REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME="$(eval echo "~${REAL_USER}")"
NS="${NETSCANNER_HOME:-$REAL_HOME/.netscanner}"
PORT=4011
LOG="$NS/deep-scan.log"

[ -d "$NS" ] || { echo "instalação não encontrada em $NS"; exit 1; }

# Discover the subnet from the running :4000 agent unless one was passed in.
CIDR="${1:-}"
if [ -z "$CIDR" ]; then
  CIDR="$(curl -fsS http://127.0.0.1:4000/api/network/interfaces 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{console.log(JSON.parse(s).primaryCidr||"")}catch{console.log("")}})')"
fi
[ -n "$CIDR" ] || { echo "não consegui detectar o CIDR — passe como argumento, ex.: ... $0 192.168.1.0/24"; exit 1; }

echo "[deep] usuário: $REAL_USER | instalação: $NS | subnet: $CIDR"
echo "[deep] subindo agente root em :$PORT (elevado → nmap -O)…"
( cd "$NS" && GATEWAY_PORT=$PORT GATEWAY_HOST=127.0.0.1 DATABASE_URL="file:./netscanner.db" NODE_ENV=production \
    pnpm --filter @netscanner/gateway start >"$LOG" 2>&1 ) &

cleanup() {
  echo "[deep] encerrando agente root e restaurando posse do banco…"
  lsof -ti "tcp:$PORT" 2>/dev/null | xargs kill 2>/dev/null || true
  chown -R "$REAL_USER" "$NS/services/inventory/prisma" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for the temp agent to become healthy and confirm it is elevated.
for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$PORT/api/health" >/dev/null 2>&1 && break; sleep 1; done
HEALTH="$(curl -fsS "http://127.0.0.1:$PORT/api/health" 2>/dev/null || true)"
echo "[deep] health: $HEALTH"
case "$HEALTH" in
  *'"elevated":true'*) : ;;
  *) echo "[deep] AVISO: agente não está elevado — a detecção de SO pode não rodar";;
esac

echo "[deep] iniciando scan DEEP em $CIDR (all ports + OS) — pode levar 1–3 min…"
curl -fsS -X POST "http://127.0.0.1:$PORT/api/scans" \
  -H 'content-type: application/json' -H "Origin: http://127.0.0.1:$PORT" \
  -d "{\"cidr\":\"$CIDR\",\"scanType\":\"deep\"}" >/dev/null

# Poll until the scan completes.
while true; do
  ST="$(curl -fsS "http://127.0.0.1:$PORT/api/scans" 2>/dev/null \
    | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const x=JSON.parse(s).scan;console.log((x&&x.status)||"?")}catch{console.log("?")}})')"
  echo "  status: $ST"
  [ "$ST" = "completed" ] && break
  [ "$ST" = "failed" ] && { echo "[deep] scan falhou — veja $LOG"; break; }
  sleep 5
done

echo
echo "[deep] pronto ✓  Atualize http://localhost:4000 para ver o SO por dispositivo."
