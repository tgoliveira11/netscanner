# NetScanner agent installer (Windows / PowerShell).
#   irm https://<host>/install.ps1 | iex
#
# Installs prerequisites (Node 20+, pnpm, optionally nmap), fetches NetScanner,
# builds the bundled dashboard, and registers a Scheduled Task that runs the
# agent on 127.0.0.1:4000 at logon.
#
# Env overrides: NETSCANNER_HOME, NETSCANNER_REPO, NETSCANNER_SRC, NETSCANNER_PORT, NO_SERVICE=1
$ErrorActionPreference = 'Stop'

$Home_       = if ($env:NETSCANNER_HOME) { $env:NETSCANNER_HOME } else { Join-Path $HOME '.netscanner' }
$Repo        = if ($env:NETSCANNER_REPO) { $env:NETSCANNER_REPO } else { 'https://github.com/netscanner/netscanner.git' }
$Port        = if ($env:NETSCANNER_PORT) { $env:NETSCANNER_PORT } else { '4000' }
$TaskName    = 'NetScannerAgent'

function Log($m)  { Write-Host "[netscanner] $m" -ForegroundColor Cyan }
function Ok($m)   { Write-Host "[netscanner] $m" -ForegroundColor Green }
function Warn($m) { Write-Host "[netscanner] $m" -ForegroundColor Yellow }
function Have($c) { [bool](Get-Command $c -ErrorAction SilentlyContinue) }

function Install-Pkg($winget, $choco) {
  if (Have winget) { winget install -e --id $winget --accept-source-agreements --accept-package-agreements | Out-Null }
  elseif (Have choco) { choco install -y $choco | Out-Null }
  else { Warn "instale manualmente: $winget" }
}

# --- prerequisites ---
function Ensure-Node {
  if (Have node) {
    $v = (node -v).TrimStart('v').Split('.')[0]
    if ([int]$v -ge 20) { Ok "Node $(node -v) presente"; return }
  }
  Log 'instalando Node.js 20+…'
  Install-Pkg 'OpenJS.NodeJS.LTS' 'nodejs-lts'
  $env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path','User')
  if (-not (Have node)) { throw 'Node 20+ é obrigatório. Reabra o PowerShell e rode de novo.' }
}
function Ensure-Pnpm {
  if (Have pnpm) { Ok "pnpm $(pnpm -v) presente"; return }
  Log 'instalando pnpm…'
  if (Have corepack) { corepack enable | Out-Null; corepack prepare pnpm@9.15.9 --activate }
  elseif (Have npm) { npm install -g pnpm@9.15.9 }
  else { throw 'não foi possível instalar o pnpm (sem corepack/npm)' }
  Ok "pnpm $(pnpm -v)"
}
function Ensure-Git  { if (-not (Have git)) { Log 'instalando git…'; Install-Pkg 'Git.Git' 'git' } }
function Ensure-Nmap { if (Have nmap) { Ok 'nmap presente' } else { Log 'instalando nmap (opcional)…'; Install-Pkg 'Insecure.Nmap' 'nmap' } }

Ensure-Node; Ensure-Pnpm; Ensure-Nmap

# --- fetch source ---
if ($env:NETSCANNER_SRC) {
  Log "copiando fonte de $($env:NETSCANNER_SRC)…"
  New-Item -ItemType Directory -Force -Path $Home_ | Out-Null
  robocopy $env:NETSCANNER_SRC $Home_ /MIR /XD node_modules .next out /XF *.db | Out-Null
} elseif (Test-Path (Join-Path $Home_ '.git')) {
  Log 'atualizando instalação…'; git -C $Home_ pull --ff-only
} else {
  Ensure-Git; Log "clonando $Repo…"; git clone --depth 1 $Repo $Home_
}

# --- build ---
Push-Location $Home_
$env:DATABASE_URL = 'file:./netscanner.db'   # Prisma CLI reads this from the env
Log 'instalando dependências…';         pnpm install
Log 'preparando banco (Prisma)…';       pnpm --filter '@netscanner/inventory' db:generate; pnpm --filter '@netscanner/inventory' db:push
Log 'compilando o dashboard…';          $env:BUILD_STATIC='1'; pnpm --filter '@netscanner/web' build; Remove-Item Env:\BUILD_STATIC
Ok 'build concluído'
Pop-Location

# --- runner + service ---
$Runner = Join-Path $Home_ 'agent-run.ps1'
@"
`$env:GATEWAY_PORT='$Port'
`$env:GATEWAY_HOST='127.0.0.1'
`$env:DATABASE_URL='file:./netscanner.db'
`$env:NODE_ENV='production'
Set-Location '$Home_'
pnpm --filter '@netscanner/gateway' start
"@ | Set-Content -Encoding UTF8 $Runner

if ($env:NO_SERVICE -eq '1') { Ok 'iniciando em foreground…'; & powershell -ExecutionPolicy Bypass -File $Runner; exit 0 }

Log 'registrando Scheduled Task (logon)…'
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Runner`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Ok 'serviço (Scheduled Task) registrado e iniciado'

# --- wait for health ---
Log 'aguardando o agente responder…'
for ($i = 0; $i -lt 30; $i++) {
  try {
    Invoke-RestMethod "http://127.0.0.1:$Port/api/health" -TimeoutSec 2 | Out-Null
    Ok "agente no ar → http://localhost:$Port"
    Start-Process "http://localhost:$Port"
    exit 0
  } catch { Start-Sleep -Seconds 1 }
}
Warn "o agente ainda não respondeu — veja o log via a Scheduled Task '$TaskName'"
