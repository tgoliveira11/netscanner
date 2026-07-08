# NetScanner

An efficient local-network **device scanner & classifier**. It discovers every
host on a subnet (wired or WiFi), fingerprints it, and classifies it in detail —
IP/MAC, vendor, hostname, OS, device type, open ports/services, first/last seen,
online status, and security findings — streamed live to a dashboard.

> ⚠️ **Authorized use only.** Scan networks you own or administer. Port scanning
> and fingerprinting third-party networks may be illegal.

---

## Why the architecture looks like this

Real network discovery (ARP sweeps, ICMP, OS/port fingerprinting) needs OS-level
raw network access. **Browsers cannot do this**, so the scanning engine runs
server-side in Node.js; Next.js/React is the dashboard only.

Two honest limitations, surfaced in the UI:

- **Wired vs WiFi** cannot be reliably determined from a remote host — that data
  lives on the router/switch. It is reported as `unknown` unless a router
  integration (SNMP) provides it. No false certainty.
- Full nmap **OS detection** (`-O`) needs root/sudo. Without it, the engine falls
  back to service/banner heuristics. nmap itself is optional — a pure-Node
  TCP/ARP/mDNS/SSDP core always works and nmap **enriches** it when present.
- **DHCP fingerprints** (option 55) are sniffed locally on the agent's L2
  interfaces (`DHCP_SNIFF_IFACES` / `tcpdump -i any`). Routed VLANs that the Mac
  cannot see at L2 (e.g. guest) need remote capture on the OpenWrt switch
  `br-lan` (`SNMP_SWITCH_HOST` + SSH / `ROUTER_SCRAPE` password).

## Architecture

A **modular monorepo** (pnpm + Turborepo). Each service is an independent package
with strict Clean-Architecture layers — `domain → application → infrastructure →
interface` — with dependencies pointing inward. The gateway is the single
composition root that wires concrete adapters to the domain ports.

```
apps/web            Next.js dashboard (live grid, detail drawer, topology, alerts, export)
services/
  gateway           REST + WebSocket hub, composition root, scan orchestration
  discovery         host discovery (ARP, ICMP sweep, mDNS, SSDP)
  scanner           deep fingerprint (nmap XML + pure-Node TCP fallback)
  classification    rule engine (Strategy) → device type + confidence, security flags
  inventory         persistence (Prisma/SQLite), history, new-device detection, export
packages/
  contracts         shared DTOs, zod schemas, domain event catalogue
  kernel            value objects (MacAddress/IpAddress/Cidr), OUI vendor lookup, Result
  os-abstraction    cross-platform command runner, capability & local-network detection
  logger, config    pino logging, zod-validated env config
```

Services communicate through an **event bus** behind `IEventPublisher` /
`IEventSubscriber` (in-process `EventEmitter` today; swappable to Redis/NATS
without touching the domain). Internal calls go through injected use cases.

### Live scan pipeline

```
scan.start → discovery streams host.discovered
          → scanner fingerprints  → host fingerprint
          → classification        → device.classified
          → inventory persists    → device.new / device.changed
          → gateway pushes every event over WebSocket → dashboard updates live
```

### SOLID, concretely

- **SRP** — one use case = one responsibility; adapters are single-concern.
- **OCP** — classification rules are pluggable `ClassificationRule` strategies
  (`services/classification/src/domain/rules/`); add device types without editing
  the engine.
- **LSP** — every probe implements `IHostProbe`; every scanner `IDeepScanner`.
- **ISP** — narrow ports: `IDeviceRepository`, `IVendorLookup`, `IEventPublisher`.
- **DIP** — application depends on interfaces only; the composition root
  (`services/gateway/src/container.ts`) binds implementations.

## Requirements

- Node ≥ 20, pnpm ≥ 9
- Optional but recommended: **nmap** (`brew install nmap` / `apt install nmap`).
  Run the gateway with `sudo` for OS detection.

## Setup

```bash
pnpm install
pnpm db:generate      # generate Prisma client
pnpm db:push          # create the SQLite schema
cp .env.example .env  # optional; sensible defaults otherwise
```

## Run

```bash
pnpm dev              # gateway (:4000) + web dashboard (:3000)
# or individually:
pnpm dev:api
pnpm dev:web
```

Open http://localhost:3000, confirm the subnet (auto-detected), pick a depth, and
**Start scan**. Devices stream in and classify live.

### Deployment profiles

See **[docs/deployment-profiles.md](docs/deployment-profiles.md)** for ready-made
`config.env` setups: standalone scan, pfSense only, pfSense + managed switch, and
multi-VLAN home lab (`TOPOLOGY_MODE=vlan`).

For OS detection: `sudo pnpm dev:api` (nmap `-O` needs elevation).

If Prisma isn't set up, the gateway automatically falls back to in-memory storage
(non-persistent) — set `PERSISTENCE=memory` to force it.

## Install via website (local agent)

Because a browser can't scan a network, end users install a **local agent** (the
gateway + engine) that runs on their own machine and serves the dashboard at
`http://localhost:4000`. A static **onboarding site** (`apps/onboarding/`) walks
them through it.

**Flow:**

1. User opens the onboarding site. It detects their OS and polls
   `http://localhost:4000/api/health` to see if the agent is already running.
2. If not, it shows a one-line install command:
   - macOS / Linux: `curl -fsSL https://<host>/install.sh | bash`
   - Windows (PowerShell): `irm https://<host>/install.ps1 | iex`
3. The script installs prerequisites (Node 20+, pnpm, optionally nmap), fetches
   NetScanner into `~/.netscanner`, builds the bundled dashboard
   (`BUILD_STATIC=1`), and registers a background service:
   **launchd** (macOS), **systemd --user** (Linux), or a **Scheduled Task**
   (Windows) that runs the agent at boot/logon.
4. The page auto-detects the agent and links to `http://localhost:4000`.

**Serving onboarding + trying it locally:**

```bash
# 1) build the agent bundle and run it (serves the dashboard on :4000)
BUILD_STATIC=1 pnpm --filter @netscanner/web build
pnpm --filter @netscanner/gateway start

# 2) serve the onboarding site anywhere (example)
python3 -m http.server 8080 --directory apps/onboarding
# open http://localhost:8080
```

Install without a published git remote (e.g. from this checkout):

```bash
NETSCANNER_SRC="$PWD" bash apps/onboarding/install.sh          # copies local source
# or run in the foreground instead of installing a service:
NO_SERVICE=1 NETSCANNER_SRC="$PWD" bash apps/onboarding/install.sh
```

Script env overrides: `NETSCANNER_HOME`, `NETSCANNER_REPO`, `NETSCANNER_SRC`,
`NETSCANNER_PORT`, `NO_SERVICE=1`.

### Security model of the agent

- Binds to **`127.0.0.1` only** — never exposed to the LAN.
- **CORS allow-list** + a server-side **Origin check** on state-changing requests
  (`services/gateway/src/server.ts`), so no third-party website can trigger scans
  or read your inventory via your browser. Only `/api/health` is CORS-open (it is
  non-sensitive and used by the onboarding page to detect the agent).
- **Uninstall** is a single command (shown on the onboarding page): removes
  `~/.netscanner` and the service definition.

## API

| Method | Path                       | Description                          |
| ------ | -------------------------- | ------------------------------------ |
| GET    | `/api/health`              | status + capabilities (nmap/elevated)|
| GET    | `/api/network/interfaces`  | local interfaces + primary CIDR      |
| GET    | `/api/dhcp/fingerprints`   | passive DHCP fingerprints (`?mac=` optional) |
| GET    | `/api/background/status`   | background enrich + light-scan worker status |
| GET    | `/api/router/leases`       | pfSense DHCP leases (when configured) |
| POST   | `/api/scans`               | start a scan `{ cidr?, scanType }`   |
| GET    | `/api/scans` / `/:id`      | latest / specific scan session       |
| GET    | `/api/devices` / `/:id`    | inventory (filters: `search,type,online`) |
| PATCH  | `/api/devices/:id`         | set label / notes                    |
| GET    | `/api/export?format=csv`   | export inventory (json/csv)          |

WebSocket: connect to the gateway (`/socket.io`) and listen for `domain-event`.

## Testing

```bash
pnpm test        # vitest — domain & use-case units, nmap XML fixture, aggregator, upsert deltas
pnpm typecheck   # tsc across all packages
```

## Docker

```bash
docker compose up --build
```

The scanner container needs host networking + `NET_RAW`/`NET_ADMIN` to see the
LAN (see `docker-compose.yml`).

## Configuration (env)

| Var                   | Default                 | Purpose                          |
| --------------------- | ----------------------- | -------------------------------- |
| `GATEWAY_PORT`        | `4000`                  | API/WebSocket port               |
| `WEB_ORIGIN`          | `http://localhost:3000` | CORS origin                      |
| `DATABASE_URL`        | `file:./netscanner.db`  | Prisma datasource                |
| `PERSISTENCE`         | `prisma`                | `prisma` or `memory`             |
| `SCAN_CONCURRENCY`    | `64`                    | max concurrent probes            |
| `DISCOVERY_TIMEOUT_MS`| `1000`                  | per-host discovery timeout       |
| `DISABLE_NMAP`        | `false`                 | force pure-Node engine           |
