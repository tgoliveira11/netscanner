# NetScanner — Handoff Document

> Read this first. It tells you what the project is, what's built, what's running,
> how to change it safely, and where the honest limits are. Written after an
> extended build+iteration session against a **real** home network (pfSense +
> multiple VLANs). Keep it updated as you go.

---

## 1. TL;DR — current state

- A local-network **device scanner & classifier**: discovers every device, classifies
  it (type, vendor, OS, model, wired/WiFi), and shows it on a live dashboard.
- **Fully working and verified against a real network.** ~44 unit tests pass, all
  packages typecheck, `next build` (static export) succeeds.
- Runs as a **local agent** the user installs via a website onboarding flow. On this
  machine the agent is installed as a **root LaunchDaemon** and is **live**.
- **Current strategy (Jul 2026):** maximize what a **single sudo/root agent** on the
  host can discover on its reachable subnet(s). **pfSense integration is OFF** for now
  (no lease injection, no cross-VLAN ghost devices). Inventory DB was reset; new
  discoveries accumulate in SQLite and are **never silently discarded** (sticky upsert;
  production refuses in-memory fallback).
- Sudo agent capabilities active: nmap `-O`/`-sV`, passive **DHCP sniffer** (:67),
  **Fingerbank** (when fingerprints exist), ARP/ping/mDNS/SSDP, UPnP/HTTP/TLS enricher.
- **Future:** optional remote agents (e.g. pfSense package) as **subagents** that feed
  the same event/inventory pipeline — not started yet.

**The arc we went through:** greenfield build → "detects nothing" (tiny OUI table) →
full IEEE OUI DB → reverse-DNS/mDNS → nmap `-O` via root → pfSense DHCP leases (the big
leap: hostnames + all VLANs) → Fingerbank exact model → wired/WiFi inference → **pivot
back to sudo-only local discovery** to establish a solid baseline before adding remote
agents.

---

## 2. What this project is

An efficient scanner that finds and classifies **every device** on a LAN (wired or
WiFi). Because browsers can't do raw network I/O, the scanning engine runs server-side
in Node.js as a **local agent**; the Next.js dashboard is a thin projection over it.

Intended use: networks you own/administer. The UI shows an authorized-use notice.

---

## 3. Architecture (monorepo map)

pnpm + Turborepo monorepo, TypeScript throughout, **Clean Architecture** per service
(`domain → application → infrastructure → interface`, deps point inward), DI wired in
the gateway composition root. "Modular monorepo, run as few processes": the **gateway**
hosts all backend services in one process; the **web** app is separate (or served
statically by the gateway in the agent bundle).

```
apps/
  web/          Next.js dashboard (React, Tailwind, Zustand, socket.io-client)
  onboarding/   Static site: OS detect + agent health poll + install.sh/.ps1
services/
  gateway/      REST + WebSocket hub, composition root (container.ts), scan pipeline (run-scan.use-case.ts)
  discovery/    host discovery (ARP/ping/mDNS/SSDP) + pfSense adapter + DHCP sniffer + Fingerbank client
  scanner/      deep fingerprint (nmap XML + TCP fallback) + NetworkEnricher (UPnP/HTTP/TLS)
  classification/ rule engine (Strategy) + OS/connection inference
  inventory/    persistence (Prisma/SQLite), history, new-device detection, export
packages/
  contracts/    shared DTOs, zod schemas, DomainEvent catalogue
  kernel/       value objects (MacAddress/IpAddress/Cidr), OUI DB + lookup, Result
  os-abstraction/ cross-platform command runner, capabilities, local-network, reverseDns
  logger/ config/
scripts/        deep-scan-root.sh, install-root-service.sh
Dockerfile, docker-compose.yml, README.md
```

Communication: in-process **event bus** behind `IEventPublisher`/`IEventSubscriber`
(swappable to Redis/NATS). Every scan stage emits `DomainEvent`s pushed to the dashboard
over WebSocket — the UI is a pure projection (no polling).

---

## 4. Feature status

| Feature | Status | Notes |
|---|---|---|
| Discovery (ARP, ICMP sweep, mDNS, SSDP) | ✅ | bounded concurrency, streaming |
| Deep scan (nmap `-sV`/`-O`) + TCP fallback | ✅ | `-O` needs root (see §5) |
| Classification rule engine (Strategy/OCP) | ✅ | rules in `services/classification/src/domain/rules/` |
| Full IEEE OUI vendor DB (~39.7k) | ✅ | `packages/kernel/src/oui/oui-db.json`, loaded via `loadOuiTable()` (fs, not import) |
| Reverse-DNS + mDNS/SSDP hostname enrichment | ✅ | |
| NetworkEnricher (UPnP desc / HTTP Server+title / TLS cert CN) | ✅ | `services/scanner/.../network-enricher.ts` |
| OS inference (when nmap `-O` is null) | ✅ | `os-inference.ts`, `source:'inferred'`, capped accuracy |
| Randomized-MAC → phone heuristic + `wearable` type | ✅ | |
| pfSense DHCP-lease integration (REST API v2) | ✅ live | hostnames + all VLANs; `PfSenseRestAdapter` |
| Fingerbank exact model/OS (DHCP fingerprint) | ✅ live | `FingerbankClient`; key configured |
| Passive DHCP sniffer (:67, root) | ✅ built | populates fingerprints over time; LAN-local only |
| Wired/WiFi inference | ✅ | `inferConnection`; heuristic + `authoritative` hook |
| Inventory: history, new-device alerts, export (JSON/CSV) | ✅ | |
| Dashboard: grid, detail drawer, topology, alerts, live updates | ✅ | |
| Install-via-website: onboarding + install.sh/.ps1 + root service | ✅ live | launchd on mac; systemd/scheduled-task variants exist |
| **Managed-switch SNMP / AP association (definitive wired/WiFi)** | ❌ TODO | `authoritative` hook is ready for it (see §10) |

---

## 5. The live deployment on THIS machine (important)

- The agent is installed as a **root LaunchDaemon**: `/Library/LaunchDaemons/com.netscanner.agent.plist`.
- It runs from **`~/.netscanner`** (a synced copy of the repo), via `~/.netscanner/agent-run-root.sh`.
- It binds **`127.0.0.1:4000`** only, serves the bundled dashboard, and runs elevated
  (so nmap `-O` and the DHCP sniffer work).
- **API keys are configured in `~/.netscanner/agent-run-root.sh`** (NOT in the repo):
  `PFSENSE_URL`, `PFSENSE_API_KEY`, `FINGERBANK_API_KEY`. Do not commit these.
- SQLite DB: `~/.netscanner/services/inventory/prisma/netscanner.db`.

### Update/deploy flow (the #1 operational gotcha)

The daemon runs TS via `tsx` (no build step for backend) but from `~/.netscanner`, not
the repo. To ship a change:

```bash
# 1) backend change → sync source
rsync -a --exclude node_modules --exclude .next --exclude out --exclude '*.db' \
  packages services "$HOME/.netscanner/"

# 2) frontend change → rebuild static export, then sync it
BUILD_STATIC=1 pnpm --filter @netscanner/web build
rsync -a --delete apps/web/out/ "$HOME/.netscanner/apps/web/out/"

# 3) restart the root daemon (needs the user's sudo password — you can't do this yourself)
sudo launchctl kickstart -k system/com.netscanner.agent
```

**You (the agent) cannot run `sudo`** here — it needs an interactive password. Anything
requiring root (restarting the daemon, binding :67, nmap `-O`) must be handed to the
user with the exact command.

### Verification pattern you WILL use constantly

Spin up a **throwaway gateway on a spare port, in memory**, from the repo, to test code
without touching the live root daemon or DB:

```bash
PERSISTENCE=memory GATEWAY_PORT=4013 GATEWAY_HOST=127.0.0.1 NODE_ENV=production \
  PFSENSE_URL="https://10.0.51.1" PFSENSE_API_KEY="<key>" FINGERBANK_API_KEY="<key>" \
  pnpm --filter @netscanner/gateway start &
# then POST /api/scans and read /api/devices; kill by port when done:
#   curl -s -X POST http://127.0.0.1:4013/api/scans -H 'content-type: application/json' \
#        -H 'Origin: http://127.0.0.1:4013' -d '{"cidr":"10.0.51.0/24","scanType":"quick"}'
#   lsof -ti tcp:4013 | xargs kill
```
This non-root temp agent can't do nmap `-O` or DHCP sniffing (needs root), but it
exercises the whole pipeline incl. pfSense + Fingerbank (by mac+hostname). Grab the keys
from `~/.netscanner/agent-run-root.sh` for the temp run; don't hardcode them in the repo.

---

## 6. How a device gets classified (the pipeline)

`run-scan.use-case.ts` orchestrates, per scan:
1. **Fetch pfSense leases** up front → map MAC/IP → {hostname, VLAN, online}.
2. **Discovery** streams live hosts (ARP/ping/mDNS/SSDP).
3. Per host: **fingerprint** (nmap/TCP) → **NetworkEnricher** (UPnP/HTTP/TLS) →
   **Fingerbank** (DHCP fingerprint + MAC + hostname) → gather signals.
4. **hostname priority**: pfSense lease → discovery/nmap → UPnP → reverse-DNS.
5. **classify**: `ClassifyDeviceUseCase` runs the rule engine (weighted votes), infers
   OS if nmap gave none, infers wired/WiFi.
6. **upsert** into inventory (sticky/best-so-far), emit events.
7. After the loop: **lease-only devices** (other VLANs the scan couldn't reach) are
   added from pfSense leases (hostname/vendor/VLAN, OS+connection inferred, no ports).

Rules (all in `services/classification/src/domain/rules/`, wired in `index.ts:defaultRules`):
`gateway`, `vendor`, `port-service`, `discovery-signal`, `os-hostname`, `randomized-mac`,
`app-banner` (UPnP/HTTP/TLS), `fingerbank` (highest authority). Engine sums weighted
votes → argmax type + normalized confidence.

Key non-rule logic: `os-inference.ts` (OS from hostname/banner/ports), `connection-inference.ts`
(wired/WiFi), `security-analyzer.ts` (open telnet/rdp/etc. flags).

---

## 7. Honest limitations (do not oversell these)

- **Wired vs WiFi is inferred, not measured.** Randomized MAC → WiFi is near-certain;
  infra → wired; phones/wearables → WiFi. But a device with a **real** MAC that's
  wired-capable (desktop, MacBook in a dock, PoE camera) stays `unknown`. The **only**
  definitive source is a managed-switch MAC table (SNMP) or the AP association list —
  not yet integrated (hook ready: `inferConnection`'s `authoritative`).
- **Randomized MAC defeats vendor-by-MAC.** iOS/Android/macOS randomize WiFi MACs by
  design → OUI vendor is unknowable for them. Hostname (from pfSense DHCP) is what saves
  us there. No tool on earth beats this without the router/AP.
- **nmap `-O` only works** on hosts exposing an open+closed port pair (basically the
  pfSense box here). Firewalled phones/watches get **inferred** OS from hostname instead.
- **DHCP fingerprint capture is passive**: the sniffer only sees broadcast DHCP on its
  own VLAN, only when a device (re)acquires a lease. Fingerprints fill in **over time**;
  reconnecting a device to WiFi forces a DISCOVER and captures it immediately.
- Other-VLAN devices come only from pfSense leases (no ports/nmap; OS/connection inferred).

---

## 8. Environment specifics (this user's network)

- **Router/firewall:** pfSense CE 2.8.1 at **`10.0.51.1`** (FreeBSD; the `.1` box is an
  Intel N5105 mini-PC — NIC OUI "S-Bluetech"). REST API package installed.
- **VLANs:** VLAN10 `10.0.51.x`, VLAN30 `10.0.52.x`, VLAN20 `10.0.60.x`,
  VLAN40 `10.0.40.x`, plus TRUNK/WAN. The agent host is on `10.0.51.x`.
- Real devices seen: iPhones, an Apple Watch, MacBook Air/Pro, an Amazon speaker, many
  Tuya/Espressif IoT on VLAN20, Compal (`cbnre…`) ISP gateway/mesh nodes.
- pfSense DHCP-lease field names: `ip, mac, hostname, if, online_status`
  ("active/online" | "idle/offline"), `descr`. Leases endpoint: `/api/v2/status/dhcp_server/leases`,
  auth header `X-API-Key`.

---

## 9. Develop / run / verify

```bash
pnpm install
pnpm -r typecheck          # all packages
npx vitest run             # ~44 tests (or: pnpm test)
pnpm dev                   # gateway :4000 + web :3000 (dev mode)
```
- Config is env-driven and zod-validated: `packages/config/src/index.ts`. Everything
  optional defaults to off/safe. See `.env.example`.
- Prisma: `pnpm db:generate` + `pnpm db:push`. SQLite path resolves **relative to the
  schema dir** — keep `DATABASE_URL=file:./netscanner.db` aligned with
  `container.ts:resolveSqliteUrl` (anchors at `services/inventory/prisma`).
- Web relative imports must be **extensionless** (Next/webpack won't map `.js`→`.tsx`).
- Static export for the agent: `BUILD_STATIC=1 pnpm --filter @netscanner/web build`
  (drops rewrites, `output:'export'`); the gateway serves `apps/web/out`.

---

## 10. Open items / next steps (prioritized)

1. **Definitive wired/WiFi** (the user's active ask): integrate a source that reports
   truth per MAC, then feed it as `authoritative` into `inferConnection`:
   - **Managed switch via SNMP** — BRIDGE-MIB `dot1dTpFdbTable` (MAC→port); map AP-uplink
     ports → WiFi. Need the switch's SNMP community/host.
   - **AP association list** — e.g. UniFi controller API. Need controller URL/creds.
   - Ask the user which they have. Add a `IRouterLeaseSource`-style port + adapter in
     `services/discovery`, surface `connectionAuthoritative` in signals; `inferConnection`
     already honors it.
2. **Fingerbank precision**: the DHCP sniffer is built but fingerprints populate slowly.
   Consider a lightweight prompt/telemetry showing how many fingerprints captured, and
   document the "reconnect device to WiFi to capture now" trick in the UI.
3. **DB hygiene**: sticky upsert + frontend IP-dedupe are in place, but after big
   classification changes we've been clearing the DB manually
   (`DELETE FROM DeviceRecord;`). Consider a "rescan clean" / re-classify action.
4. **Multi-subnet scanning**: today the active scan is one CIDR; other VLANs come only via
   pfSense. Optionally let the user scan each VLAN if the agent can reach them.
5. Tests for the network integrations (pfSense adapter parsing, enricher) beyond the
   pure-function units already covered.

---

## 11. Gotchas & lessons (learned the hard way)

- **You can't `sudo`** (interactive password). Hand root commands to the user verbatim.
- **Deploy = rsync to `~/.netscanner` + `sudo launchctl kickstart -k …`.** Editing the
  repo alone does nothing for the live daemon.
- **`tsx`/pnpm workspace symlinks are live**, but always restart the daemon after a sync.
- **TLS grab**: never set `servername` to an IP — Node throws. Omit SNI; the device
  returns its default cert (that's how we ID pfSense by cert CN).
- **CSRF guard**: the gateway rejects mutating requests whose `Origin` isn't allow-listed
  → when POSTing scans via curl to a temp agent, send `-H 'Origin: http://127.0.0.1:<port>'`.
  `/api/health` is intentionally CORS-open (onboarding polls it).
- **pfSense lease status** is `online_status` (not `state`); "offline" must not match the
  "online" regex.
- **Lease-only device path** had two bugs we fixed: it hardcoded `connectionType:'unknown'`
  and `os:null`, discarding inferred values. If you add fields, wire them in BOTH the
  scanned-host path and the lease-only path in `run-scan.use-case.ts`.
- The full project memory lives in the Claude memory dir (`netscanner-overview.md`) with a
  condensed version of all this.

---

## 12. Quick file index

- Orchestration: `services/gateway/src/application/run-scan.use-case.ts`
- Composition root / wiring: `services/gateway/src/container.ts`
- HTTP + WS + CSRF guard + static serve: `services/gateway/src/interface/routes.ts`, `server.ts`
  - Diagnostics: `GET /api/dhcp/fingerprints` (passive sniffer cache), `GET /api/router/leases`
- Classification entry: `services/classification/src/application/classify-device.use-case.ts`
- Rules: `services/classification/src/domain/rules/*`
- OS / connection inference: `services/classification/src/domain/{os-inference,connection-inference}.ts`
- pfSense: `services/discovery/src/infrastructure/pfsense-rest.adapter.ts`
- DHCP sniffer + parser: `services/discovery/src/{infrastructure/dhcp-sniffer.ts,domain/dhcp-fingerprint.ts}`
- Fingerbank: `services/discovery/src/infrastructure/fingerbank-client.ts`
- Enricher (UPnP/HTTP/TLS): `services/scanner/src/infrastructure/network-enricher.ts`
- OUI DB: `packages/kernel/src/oui/{oui-db.json,load-oui.ts,oui-lookup.ts}`
- Install: `apps/onboarding/{index.html,install.sh,install.ps1}`, `scripts/install-root-service.sh`
