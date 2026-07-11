# Multi-agent cluster

NetScanner can run as a **single agent** (today’s Mac install) or as a **LAN cluster**: one inventory/control leader plus optional workers and UI-only peers.

Agents are specialized by **capabilities** (announced in the UDP beacon). Profiles (`full` / `scan-only` / `ui-only`) are coarse defaults; the leader leases tasks only to peers that advertise the required capability.

## Roles

| Role | Responsibility |
|------|----------------|
| **leader** | Source of truth for inventory (SQLite). Orchestrates scans. Serves canonical UI. |
| **worker** | Executes leased tasks and returns results to the leader. |
| **ui-only** | No elevated probes / no pfSense writes. Proxies or redirects UI to the leader. |

**Control Leader** (usually the same as inventory leader on a dedicated box): the **only** agent allowed to write pfSense/Compal.

## Capabilities

| Capability | Beacon field | Typical work |
|------------|--------------|--------------|
| `inventory-scan` | `inventoryScan` | Active CIDR discover (nmap/ports/ARP) |
| `passive-l2` | `passiveL2` | DHCP sniff, LLDP/CDP (needs elevated + right iface) |
| `snmp-bridge` | `snmpBridge` | Switch FDB / BRIDGE-MIB |
| `wifi-rf` | `wifiRf` | Channel/SSID RF analyzer |
| `speed-agent` | `speedAgent` | Speed test from this host’s egress |
| `speed-wan` | `speedWan` | WAN speed via pfSense SSH (`curl --interface`) |
| `diagnostics` | `diagnostics` | On-demand ping / traceroute / DNS / port scan |
| `presence` | `presence` | Periodic online/offline polling |
| `pfsense-control` | `pfsenseControl` | Mutating pfSense control |
| `compal-control` | `compalControl` | Compal/OpenWrt admin writes |
| `ui-host` | `uiHost` | Serve dashboard |
| `cloud-sync` | `cloudSync` | Push inventory / pull remote commands |
| `topology-builder` | `topologyBuilder` | Build/serve topology graph (usually leader) |
| `traffic-relations` | `trafficRelations` | pfSense states / peer relations |
| `ap-scrape` | `apScrape` | AP client scrape (Compal/OpenWrt/…) |
| `fingerprint-cloud` | `fingerprintCloud` | Fingerbank / enrichment API calls |
| `camera-iot-probe` | `cameraIotProbe` | Camera/IoT heuristics + RTSP |
| `site-probe` | `siteProbe` | Site fingerprint when the host moves networks |
| `elevated` | `elevated` | OS privilege for raw/passive probes |

Legacy beacon flags `scan` / `wifi` / `inventory` are still accepted and mirrored for mixed-version clusters (`normalizeAgentCapabilities`).

### Suggested placement

| Host | Capabilities |
|------|----------------|
| **Dedicated Linux box** | `inventory-scan`, `passive-l2`, `presence`, `topology-builder`, `pfsense-control`, `compal-control`, `speed-wan`, `traffic-relations`, `ap-scrape`, `ui-host`, `cloud-sync`, … |
| **Mac (UI peer)** | `ui-host` only (`ui-only` profile) |
| **Mac (helper)** | `wifi-rf`, `speed-agent`, `diagnostics`, `site-probe` — no control |
| **Scan worker** | `inventory-scan`, `diagnostics`, `fingerprint-cloud` (`scan-only`) |

## Identity (`agent.json`)

Persisted under `NETSCANNER_HOME` (default `~/.netscanner` or `/var/lib/netscanner` on dedicated Linux):

```json
{
  "id": "<uuid>",
  "hostname": "netscanner-box",
  "preferLeader": true,
  "dedicated": true,
  "profile": "full",
  "createdAt": "...",
  "updatedAt": "..."
}
```

Profiles: `full` | `scan-only` | `ui-only`.

## Discovery

- **UDP beacon** on `CLUSTER_BEACON_PORT` (default `4010`), JSON `PeerBeacon` v1.
- **mDNS** `_netscanner._tcp` — only the UI/inventory leader should advertise `netscanner.local` (Fase B).

## Election

Score (higher wins): `dedicated` ≫ `preferLeader` ≫ `elevated` ≫ `uptime` ≫ lexicographic `agentId`.

**Portable agents** (`CLUSTER_DEDICATED=false` and `CLUSTER_PREFER_LEADER=false`, e.g. a Mac laptop):

- If any **preferred** peer is reachable (dedicated and/or prefer-leader), they **always yield** — role `worker`, UI reverse-proxied to the inventory leader when `MDNS_ENABLED`.
- If no preferred peer is reachable (other network, box offline past stale timeout), they **take inventory leadership** and run full UI/SoT (`AGENT_PROFILE=full`).

- Inventory pool: peers with inventory-holding capabilities (`canHoldInventory`).
- Control pool: peers with `pfsense-control` and/or `compal-control` (`canHoldControl`).
- Term/epoch increments when leadership changes.
- Non-leaders **freeze** pfSense/Compal control writes.
- Split-brain: if two leaders are seen, control stays disabled until a single stable leader remains for one election interval.

## Task leases

Leader assigns `TaskLease` to workers. One active scan per CIDR/site.

| Task type | Required capability |
|-----------|---------------------|
| `scan-cidr` | `inventory-scan` |
| `wifi-analyze` | `wifi-rf` |
| `enrich` | `fingerprint-cloud` |
| `speed-agent` | `speed-agent` |
| `speed-wan` | `speed-wan` |
| `passive-capture` | `passive-l2` |
| `diagnostics` | `diagnostics` |
| `snmp-bridge` | `snmp-bridge` |
| `ap-scrape` | `ap-scrape` |
| `camera-iot-probe` | `camera-iot-probe` |
| `site-probe` | `site-probe` |
| `presence-poll` | `presence` |

Helpers in `@netscanner/contracts`: `requiredCapabilityForTask`, `peerCanRunTask`, `listEnabledCapabilities`, `shardCidrs`.

## APIs

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/cluster/status` | Self + peers + leaders |
| GET | `/api/cluster/peers` | Peer list |
| POST | `/api/cluster/tasks/result` | Worker posts task results (token) |

## Config

| Key | Default | Notes |
|-----|---------|-------|
| `CLUSTER_ENABLED` | `true` | Peer beacon + election |
| `CLUSTER_BEACON_PORT` | `4010` | UDP |
| `CLUSTER_PREFER_LEADER` | `false` | Hint for dedicated boxes |
| `CLUSTER_DEDICATED` | `false` | Hardware appliance |
| `AGENT_PROFILE` | `full` | `full` / `scan-only` / `ui-only` |
| `CLUSTER_UI_REDIRECT` | `true` | Non-leaders redirect browser to inventory leader |
| `CLUSTER_PEER_HOSTS` | — | Comma-separated IPs for **unicast** beacons (required across VLANs) |
| `CLUSTER_ADVERTISE_HOST` | — | LAN IP advertised so peers can reach this agent’s HTTP API |
| `CLUSTER_CONTROL_ELIGIBLE` | `true` | Set `false` on helper peers (wifi/speed) that must never take control |
| `GATEWAY_HOST` | `127.0.0.1` | Use `0.0.0.0` for LAN UI (Fase B) |
| `MDNS_ENABLED` | `false` | Advertise `MDNS_HOSTNAME.local` + bind `:80`. Helpers reverse-proxy to the inventory leader so the URL stays `http://netscanner.local/` |
| `MDNS_HOSTNAME` | `netscanner` | → `netscanner.local` (link-local; enable on **one agent per VLAN**) |
| `CLOUD_SYNC_URL` | — | Self-host cloud base URL |
| `CLOUD_SYNC_TOKEN` | — | Site token |
| `CLOUD_SYNC_ENABLED` | `false` | Near-realtime push |
| `CLOUD_PII_CONSENT` | `false` | Required before syncing MACs/IPs/hostnames |

## Trust model

- LAN UI may be open (no browser auth) when bound to the LAN.
- Mutating APIs keep Bearer tokens (`AGENT_CONTROL_TOKEN` / `CONTROL_TOKEN`).
- Do not expose the agent to the WAN without cloud auth (Fase C + future `@tgoliveira/secure-auth`).

## Packaging (dedicated Linux)

See [deploy/linux](../deploy/linux/README.md): Docker Compose, systemd unit, `.deb` skeleton. Data dir: `/var/lib/netscanner`.
