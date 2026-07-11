# NetScanner Admin — configuration reference

The **Admin** page (`/admin`) is the local control plane for the NetScanner agent. It runs against `http://127.0.0.1:4000` (or your `GATEWAY_PORT`) and is intended for localhost use.

## How configuration is stored

| Layer | Role |
|-------|------|
| **`config.env`** | Primary runtime file edited by Admin. Lives next to the gateway service (e.g. `~/.netscanner/services/gateway/config.env`). |
| **LaunchDaemon / shell env** | Boot-time defaults. **Overridden** by `config.env` for any key visible in Admin. |
| **Live process** | After **Save**, non-restart keys apply immediately; restart keys need **Restart agent**. |

Secrets (`PFSENSE_API_KEY`, router passwords, etc.) are masked in the UI (`••••••••`). Leave a secret field empty on save to keep the current value.

## Admin sections

| Section | Purpose |
|---------|---------|
| **Runtime status** | Agent health, discovery counters, active scan, config path. |
| **WiFi / SSIDs** | Live probe of `ROUTER_SCRAPE_TARGETS` with `openwrt` kind. |
| **Network control** | pfSense bootstrap, **Verify rules** (alias + firewall checks), parental schedules, audit log. |
| **Internet speed** | Background WAN speed tests (`SPEED_TEST_*`). |
| **Recent discoveries** | Last DHCP fingerprints and passive signal samples (collapsed by default). |
| **Logs** | Ring buffer + tail of agent log file (newest first). |
| **Configuration** | All runtime keys grouped below. Hover a field label for a short explanation. |

## pfSense network control

When `PFSENSE_CONTROL_ENABLED=true`, NetScanner can write to pfSense via REST API (multi-agent: only the **control leader** — see [multi-agent.md](./multi-agent.md)):

| Alias | Purpose | Required firewall rule |
|-------|---------|----------------------|
| `NS_BLOCK` | Manual block from device drawer | Floating **block**, source `NS_BLOCK`, protocol any, **Quick** |
| `NS_PAUSED` | Timed pause | Floating **block**, source `NS_PAUSED`, **Quick** |
| `NS_AUTOBLOCK` | New devices (if `AUTOBLOCK_ENABLED`) | Floating **block**, source `NS_AUTOBLOCK`, **Quick** |
| `NS_DNS_SRC` / `NS_DNS_BLOCK` | Per-device domain block | Floating **block**, source `NS_DNS_SRC`, dest `NS_DNS_BLOCK`, **Quick** |
| `NS_DEST_SRC` / `NS_DEST_BLOCK` | Per-device IP/CIDR block | Floating **block**, source `NS_DEST_SRC`, dest `NS_DEST_BLOCK`, **Quick** |
| `NS_ROUTE_WAN` | Force egress via WAN | Floating **pass**, source `NS_ROUTE_WAN`, gateway `WAN_DHCP`, **Quick** |
| `NS_ROUTE_LB` | Force egress via LB | Floating **pass**, source `NS_ROUTE_LB`, gateway `LB_WAN`, **Quick** |
| `NS_ROUTE_VPN` | Force egress via VPN | Floating **pass**, source `NS_ROUTE_VPN`, gateway `SSVPN_Failover`, **Quick** |
| `NS_RT_*` | Dynamic per-gateway route aliases | Created on demand when Policy → Route picks a gateway |
| `NS_LIMIT` | Per-device bandwidth | Floating **pass** IN/OUT, source `NS_LIMIT`, pipes `NS_IN` / `NS_OUT` (or `NS_LIMIT_IN` / `NS_LIMIT_OUT`), **Quick** |

**Verify rules** in Admin runs automated checks: aliases exist, rule sources are correct (not `any` or inverted `!alias`), bandwidth pipes wired, limiters enabled, and a safe round-trip write to `NS_BLOCK` using probe IP `198.18.0.254`.

**Bootstrap** creates aliases and ensures the floating rules above (on VLANs `opt3–opt6` / LAN_INFRA–IOT). Dynamic `NS_RT_*` route rules are created when a device is assigned a specific gateway.

---

## Configuration groups

### Network Control

| Key | Type | Restart | Description |
|-----|------|---------|-------------|
| `PFSENSE_CONTROL_ENABLED` | boolean | yes | Master switch for block, pause, DHCP reserve, bandwidth, and parental schedule writes to pfSense. When false, control APIs return 503 and the UI shows read-only bootstrap status. |
| `AUTOBLOCK_ENABLED` | boolean | yes | When true, newly discovered devices are added to the `NS_AUTOBLOCK` alias. **Off by default** — enable only with a working AUTOBLOCK floating rule. |
| `AUTOBLOCK_VLANS` | string | yes | Comma-separated pfSense interface labels (e.g. `LAN_GUEST`). Empty = all VLANs when autoblock is on. Restrict guest-only autoblock by setting e.g. `LAN_GUEST`. |
| `CONTROL_TOKEN` | secret | yes | Optional Bearer token for `/api/control/*`. When set, requests must send `Authorization: Bearer <token>`. Localhost without token still works when unset. |

### Network Sites

Multi-site fingerprinting and VPN-aware site matching. See also [network-sites.md](./network-sites.md).

| Key | Type | Restart | Description |
|-----|------|---------|-------------|
| `SITE_AUTO_CREATE` | boolean | yes | Create a new site record when no fingerprint matches. |
| `SITE_MATCH_THRESHOLD` | number | yes | Minimum score (0–1) to accept an automatic site match. |
| `SITE_AMBIGUOUS_THRESHOLD` | number | yes | Minimum score to show ambiguous-site confirmation in the UI. |
| `SITE_VPN_IGNORE_GEO` | boolean | yes | Skip geolocation signals when a VPN/tunnel is detected during site matching. |

### Integrations

External systems that feed inventory, traffic, or DHCP data.

**CPE / modem access** — on the Integrations tab you can open a browser session to any modem/CPE admin UI by IP + username + password. The agent probes direct reachability first; if the CPE is only reachable from pfSense (typical ISP modem on WAN), it opens an SSH local-forward (`PFSENSE_URL` + `PFSENSE_SSH_PASSWORD`) and reverse-proxies under `/api/admin/cpe/proxy/:id/`. Sessions are stored in SQLite and survive agent restart; they close only when you click **Close tunnel**. Credentials are kept encrypted at rest when possible and used for one-shot auto-login on the modem page.

| Key | Type | Restart | Description |
|-----|------|---------|-------------|
| `PFSENSE_URL` | string | yes | Base URL for pfSense REST API, e.g. `https://192.168.51.1`. Required for leases, traffic states, and network control. |
| `PFSENSE_API_KEY` | secret | yes | pfSense REST API key (System → API). |
| `PFSENSE_LEASES_PATH` | string | no | API path for DHCP leases (default `/api/v2/status/dhcp_server/leases`). |
| `PFSENSE_INSECURE_TLS` | boolean | no | Accept self-signed pfSense TLS certificates. |
| `PFSENSE_TRAFFIC_ENABLED` | boolean | yes | Poll firewall states for per-device bytes and relation peers. |
| `PFSENSE_SSH_USER` | string | yes | SSH user for remote DNS tcpdump on pfSense (cross-VLAN DNS passive). |
| `PFSENSE_SSH_PORT` | number | yes | SSH port (default 22; some labs use e.g. 2231). |
| `PFSENSE_SSH_PASSWORD` | secret | yes | SSH password for pfSense remote capture. |
| `FINGERBANK_API_KEY` | secret | yes | Fingerbank API for DHCP fingerprint → device class hints. |
| `ROUTER_SNMP_HOST` | string | yes | Gateway SNMP when not using pfSense for ARP/MAC tables. |
| `ROUTER_SCRAPE_URL` | string | yes | Single router panel URL (legacy; prefer `ROUTER_SCRAPE_TARGETS`). |
| `ROUTER_SCRAPE_KIND` | string | yes | `openwrt` (LuCI) or `compal` (Claro AP ARP table). |
| `ROUTER_SCRAPE_USER` | string | yes | HTTP login for router panel. |
| `ROUTER_SCRAPE_PASSWORD` | secret | yes | HTTP password for router panel. |
| `ROUTER_SCRAPE_TARGETS` | multiline | yes | One router per line: `url\|kind\|user\|password`. Example: `http://192.168.40.2\|openwrt\|root\|pass` and `http://192.168.51.101\|compal\|CLARO_21A469\|pass`. Used for WiFi SSID probe, Compal/OpenWrt enrichment, and DHCP sniff SSH fallback. |
| `FRITZBOX_URL` | string | yes | Fritz!Box base URL for host list integration. |
| `FRITZBOX_USER` | string | yes | Fritz!Box username. |
| `FRITZBOX_PASSWORD` | secret | yes | Fritz!Box password. |
| `UNIFI_URL` | string | yes | UniFi controller URL. |
| `UNIFI_API_KEY` | secret | yes | UniFi API key. |
| `UNIFI_SITE` | string | yes | UniFi site name (default `default`). |
| `OMADA_URL` | string | yes | TP-Link Omada controller URL. |
| `OMADA_CLIENT_ID` | string | yes | Omada Open API client ID. |
| `OMADA_CLIENT_SECRET` | secret | yes | Omada Open API client secret. |
| `OMADA_SITE_ID` | string | yes | Omada site identifier. |

### Topology

Controls how the dashboard draws network layout.

| Key | Type | Restart | Description |
|-----|------|---------|-------------|
| `TOPOLOGY_MODE` | string | no | `simple` = pfSense → switch → clients; `vlan` = multi-VLAN home layout with optional WiFi APs. |
| `TOPOLOGY_VLAN_ORDER` | string | no | Comma-separated pfSense interface labels for vlan mode display order. |
| `TOPOLOGY_WIRED_VLAN` | string | no | Interface label for the wired switch segment in vlan mode. |
| `TOPOLOGY_MAC_SHARING_PREFIX` | string | no | IP prefix for Mac Internet Sharing branch (default `192.168.64.`). |

### Discovery

Passive listeners, SNMP, protocol probes, and presence polling.

| Key | Type | Restart | Description |
|-----|------|---------|-------------|
| `DHCP_SNIFF` | boolean | yes | Passive DHCP fingerprint capture via tcpdump. Requires root/CAP_NET_RAW. |
| `DHCP_SNIFF_IFACES` | string | yes | Comma-separated local interfaces (e.g. `en0,any`). Empty = auto. Routed VLANs without L2 on this host need remote capture on the switch/AP. |
| `DHCP_SNIFF_SSH_PASSWORD` | secret | yes | SSH password for remote tcpdump on `SNMP_SWITCH_HOST`. |
| `PASSIVE_LISTENERS_ENABLED` | boolean | yes | Continuous mDNS + SSDP listeners. |
| `LLDP_PASSIVE_ENABLED` | boolean | yes | LLDP capture via tcpdump (needs root). |
| `LLDP_STREAM_ENABLED` | boolean | yes | Continuous LLDP stream vs periodic burst. |
| `SNMP_ENABLED` | boolean | no | SNMP v2c enrichment when `snmpget` is available. |
| `SNMP_COMMUNITY` | string | no | Primary SNMP v2c community. |
| `SNMP_COMMUNITIES` | string | no | Comma-separated communities tried in order. |
| `SNMP_SWITCH_HOST` | string | yes | Managed switch/AP for BRIDGE-MIB wired/WiFi MAC learning. |
| `SNMP_WIFI_PORTS` | string | no | BRIDGE-MIB port numbers where WiFi APs uplink; MACs on these ports are tagged `wifi`. |
| `SNMP_V3_USER` | string | yes | SNMPv3 username (optional). |
| `SNMP_V3_AUTH_PASS` | secret | yes | SNMPv3 authentication password. |
| `SNMP_V3_PRIV_PASS` | secret | yes | SNMPv3 privacy password. |
| `SNMP_V3_AUTH_PROTO` | string | yes | `SHA`, `MD5`, etc. |
| `SNMP_V3_PRIV_PROTO` | string | yes | `AES`, `DES`, etc. |
| `SNMP_V3_SEC_LEVEL` | string | yes | `noAuthNoPriv`, `authNoPriv`, or `authPriv`. |
| `PASSIVE_DNS_ENABLED` | boolean | yes | tcpdump on port 53 for hostname hints. |
| `PASSIVE_IGMP_ENABLED` | boolean | yes | Multicast joins (Chromecast, TVs). |
| `PASSIVE_DHCPV6_ENABLED` | boolean | yes | Passive DHCPv6 fingerprint capture. |
| `MAC_DNS_CACHE_ENABLED` | boolean | yes | Resolve hostnames from local DNS cache by MAC. |
| `PROTOCOL_PROBE_ENABLED` | boolean | yes | Lightweight protocol banners during discovery. |
| `PRESENCE_POLL_ENABLED` | boolean | yes | Fast ping loop for near-real-time online/offline. |
| `PRESENCE_POLL_INTERVAL_MS` | number | yes | Ping interval (default 30s). |
| `PRESENCE_PING_TIMEOUT_MS` | number | yes | ICMP timeout per device (default 2500ms). |
| `PRESENCE_OFFLINE_AFTER_MISSES` | number | yes | Failed polls before marking offline (default 4). |
| `PRESENCE_PING_CONCURRENCY` | number | yes | Parallel ICMP probes during presence polling. |
| `P0F_PASSIVE_ENABLED` | boolean | yes | OS hints from passive TCP SYN fingerprinting (p0f). |
| `CDP_PASSIVE_ENABLED` | boolean | yes | Cisco CDP neighbor capture. |
| `BAYESIAN_CLASSIFICATION` | boolean | yes | Probabilistic fusion of classification evidence. |

### Scanning

Active discovery sweeps and port probing.

| Key | Type | Restart | Description |
|-----|------|---------|-------------|
| `SCAN_CONCURRENCY` | number | no | Max parallel host probes during discovery. |
| `DISCOVERY_TIMEOUT_MS` | number | no | Per-host discovery timeout. |
| `DISABLE_NMAP` | boolean | yes | Force pure-Node scanning even if nmap is installed. |
| `SCAN_CIDRS` | string | no | Extra subnets beyond local interfaces (comma-separated). Used by “Scan all CIDRs” and background light scan. |
| `ADAPTIVE_SCAN_ENABLED` | boolean | no | Quick probes on well-known devices. |
| `MASSCAN_ENABLED` | boolean | yes | Fast sweep on large subnets (requires masscan). |
| `MASSCAN_RATE` | number | no | Packets per second for masscan. |

### Background

Periodic tasks that run without user action.

| Key | Type | Restart | Description |
|-----|------|---------|-------------|
| `BACKGROUND_ENRICH_INTERVAL_MS` | number | no | How often to re-enrich stale devices. |
| `BACKGROUND_SCAN_INTERVAL_MS` | number | no | Light ping+ARP scan interval. |
| `BACKGROUND_SCAN_ENABLED` | boolean | no | Enable periodic light scans. |
| `BACKGROUND_PORT_RESCAN_ENABLED` | boolean | no | Re-probe stale online devices for open ports. |
| `BACKGROUND_PORT_RESCAN_MAX_AGE_MS` | number | no | Re-scan ports when older than this (default 7 days). |
| `BACKGROUND_PORT_RESCAN_BATCH` | number | no | Max devices per port-rescan sweep. |
| `SPEED_TEST_ENABLED` | boolean | no | Periodic WAN speed tests via Cloudflare endpoints. |
| `SPEED_TEST_INTERVAL_MS` | number | no | Interval between tests (default 1h). |
| `SPEED_TEST_DOWNLOAD_BYTES` | number | no | Download payload size per test. |
| `SPEED_TEST_UPLOAD_BYTES` | number | no | Upload payload size per test. |
| `SPEED_TEST_URL` | string | no | Base URL for Cloudflare speed endpoints. |

### Gateway

HTTP server binding and CORS.

| Key | Type | Restart | Description |
|-----|------|---------|-------------|
| `GATEWAY_PORT` | number | yes | HTTP port the agent listens on (default 4000). |
| `GATEWAY_HOST` | string | yes | Bind address (`127.0.0.1` recommended). |
| `WEB_ORIGIN` | string | yes | Allowed CORS origin for the dev dashboard. |
| `ONBOARDING_ORIGIN` | string | yes | Hosted onboarding site allowed to poll `/api/health`. |

### Persistence

| Key | Type | Restart | Description |
|-----|------|---------|-------------|
| `DATABASE_URL` | string | yes | SQLite file path for Prisma (inventory, audit, speed tests). |

### Agent

Hidden from Admin UI; set via `config.env` or environment only.

| Key | Description |
|-----|-------------|
| `AGENT_ENCRYPTION_KEY` | Encrypts router passwords at rest (64-char hex). Auto-generated if unset. |
| `AGENT_CONTROL_TOKEN` | Bearer token for `POST /api/agent/restart`. |

---

## Related docs

- [deployment-profiles.md](./deployment-profiles.md) — example `config.env` profiles
- [network-sites.md](./network-sites.md) — multi-site design
- [discovery-enhancements-plan.md](./discovery-enhancements-plan.md) — planned discovery features
