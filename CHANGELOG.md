# Changelog

All notable changes to NetScanner are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Multi-agent cluster (Fase A)** — agent identity (`agent.json`), UDP peer beacon, automatic leader election, control-leader gate for pfSense/Compal writes; Admin **Cluster** tab; `GET /api/cluster/status` and `/api/cluster/peers`. See [docs/multi-agent.md](docs/multi-agent.md).
- **Agent profiles** — `AGENT_PROFILE=full|scan-only|ui-only` and `UI_ONLY` (Mac UI peer without elevated probes); dedicated flags `CLUSTER_DEDICATED` / `CLUSTER_PREFER_LEADER`.
- **Linux dedicated packaging** — Docker Compose, Dockerfile, systemd unit, `.deb` skeleton, and auto-update helper under `deploy/linux/` and `scripts/build-deb.sh` / `check-update.sh`.
- **LAN-wide UI (Fase B)** — private-LAN CORS, optional `GATEWAY_HOST=0.0.0.0`, mDNS name claim when inventory leader (`MDNS_ENABLED` / `MDNS_HOSTNAME`), non-leader browser redirect to inventory leader (`CLUSTER_UI_REDIRECT`).
- **Self-host cloud sync (Fase C)** — `@netscanner/cloud` service (events + remote command queue); gateway `CloudSyncWorker` with `CLOUD_SYNC_*` and required `CLOUD_PII_CONSENT`.
- **Mobile shell (Fase D)** — `apps/mobile` discovery/aggregation helpers for multi-agent + stand-alone limited scan (Expo UI next).
- **Scan-only CLI** — `pnpm --filter @netscanner/scanner scan --cidr … --workers N` with `shardCidrs()` for large multi-CIDR jobs.

### Changed
- Gateway trust model docs: localhost-only default; dedicated boxes may bind LAN; mutating APIs still use Bearer tokens.
- Admin tabs include **Cluster**; runtime config exposes Cluster and Cloud settings groups.
- **Fine-grained agent capabilities** — beacons advertise inventory-scan, wifi-rf, speed-agent/wan, passive-l2, diagnostics, presence, ap-scrape, etc.; `TaskLease` types map via `TASK_REQUIRED_CAPABILITY` / `peerCanRunTask`; legacy `scan`/`wifi`/`inventory` flags still accepted. See [docs/multi-agent.md](docs/multi-agent.md).
- **Topology unknown→switch** — clients with `connectionType=unknown` on `TOPOLOGY_WIRED_VLAN` or the switch `/24` hang under the switch instead of pfSense (e.g. Proxmox on LAN_INFRA without SNMP FDB).
- **Cross-VLAN cluster peers** — `CLUSTER_PEER_HOSTS` unicast beacons, `CLUSTER_ADVERTISE_HOST`, and `CLUSTER_CONTROL_ELIGIBLE=false` for Mac wifi/speed helpers.
- **Portable agent election** — helpers without `CLUSTER_DEDICATED`/`CLUSTER_PREFER_LEADER` always yield to a preferred peer when reachable; alone they become inventory leader (full UI/SoT on another network).
- **WAN CPE discovery** — ARP neighbors on `WAN*` interfaces are `online` for lease upsert; explicit `SCAN_CIDRS` may include ISP handoff nets (`192.168.0.0/24`, `192.168.15.0/24`) for port/enrichment scans.
- **Background speed tests are per-WAN** — worker runs SSH `curl --interface` for each physical WAN (not agent LB egress); gateway `srcip` maps to `hwif` when pfSense omits `interface`.
- **Real mDNS advertise** — agents with `MDNS_ENABLED` publish `netscanner.local` (honest local A record) and bind `:80`. Cross-VLAN helpers reverse-proxy to the inventory leader so the browser keeps `http://netscanner.local/` (macOS ignores mDNS answers that point at another host’s IP). Enable on one agent per VLAN.

## [0.2.0] - 2026-07-10

### Added
- **Per-WAN speed tests** — SSH on pfSense with `curl --interface` per physical WAN (`POST /api/speed-tests/run` `{ target: "wan-all" }`); Admin chart/history with WAN filter and 90-day retention (`SPEED_TEST_RETENTION_DAYS`).
- **Agent egress labeling** — agent speed tests record observed path (`egressRoute` / `egressGateway`: VPN, LB, WAN) from pfSense telemetry.
- **Device Policy tab** — block internet, block domains (FQDN alias), block destinations (IP/CIDR), policy routing, and audit log in the device drawer.
- **Granular pfSense control** — `NS_DNS_BLOCK` / `NS_DEST_BLOCK` aliases; `POST /api/control/dns-block`, `/dest-block`, `/route`; auto-create floating DNS/DEST/ROUTE rules via REST API.
- **Policy routing dropdown** — `GET /api/control/route-options` lists real gateways/groups from telemetry; `NS_RT_*` aliases + floating pass with Gateway column.
- **Persisted device policies** — route/DNS/dest stored in SQLite (`DevicePolicyRecord`); reapplied to pfSense after agent restart.
- **Admin tabs + background polling** — Network / Integrations / Topology keep state when switching tabs; `background-data-store` continues refreshing off-screen.
- **pfSense gateways panel** — system, gateway groups, VPN clients, egress insights on Admin.
- **Compal admin panel** — mesh toggle and status for Compal/CBN APs.
- **Wi‑Fi analyzer** — Tools page panel with channel/SSID analysis (CoreWLAN native helper on macOS).
- **Loading spinners** — shared loading UI for slow admin/tools/topology fetches.
- **Diagnostics toolkit (A1–A4)** — ping, traceroute, DNS lookup, single-host port scan in the device drawer; **Tools** page with Wi‑Fi scanner, generic DNS, camera heuristics + RTSP probe.
- **Network control (B0–B5)** — pfSense REST bootstrap (`NS_BLOCK`, `NS_PAUSED`, `NS_AUTOBLOCK`, `NS_LIMIT`); block/unblock/pause; DHCP static mapping; autoblock; parental schedules; policy audit log.
- **Network sites** — isolated inventory per location with fingerprint match, lock/rename, VPN-aware matching.
- **Topology WAN tier** — WAN node role above pfSense; Compal LuCI RSA login; per-device router credentials; `ROUTER_SCRAPE_TARGETS`; `/api/admin/wireless`.

### Fixed
- **Online/offline presence** — always ping for liveness; lease idle accelerates offline; ARP alone no longer marks online; lease-only hosts excluded from scan `seenIds`.
- **WAN speed test UX** — prefer cached pfSense telemetry (avoid 30s+ refresh before SSH tests); enable WAN button from SSH config, not slow gateways endpoint.
- **pfSense gateways API** — serve fresh-enough cache; shared refresh mutex to avoid stampedes.
- **Speed test during scan** — returns **409** instead of opaque 503.
- **DHCP sniff multi-VLAN** — listen on all sniffable ifaces / optional remote OpenWrt capture.
- **pfSense gateway next-hop** — stop treating `srcip` as ISP next-hop; merge routing gateways.
- **nmap `DISABLE_NMAP=false`** — Zod `envBool()` so string `"false"` is not coerced to `true`.
- SNMP / OpenWrt / Compal scrape and topology placement fixes (BRIDGE-MIB, LuCI, Mac Sharing, ISP WAN modems).

### Changed
- UI copy fully in **English**.
- Speed test report defaults to **90 days** / up to 2000 samples (was 30 samples in UI).
- Admin page reorganized into tabs (overview, network, speed, integrations, discovery, settings).
- Scan-all-CIDRs and background light scan walk every configured subnet; topology rebuild is VLAN-centric.

## [0.1.0] - 2026-07-07

### Added
- Initial release: local network scanner agent with dashboard.
- Admin UI, runtime config API, background scan/enrich.
- Tier 2/3 discovery: SNMP bridge, passive DNS/IGMP/DHCPv6, UniFi/Omada, JA3/SMB, Fingerbank passive signals.
- pfSense REST, FritzBox, SNMP ARP, OpenWrt/Compal HTTP scrape integrations.
- Root LaunchDaemon install for elevated scans (`install-root-service.sh`).

[Unreleased]: https://github.com/tgoliveira11/netscanner/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/tgoliveira11/netscanner/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tgoliveira11/netscanner/releases/tag/v0.1.0
