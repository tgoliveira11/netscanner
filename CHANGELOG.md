# Changelog

All notable changes to NetScanner are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
