# Changelog

All notable changes to NetScanner are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **Diagnostics toolkit (A1–A4)** — ping, traceroute, DNS lookup, single-host port scan in the device drawer; **Tools** page with Wi‑Fi scanner, generic DNS, camera heuristics + RTSP probe (travel mode disclaimer).
- **Network control (B0–B5)** — pfSense REST bootstrap (`NS_BLOCK`, `NS_PAUSED`, `NS_AUTOBLOCK`, `NS_LIMIT`); block/unblock/pause with TTL expiry; DHCP static mapping; autoblock on `device.new` (off by default, VLAN filter via `AUTOBLOCK_VLANS`); bandwidth limit tracking; parental schedules via pfSense + Admin panel; policy audit log in SQLite.
- **Network sites** — isolated inventory per location (home, hotel, office); fingerprint match (gateway MAC/IP, CIDR, router id, SSIDs, geo); auto-create unknown sites; manual lock + rename in UI; VPN-aware matching; per-site integration overrides.
- **WAN speed test** — background download/upload sampling via Cloudflare (`SPEED_TEST_*`); results stored in SQLite; `GET /api/speed-tests/report`, manual `POST /api/speed-tests/run`; Admin **Internet speed** panel with 30-day report.
- **pfSense identity classification** — MAC/IP matching `pfsenseInterfaces` → `firewall`; WAN next-hop / WAN* CPE → `router` (ISP modem).
- **Topology WAN tier** — `wan` node role above the pfSense gateway in `/api/topology` and TopologyView.
- **Copy MAC address** — clipboard icon button next to the MAC field in the device drawer; shows a checkmark for 1.5 s after copying; hidden when MAC is unavailable.
- **Compal/CBN Claro LuCI login (RSA)** — fetches `jsencrypt.min.js` from the CPE, encrypts credentials client-side, and reads SSIDs via `wireless_status` JSON (clarostyle firmware).
- **`deriveIspUsername()`** — builds `ISP_<last3MACoctets>` from device MAC.
- Per-device **router panel credentials** (username/password) in the device drawer — saved in SQLite and used for LuCI scrape, DHCP leases, and WiFi/SSID probe.
- **`ROUTER_SCRAPE_TARGETS`** — multiple router scrape entries (`url|kind|user|password; …`) in admin Integrations.
- **`GET /api/admin/wireless`** — OpenWrt LuCI SSID/radio probe for all configured scrape targets.
- **WiFi / SSIDs** section on the admin page.
- **`POST /api/admin/restart`** — admin UI restart without Bearer token (fixes 401 on root LaunchDaemon installs).
- **`GET /api/topology`** — WiFi clients linked to AP/router by SSID (from Compal `wireless_status` assoclist); topology view shows SSID labels on edges.
- **`CHANGELOG.md`** — project change history.

### Fixed
- **DHCP sniff multi-VLAN** — local tcpdump listens on all sniffable ifaces (or `tcpdump -i any`); optional remote capture on OpenWrt switch `br-lan` via SSH when `SNMP_SWITCH_HOST` + scrape/SSH credentials are set (guest/iot VLANs are L2-isolated from the Mac). Config: `DHCP_SNIFF_IFACES`, `DHCP_SNIFF_SSH_PASSWORD`; status: `dhcpSniffIfaces`.
- Admin **DHCP fingerprints** empty state — explain listening status / renew needed instead of a bare `[]` JSON blob; show live/stored counts + sniff ifaces.
- **pfSense gateway next-hop** — `/api/v2/status/gateways` only exposes `srcip` (local WAN IP). Stop treating `srcip` as the ISP next-hop; merge `/api/v2/routing/gateways` and leave `gateway` null for DHCP `dynamic` rows.
- **Topology includes ISP WAN modems** upstream of pfSense (WAN* CPE / `.1` handoff), excludes pfSense self-interface MACs as leaf clients, and keeps VPN overlays (`10.8.` / `10.14.`) out of the home tree.
- **Mac Internet Sharing (`192.168.64.x`)** — clients hang under the sharing Mac host (local scanner LAN device / bridge owner), not under pfSense.
- **SNMP BRIDGE-MIB walk values** — strip `STRING:` / `INTEGER:` tags from `snmpwalk -On` so FDB MAC→port maps populate.
- **Topology parents SNMP-wired clients under the switch** — BRIDGE-MIB `type=wired` wins over heuristic `connectionType=wifi`, so FDB-learned hosts hang off the managed switch.
- **`SNMP_WIFI_PORTS` docs** — clarify values are BRIDGE-MIB bridge ports (AP uplinks); MACs learned there count as wifi under the AP, not as switch access ports.
- **Compal routers excluded from WiFi probe** — `kind: compal` targets now use RSA LuCI auth and appear in `/api/admin/wireless`.
- **nmap reported off despite `DISABLE_NMAP=false`** — root cause: Zod `coerce.boolean` treats the string `"false"` as `true` (`Boolean("false")`). Fixed with `envBool()` for all boolean env vars; regression tests in `@netscanner/config` and `@netscanner/os-abstraction`.
- **`install-root-service.sh`** now prepends Homebrew `/opt/homebrew/bin` (and `/usr/local/bin` when nmap is there) to the LaunchDaemon PATH so root can find `nmap`.
- SNMP ARP lease parsing for pfSense `STRING:` MAC format (was returning 0 leases).
- OpenWrt LuCI scrape — form login + ubus (`getDHCPLeases` / `getHostHints`) instead of Basic Auth (HTTP 403).
- Admin missing `ROUTER_SCRAPE_*` fields in runtime config UI.
- Startup log now explains **why** nmap is off (config flag vs missing binary).

### Changed
- **Scan all configured CIDRs** — dashboard can start one session that walks every local + Extra scan CIDR; progress counters accumulate across subnets.
- **Background light scan** — walks all configured CIDRs in one pass (offline marking once at the end) and kicks shortly after agent start, not only on the interval. Auto-skips Mac Internet Sharing / WAN handoff / VPN overlay interfaces unless listed in Extra scan CIDRs. Also refreshes `pfsenseGateways` / `pfsenseInterfaces` on devices and upserts lease-only hosts (WAN CPE) that sit on ignored scan CIDRs.
- **Topology rebuild** — VLAN-centric tree: ISP modem(s) → pfSense → VLAN40 (Ubiquiti) + Compal WiFi APs (MAIN/GUEST/IOT) → clients; Mac Sharing under the sharing Mac; solid = wired, dashed = wifi; SSIDs when LuCI reports associations.
- **pfSense REST pull** — `PfSenseRestAdapter` now fetches DHCP leases, ARP, gateways, interfaces, and static mappings in one snapshot; maps `opt*` iface keys to GUI labels (e.g. `VLAN10`).
- `HttpRouterScrapeAdapter` uses shared `LuciClient`; adapter names include hostname for composite logs.

## [0.1.0] - 2026-07-07

### Added
- Initial release: local network scanner agent with dashboard.
- Admin UI, runtime config API, background scan/enrich.
- Tier 2/3 discovery: SNMP bridge, passive DNS/IGMP/DHCPv6, UniFi/Omada, JA3/SMB, Fingerbank passive signals.
- pfSense REST, FritzBox, SNMP ARP, OpenWrt/Compal HTTP scrape integrations.
- Root LaunchDaemon install for elevated scans (`install-root-service.sh`).

[Unreleased]: https://github.com/tgoliveira11/netscanner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/tgoliveira11/netscanner/releases/tag/v0.1.0
