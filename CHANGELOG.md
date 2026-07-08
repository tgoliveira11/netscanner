# Changelog

All notable changes to NetScanner are documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
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
- **Compal routers excluded from WiFi probe** — `kind: compal` targets now use RSA LuCI auth and appear in `/api/admin/wireless`.
- **nmap reported off despite `DISABLE_NMAP=false`** — root cause: Zod `coerce.boolean` treats the string `"false"` as `true` (`Boolean("false")`). Fixed with `envBool()` for all boolean env vars; regression tests in `@netscanner/config` and `@netscanner/os-abstraction`.
- **`install-root-service.sh`** now prepends Homebrew `/opt/homebrew/bin` (and `/usr/local/bin` when nmap is there) to the LaunchDaemon PATH so root can find `nmap`.
- SNMP ARP lease parsing for pfSense `STRING:` MAC format (was returning 0 leases).
- OpenWrt LuCI scrape — form login + ubus (`getDHCPLeases` / `getHostHints`) instead of Basic Auth (HTTP 403).
- Admin missing `ROUTER_SCRAPE_*` fields in runtime config UI.
- Startup log now explains **why** nmap is off (config flag vs missing binary).

### Changed
- **Topology rebuild** — VLAN-centric tree: pfSense → VLAN40 (Ubiquiti) + Compal WiFi APs (MAIN/GUEST/IOT) → clients; solid = wired, dashed = wifi; SSIDs when LuCI reports associations.
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
