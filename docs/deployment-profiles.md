# Deployment profiles

NetScanner runs as a **single local agent** (gateway + scanner + dashboard). Choose a profile by setting `config.env` — no code changes required.

## Profile comparison

| Profile | pfSense | Switch SNMP | Router scrape | Topology mode |
|---------|---------|-------------|---------------|---------------|
| **Standalone** | — | — | — | `simple` (default) |
| **pfSense only** | REST API key | — | — | `simple` |
| **pfSense + managed switch** | REST API key | `SNMP_SWITCH_HOST` | — | `simple` |
| **Multi-VLAN home lab** | REST + optional SSH | `SNMP_SWITCH_HOST` | OpenWrt / `kind:compal` | `vlan` |

---

## Standalone (no router integration)

Scan and classify devices on local subnets only. Works on any LAN without pfSense.

```env
# Minimal — discovery + nmap on local interfaces
DISABLE_NMAP=false
BACKGROUND_SCAN_ENABLED=true
TOPOLOGY_MODE=simple
```

**You get:** device inventory, ports, classification from banners/mDNS/DHCP sniff (root), passive listeners.

**You don't get:** authoritative DHCP leases, per-VLAN tags, firewall traffic relations, SNMP wired/WiFi placement.

---

## pfSense only

Use pfSense REST for leases, ARP, gateways, interfaces, and (optional) firewall state traffic.

```env
PFSENSE_URL=https://192.168.1.1
PFSENSE_API_KEY=your-api-key
PFSENSE_INSECURE_TLS=true
PFSENSE_TRAFFIC_ENABLED=true

TOPOLOGY_MODE=simple
```

**You get:** accurate MAC/IP/hostname from DHCP, `pfsenseInterface` VLAN labels, Relations traffic peers, gateway-centric topology.

**Optional:** `PFSENSE_SSH_PASSWORD` + `PFSENSE_SSH_PORT` for cross-VLAN DNS passive capture when the agent cannot see guest/IoT at L2.

---

## pfSense + managed switch

Add BRIDGE-MIB on a managed L2 switch for wired vs WiFi and switch-port placement.

```env
PFSENSE_URL=https://192.168.1.1
PFSENSE_API_KEY=your-api-key

SNMP_ENABLED=true
SNMP_SWITCH_HOST=192.168.1.2
SNMP_COMMUNITY=public
# Bridge ports where WiFi APs uplink (dot1dTpFdbPort numbers)
SNMP_WIFI_PORTS=2,3

TOPOLOGY_MODE=simple
```

**Topology (simple):** pfSense → switch → clients (wired under switch via FDB; WiFi under gateway unless AP scrape targets are configured).

**Optional remote DHCP/DNS** on the switch (OpenWrt `br-lan`):

```env
DHCP_SNIFF=true
DHCP_SNIFF_SSH_PASSWORD=...
# Uses SNMP_SWITCH_HOST for remote tcpdump when set
```

---

## Multi-VLAN home lab (advanced)

For several pfSense interfaces (e.g. infra + multiple WiFi segments) and optional vendor-specific AP panels.

```env
PFSENSE_URL=https://192.168.1.1
PFSENSE_API_KEY=your-api-key
SNMP_SWITCH_HOST=192.168.1.2
SNMP_WIFI_PORTS=2,3

TOPOLOGY_MODE=vlan
TOPOLOGY_WIRED_VLAN=VLAN40
TOPOLOGY_VLAN_ORDER=VLAN40,VLAN10,VLAN30,VLAN20

# Standard OpenWrt LuCI DHCP scrape (fixed URL OK for infra switches)
ROUTER_SCRAPE_TARGETS=http://10.0.40.2|openwrt|root|password

# Compal/Claro APs — identity only (no IP). Bound at runtime to the discovered
# device whose MAC/hostname matches CLARO_xxxxxx / CBN_RE_xxxxxx.
# ROUTER_SCRAPE_TARGETS=...;compal|CLARO_112233|password
```

**Topology (vlan):** ISP modem(s) → pfSense → wired infra switch + WiFi APs per VLAN segment → clients.

### Compal / Claro CPE (`kind:compal`)

Use `compal|CLARO_xxxxxx|password` in `ROUTER_SCRAPE_TARGETS` (or save credentials on the device). Management IPs come from inventory discovery (matched by MAC / `CBN_RE_*` hostname). Do not pin Compal IPs in config — DHCP/AP moves will break scrapes.

---

## Quick reference — topology settings

| Variable | Default | Purpose |
|----------|---------|---------|
| `TOPOLOGY_MODE` | `simple` | `simple` = pfSense → switch → clients; `vlan` = multi-segment tree |
| `TOPOLOGY_VLAN_ORDER` | (empty) | Comma-separated pfSense interface labels for display order |
| `TOPOLOGY_WIRED_VLAN` | (empty) | Interface label for the wired switch segment (`vlan` mode) |
| `TOPOLOGY_MAC_SHARING_PREFIX` | `192.168.64.` | Mac Internet Sharing side branch |

---

## Elevated agent (recommended)

OS detection (`nmap -O`), SYN/UDP deep scans, and local DHCP sniff require root:

```bash
sudo env "PATH=$PATH" bash scripts/install-root-service.sh
```

See [README](../README.md) for install and security model.
