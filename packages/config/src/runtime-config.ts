import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { EnvSchema, type AppConfig } from './env-schema.js';
import { loadConfig, resetConfigCache } from './config-loader.js';
import {
  formatRouterScrapeTargetsForAdmin,
  normalizeRouterScrapeTargetsInput,
} from './router-scrape-config.js';

export type ConfigValueType = 'string' | 'number' | 'boolean' | 'secret' | 'multiline';

export interface ConfigFieldMeta {
  key: keyof AppConfig & string;
  label: string;
  description: string;
  /** Longer hover help in Admin; falls back to description when omitted. */
  help?: string;
  type: ConfigValueType;
  group: string;
  restartRequired: boolean;
  hidden?: boolean;
}

export const CONFIG_FIELDS: ConfigFieldMeta[] = [
  { key: 'GATEWAY_PORT', label: 'Gateway port', description: 'HTTP port the agent listens on.', type: 'number', group: 'Gateway', restartRequired: true },
  { key: 'GATEWAY_HOST', label: 'Gateway host', description: 'Bind address (127.0.0.1 recommended).', type: 'string', group: 'Gateway', restartRequired: true },
  { key: 'WEB_ORIGIN', label: 'Web origin', description: 'Allowed CORS origin for the dev dashboard.', type: 'string', group: 'Gateway', restartRequired: true },
  { key: 'ONBOARDING_ORIGIN', label: 'Onboarding origin', description: 'Hosted onboarding site allowed to poll /api/health.', type: 'string', group: 'Gateway', restartRequired: true },
  { key: 'DATABASE_URL', label: 'Database URL', description: 'SQLite file path (Prisma datasource).', type: 'string', group: 'Persistence', restartRequired: true },
  { key: 'PFSENSE_CONTROL_ENABLED', label: 'pfSense control enabled', description: 'Enable block/pause/DHCP/bandwidth writes via pfSense REST API.', type: 'boolean', group: 'Network Control', restartRequired: true },
  { key: 'AUTOBLOCK_ENABLED', label: 'Autoblock new devices', description: 'Auto-add new devices to NS_AUTOBLOCK alias (off by default).', type: 'boolean', group: 'Network Control', restartRequired: true },
  { key: 'AUTOBLOCK_VLANS', label: 'Autoblock VLANs', description: 'Comma-separated pfSense interface labels (e.g. LAN_GUEST). Empty = all VLANs when autoblock is on.', type: 'string', group: 'Network Control', restartRequired: true },
  { key: 'CONTROL_TOKEN', label: 'Control API token', description: 'Optional Bearer for /api/control/* when set; localhost works without it.', type: 'secret', group: 'Network Control', restartRequired: true },
  { key: 'SITE_AUTO_CREATE', label: 'Auto-create sites', description: 'Create a new site when fingerprint does not match any known site.', type: 'boolean', group: 'Network Sites', restartRequired: true },
  { key: 'SITE_MATCH_THRESHOLD', label: 'Site match threshold', description: 'Minimum score (0–1) to accept an automatic site match.', type: 'number', group: 'Network Sites', restartRequired: true },
  { key: 'SITE_AMBIGUOUS_THRESHOLD', label: 'Site ambiguous threshold', description: 'Minimum score to show ambiguous site confirmation UI.', type: 'number', group: 'Network Sites', restartRequired: true },
  { key: 'SITE_VPN_IGNORE_GEO', label: 'Site VPN ignore geo', description: 'Ignore geolocation for site matching when VPN/tunnel is detected.', type: 'boolean', group: 'Network Sites', restartRequired: true },
  { key: 'SCAN_CONCURRENCY', label: 'Scan concurrency', description: 'Max parallel host probes during discovery.', type: 'number', group: 'Scanning', restartRequired: false },
  { key: 'DISCOVERY_TIMEOUT_MS', label: 'Discovery timeout (ms)', description: 'Per-host discovery timeout.', type: 'number', group: 'Scanning', restartRequired: false },
  { key: 'DISABLE_NMAP', label: 'Disable nmap', description: 'Force pure-Node scanning even if nmap is installed.', type: 'boolean', group: 'Scanning', restartRequired: true },
  { key: 'PFSENSE_URL', label: 'pfSense URL', description: 'Base URL for pfSense REST API (optional).', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'PFSENSE_API_KEY', label: 'pfSense API key', description: 'REST API key for pfSense.', type: 'secret', group: 'Integrations', restartRequired: true },
  { key: 'PFSENSE_LEASES_PATH', label: 'pfSense leases path', description: 'API path for DHCP leases.', type: 'string', group: 'Integrations', restartRequired: false },
  { key: 'PFSENSE_INSECURE_TLS', label: 'pfSense insecure TLS', description: 'Allow self-signed pfSense certificates.', type: 'boolean', group: 'Integrations', restartRequired: false },
  { key: 'PFSENSE_TRAFFIC_ENABLED', label: 'pfSense traffic (REST)', description: 'Poll /api/v2/firewall/states for per-device bytes and Relations peers (needs API key).', type: 'boolean', group: 'Integrations', restartRequired: true },
  { key: 'PFSENSE_SSH_USER', label: 'pfSense SSH user', description: 'SSH login for remote DNS tcpdump on pfSense.', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'PFSENSE_SSH_PORT', label: 'pfSense SSH port', description: 'SSH port for remote DNS capture (default 22; some labs use 2231).', type: 'number', group: 'Integrations', restartRequired: true },
  { key: 'PFSENSE_SSH_PASSWORD', label: 'pfSense SSH password', description: 'SSH password for remote DNS tcpdump on pfSense (cross-VLAN).', type: 'secret', group: 'Integrations', restartRequired: true },
  { key: 'FINGERBANK_API_KEY', label: 'Fingerbank API key', description: 'Device identification from DHCP fingerprints.', type: 'secret', group: 'Integrations', restartRequired: true },
  { key: 'DHCP_SNIFF', label: 'DHCP sniffing', description: 'Passive DHCP fingerprint capture (needs root).', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'DHCP_SNIFF_IFACES', label: 'DHCP sniff interfaces', description: 'Comma-separated local ifaces for tcpdump fallback (e.g. any,en0). Empty = auto. Routed VLANs without L2 on this host need remote capture on the switch.', type: 'string', group: 'Discovery', restartRequired: true },
  { key: 'DHCP_SNIFF_SSH_PASSWORD', label: 'DHCP sniff SSH password', description: 'SSH password for remote tcpdump on SNMP_SWITCH_HOST (falls back to ROUTER_SCRAPE password for that host).', type: 'secret', group: 'Discovery', restartRequired: true },
  { key: 'BACKGROUND_ENRICH_INTERVAL_MS', label: 'Background enrich interval (ms)', description: 'How often to re-enrich stale devices.', type: 'number', group: 'Background', restartRequired: false },
  { key: 'BACKGROUND_SCAN_INTERVAL_MS', label: 'Background scan interval (ms)', description: 'How often to run light ping+ARP scans.', type: 'number', group: 'Background', restartRequired: false },
  { key: 'BACKGROUND_SCAN_ENABLED', label: 'Background scan enabled', description: 'Periodic light scans without manual trigger.', type: 'boolean', group: 'Background', restartRequired: false },
  { key: 'BACKGROUND_PORT_RESCAN_ENABLED', label: 'Background port rescan', description: 'Re-probe stale online devices for open ports between full scans.', type: 'boolean', group: 'Background', restartRequired: false },
  { key: 'BACKGROUND_PORT_RESCAN_MAX_AGE_MS', label: 'Port rescan max age (ms)', description: 'Re-scan ports when older than this (default 7 days).', type: 'number', group: 'Background', restartRequired: false },
  { key: 'BACKGROUND_PORT_RESCAN_BATCH', label: 'Port rescan batch', description: 'Max devices to port-rescan per enrich sweep.', type: 'number', group: 'Background', restartRequired: false },
  { key: 'PASSIVE_LISTENERS_ENABLED', label: 'Passive listeners', description: 'Continuous mDNS + SSDP listeners.', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'LLDP_PASSIVE_ENABLED', label: 'LLDP passive', description: 'LLDP capture via tcpdump (needs root).', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'SNMP_ENABLED', label: 'SNMP enabled', description: 'SNMP v2c enrichment when snmpget is available.', type: 'boolean', group: 'Discovery', restartRequired: false },
  { key: 'SNMP_COMMUNITY', label: 'SNMP community', description: 'Primary SNMP v2c community (default public).', type: 'string', group: 'Discovery', restartRequired: false },
  { key: 'SNMP_COMMUNITIES', label: 'SNMP communities', description: 'Comma-separated list tried in order.', type: 'string', group: 'Discovery', restartRequired: false },
  { key: 'SNMP_SWITCH_HOST', label: 'SNMP switch host', description: 'Managed switch/AP for BRIDGE-MIB wired/WiFi.', type: 'string', group: 'Discovery', restartRequired: true },
  { key: 'SNMP_WIFI_PORTS', label: 'SNMP WiFi ports', description: 'BRIDGE-MIB bridge-port numbers (dot1dTpFdbPort) where WiFi APs uplink. MACs learned on these ports are treated as wifi.', type: 'string', group: 'Discovery', restartRequired: false },
  { key: 'SNMP_V3_USER', label: 'SNMP v3 user', description: 'SNMPv3 username (optional).', type: 'string', group: 'Discovery', restartRequired: true },
  { key: 'SNMP_V3_AUTH_PASS', label: 'SNMP v3 auth password', description: 'SNMPv3 authentication password.', type: 'secret', group: 'Discovery', restartRequired: true },
  { key: 'SNMP_V3_PRIV_PASS', label: 'SNMP v3 priv password', description: 'SNMPv3 privacy password.', type: 'secret', group: 'Discovery', restartRequired: true },
  { key: 'SNMP_V3_AUTH_PROTO', label: 'SNMP v3 auth proto', description: 'SNMPv3 auth protocol (SHA, MD5).', type: 'string', group: 'Discovery', restartRequired: true },
  { key: 'SNMP_V3_PRIV_PROTO', label: 'SNMP v3 priv proto', description: 'SNMPv3 privacy protocol (AES, DES).', type: 'string', group: 'Discovery', restartRequired: true },
  { key: 'SNMP_V3_SEC_LEVEL', label: 'SNMP v3 security level', description: 'noAuthNoPriv, authNoPriv, or authPriv.', type: 'string', group: 'Discovery', restartRequired: true },
  { key: 'ROUTER_SNMP_HOST', label: 'Router SNMP host', description: 'Gateway SNMP for ARP/MAC table (no pfSense).', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'ROUTER_SCRAPE_URL', label: 'Router scrape URL', description: 'Base URL of OpenWrt LuCI or Compal router panel (e.g. http://192.168.1.2).', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'ROUTER_SCRAPE_KIND', label: 'Router scrape kind', description: 'Panel type: openwrt (LuCI DHCP) or compal (ARP table).', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'ROUTER_SCRAPE_USER', label: 'Router scrape user', description: 'HTTP login for the router panel.', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'ROUTER_SCRAPE_PASSWORD', label: 'Router scrape password', description: 'HTTP password for the router panel.', type: 'secret', group: 'Integrations', restartRequired: true },
  { key: 'ROUTER_SCRAPE_TARGETS', label: 'Router scrape targets', description: 'One router per line: url|kind|user|password (kind = openwrt or compal).', type: 'multiline', group: 'Integrations', restartRequired: true },
  { key: 'TOPOLOGY_MODE', label: 'Topology mode', description: 'simple = pfSense → switch → clients; vlan = multi-VLAN home layout with optional WiFi APs.', type: 'string', group: 'Topology', restartRequired: false },
  { key: 'TOPOLOGY_VLAN_ORDER', label: 'Topology VLAN order', description: 'Comma-separated pfSense interface labels for vlan mode (e.g. VLAN40,VLAN10,VLAN30).', type: 'string', group: 'Topology', restartRequired: false },
  { key: 'TOPOLOGY_WIRED_VLAN', label: 'Topology wired VLAN', description: 'pfSense interface label for the wired switch segment in vlan mode (e.g. VLAN40).', type: 'string', group: 'Topology', restartRequired: false },
  { key: 'TOPOLOGY_MAC_SHARING_PREFIX', label: 'Mac sharing prefix', description: 'IP prefix for Mac Internet Sharing side branch (default 192.168.64.).', type: 'string', group: 'Topology', restartRequired: false },
  { key: 'SPEED_TEST_ENABLED', label: 'Speed test enabled', description: 'Periodic WAN download/upload sampling (Cloudflare).', type: 'boolean', group: 'Background', restartRequired: false },
  { key: 'SPEED_TEST_INTERVAL_MS', label: 'Speed test interval (ms)', description: 'How often to run background speed tests (default 1h).', type: 'number', group: 'Background', restartRequired: false },
  { key: 'SPEED_TEST_DOWNLOAD_BYTES', label: 'Speed test download bytes', description: 'Download payload size per test (default 10 MB).', type: 'number', group: 'Background', restartRequired: false },
  { key: 'SPEED_TEST_UPLOAD_BYTES', label: 'Speed test upload bytes', description: 'Upload payload size per test (default 5 MB).', type: 'number', group: 'Background', restartRequired: false },
  { key: 'SPEED_TEST_URL', label: 'Speed test URL', description: 'Base URL for Cloudflare speed endpoints.', type: 'string', group: 'Background', restartRequired: false },
  { key: 'FRITZBOX_URL', label: 'Fritz!Box URL', description: 'Base URL for Fritz!Box host list.', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'FRITZBOX_USER', label: 'Fritz!Box user', description: 'Fritz!Box login username.', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'FRITZBOX_PASSWORD', label: 'Fritz!Box password', description: 'Fritz!Box login password.', type: 'secret', group: 'Integrations', restartRequired: true },
  { key: 'UNIFI_URL', label: 'UniFi URL', description: 'UniFi controller base URL.', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'UNIFI_API_KEY', label: 'UniFi API key', description: 'UniFi API key.', type: 'secret', group: 'Integrations', restartRequired: true },
  { key: 'UNIFI_SITE', label: 'UniFi site', description: 'UniFi site name (default).', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'OMADA_URL', label: 'Omada URL', description: 'TP-Link Omada controller URL.', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'OMADA_CLIENT_ID', label: 'Omada client ID', description: 'Omada Open API client id.', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'OMADA_CLIENT_SECRET', label: 'Omada client secret', description: 'Omada Open API client secret.', type: 'secret', group: 'Integrations', restartRequired: true },
  { key: 'OMADA_SITE_ID', label: 'Omada site ID', description: 'Omada site identifier.', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'PASSIVE_DNS_ENABLED', label: 'DNS passive', description: 'tcpdump :53 for hostname hints.', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'PASSIVE_IGMP_ENABLED', label: 'IGMP passive', description: 'Multicast joins (Chromecast, TVs).', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'PASSIVE_DHCPV6_ENABLED', label: 'DHCPv6 passive', description: 'Passive DHCPv6 fingerprint capture.', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'MAC_DNS_CACHE_ENABLED', label: 'MAC DNS cache', description: 'Resolve hostnames from local DNS cache by MAC.', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'PROTOCOL_PROBE_ENABLED', label: 'Protocol probe', description: 'Lightweight protocol banners during discovery.', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'PRESENCE_POLL_ENABLED', label: 'Presence polling', description: 'Fast ping loop for near-real-time online/offline.', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'PRESENCE_POLL_INTERVAL_MS', label: 'Presence interval (ms)', description: 'How often to ping known devices (default 30s).', type: 'number', group: 'Discovery', restartRequired: true },
  { key: 'PRESENCE_PING_TIMEOUT_MS', label: 'Presence ping timeout (ms)', description: 'ICMP timeout per device (default 2500ms).', type: 'number', group: 'Discovery', restartRequired: true },
  { key: 'PRESENCE_OFFLINE_AFTER_MISSES', label: 'Offline after misses', description: 'Consecutive failed polls before marking offline (default 4).', type: 'number', group: 'Discovery', restartRequired: true },
  { key: 'PRESENCE_PING_CONCURRENCY', label: 'Presence ping concurrency', description: 'Parallel ICMP probes during presence polling.', type: 'number', group: 'Discovery', restartRequired: true },
  { key: 'AGENT_ENCRYPTION_KEY', label: 'DB encryption key', description: 'Encrypts router passwords at rest (64-char hex). Auto-generated file if unset.', type: 'secret', group: 'Agent', restartRequired: true, hidden: true },
  { key: 'P0F_PASSIVE_ENABLED', label: 'p0f passive (TCP SYN)', description: 'OS hints from passive SYN stack fingerprinting.', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'CDP_PASSIVE_ENABLED', label: 'CDP passive', description: 'Cisco CDP neighbor capture (Cisco gear only).', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'BAYESIAN_CLASSIFICATION', label: 'Bayesian classification', description: 'Probabilistic fusion of classification evidence.', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'LLDP_STREAM_ENABLED', label: 'LLDP stream', description: 'Continuous LLDP tcpdump vs periodic burst.', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'SCAN_CIDRS', label: 'Extra scan CIDRs', description: 'Comma-separated subnets beyond local interfaces. Used by “Scan all CIDRs” and by the background light scan.', type: 'string', group: 'Scanning', restartRequired: false },
  { key: 'ADAPTIVE_SCAN_ENABLED', label: 'Adaptive scan', description: 'Quick probes on well-known devices.', type: 'boolean', group: 'Scanning', restartRequired: false },
  { key: 'MASSCAN_ENABLED', label: 'Masscan enabled', description: 'Fast sweep on large subnets.', type: 'boolean', group: 'Scanning', restartRequired: true },
  { key: 'MASSCAN_RATE', label: 'Masscan rate', description: 'Packets per second for masscan.', type: 'number', group: 'Scanning', restartRequired: false },
  { key: 'AGENT_CONTROL_TOKEN', label: 'Agent control token', description: 'Bearer token for POST /api/agent/restart.', type: 'secret', group: 'Agent', restartRequired: true, hidden: true },
];

const SECRET_KEYS = new Set(CONFIG_FIELDS.filter((f) => f.type === 'secret').map((f) => f.key));

export function resolveConfigFilePath(cwd = process.cwd()): string {
  if (process.env.NETSCANNER_CONFIG_PATH) return process.env.NETSCANNER_CONFIG_PATH;
  return path.join(cwd, 'config.env');
}

export function readEnvFileMap(filePath: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!existsSync(filePath)) return out;
  const text = readFileSync(filePath, 'utf8');
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    out[key] = value;
  }
  return out;
}

/** Keys editable via /admin — config.env values override the same keys from the process environment. */
export const ADMIN_CONFIG_KEYS = new Set(
  CONFIG_FIELDS.filter((f) => !f.hidden).map((f) => f.key),
);

/**
 * Load config with admin file precedence: for every admin-visible key present in
 * config.env, that value wins over LaunchDaemon / shell environment.
 */
export function loadAdminConfig(configPath: string, baseEnv: NodeJS.ProcessEnv = process.env): AppConfig {
  resetConfigCache();
  const fileEnv = readEnvFileMap(configPath);
  const env: NodeJS.ProcessEnv = { ...baseEnv };
  for (const key of ADMIN_CONFIG_KEYS) {
    if (key in fileEnv) env[key] = fileEnv[key];
  }
  return loadConfig(env);
}

export function loadEnvFile(filePath: string): void {
  if (!existsSync(filePath)) return;
  const text = readFileSync(filePath, 'utf8');
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq <= 0) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

function serializeEnvValue(value: unknown): string {
  const s = String(value ?? '');
  if (/[\s#"']/.test(s)) return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  return s;
}

export function saveEnvFile(filePath: string, values: Record<string, string | number | boolean>): void {
  mkdirSync(path.dirname(filePath), { recursive: true });
  const lines = [
    '# NetScanner runtime config — edited via /admin (takes precedence over LaunchDaemon env).',
    `# Updated ${new Date().toISOString()}`,
    '',
  ];
  for (const field of CONFIG_FIELDS) {
    if (field.hidden) continue;
    const v = values[field.key];
    if (v === undefined || v === null) continue;
    lines.push(`${field.key}=${serializeEnvValue(v)}`);
  }
  writeFileSync(filePath, lines.join('\n') + '\n', 'utf8');
}

export function maskSecret(value: string | undefined): string | null {
  if (!value) return null;
  return '••••••••';
}

export function configForAdmin(config: AppConfig): Record<string, string | number | boolean | null> {
  const out: Record<string, string | number | boolean | null> = {};
  for (const field of CONFIG_FIELDS) {
    if (field.hidden) continue;
    const raw = config[field.key as keyof AppConfig];
    if (field.type === 'secret') {
      out[field.key] = raw ? maskSecret(String(raw)) : null;
    } else if (raw === undefined) {
      out[field.key] = null;
    } else if (field.key === 'ROUTER_SCRAPE_TARGETS') {
      out[field.key] = formatRouterScrapeTargetsForAdmin(String(raw));
    } else {
      out[field.key] = raw as string | number | boolean;
    }
  }
  return out;
}

const PartialConfigSchema = EnvSchema.partial();

export function parseConfigPatch(
  body: Record<string, unknown>,
  current: AppConfig,
): { values: AppConfig; restartRequired: boolean } {
  const patch: Record<string, unknown> = {};
  for (const field of CONFIG_FIELDS) {
    if (field.hidden) continue;
    if (!(field.key in body)) continue;
    const v = body[field.key];
    if (field.type === 'secret') {
      if (v === null || v === undefined || v === '' || v === maskSecret('x')) continue;
    } else if (v === null || v === undefined) {
      continue;
    } else if (v === '' && field.type !== 'string' && field.type !== 'multiline') {
      continue;
    }
    if (field.key === 'ROUTER_SCRAPE_TARGETS' && typeof v === 'string') {
      patch[field.key] = normalizeRouterScrapeTargetsInput(v);
      continue;
    }
    patch[field.key] = v;
  }

  const parsed = PartialConfigSchema.safeParse(patch);
  if (!parsed.success) throw new Error(parsed.error.message);

  const merged = { ...current, ...parsed.data };
  const full = EnvSchema.parse({ ...process.env, ...flattenConfig(merged) });

  let restartRequired = false;
  for (const field of CONFIG_FIELDS) {
    if (!field.restartRequired) continue;
    if (field.key in parsed.data && parsed.data[field.key as keyof AppConfig] !== current[field.key as keyof AppConfig]) {
      restartRequired = true;
    }
  }

  return { values: full, restartRequired };
}

function flattenConfig(config: AppConfig): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(config)) {
    if (v === undefined || v === null) continue;
    out[k] = String(v);
  }
  return out;
}

export function reloadRuntimeConfig(configPath: string): AppConfig {
  return loadAdminConfig(configPath);
}

export function applyConfigToProcess(config: AppConfig): void {
  for (const [k, v] of Object.entries(config)) {
    if (v === undefined || v === null) delete process.env[k];
    else process.env[k] = String(v);
  }
}

export function isSecretKey(key: string): boolean {
  return SECRET_KEYS.has(key as keyof AppConfig & string);
}
