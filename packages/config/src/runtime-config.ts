import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import { EnvSchema, type AppConfig } from './env-schema.js';
import { loadConfig, resetConfigCache } from './config-loader.js';

export type ConfigValueType = 'string' | 'number' | 'boolean' | 'secret';

export interface ConfigFieldMeta {
  key: keyof AppConfig & string;
  label: string;
  description: string;
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
  { key: 'SCAN_CONCURRENCY', label: 'Scan concurrency', description: 'Max parallel host probes during discovery.', type: 'number', group: 'Scanning', restartRequired: false },
  { key: 'DISCOVERY_TIMEOUT_MS', label: 'Discovery timeout (ms)', description: 'Per-host discovery timeout.', type: 'number', group: 'Scanning', restartRequired: false },
  { key: 'DISABLE_NMAP', label: 'Disable nmap', description: 'Force pure-Node scanning even if nmap is installed.', type: 'boolean', group: 'Scanning', restartRequired: true },
  { key: 'PFSENSE_URL', label: 'pfSense URL', description: 'Base URL for pfSense REST API (optional).', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'PFSENSE_API_KEY', label: 'pfSense API key', description: 'REST API key for pfSense.', type: 'secret', group: 'Integrations', restartRequired: true },
  { key: 'PFSENSE_LEASES_PATH', label: 'pfSense leases path', description: 'API path for DHCP leases.', type: 'string', group: 'Integrations', restartRequired: false },
  { key: 'PFSENSE_INSECURE_TLS', label: 'pfSense insecure TLS', description: 'Allow self-signed pfSense certificates.', type: 'boolean', group: 'Integrations', restartRequired: false },
  { key: 'FINGERBANK_API_KEY', label: 'Fingerbank API key', description: 'Device identification from DHCP fingerprints.', type: 'secret', group: 'Integrations', restartRequired: true },
  { key: 'DHCP_SNIFF', label: 'DHCP sniffing', description: 'Passive DHCP fingerprint capture (needs root).', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'DHCP_SNIFF_IFACES', label: 'DHCP sniff interfaces', description: 'Comma-separated local ifaces for tcpdump fallback (e.g. any,en0). Empty = auto. Routed VLANs without L2 on this host need remote capture on the switch.', type: 'string', group: 'Discovery', restartRequired: true },
  { key: 'DHCP_SNIFF_SSH_PASSWORD', label: 'DHCP sniff SSH password', description: 'SSH password for remote tcpdump on SNMP_SWITCH_HOST (falls back to ROUTER_SCRAPE password for that host).', type: 'secret', group: 'Discovery', restartRequired: true },
  { key: 'BACKGROUND_ENRICH_INTERVAL_MS', label: 'Background enrich interval (ms)', description: 'How often to re-enrich stale devices.', type: 'number', group: 'Background', restartRequired: false },
  { key: 'BACKGROUND_SCAN_INTERVAL_MS', label: 'Background scan interval (ms)', description: 'How often to run light ping+ARP scans.', type: 'number', group: 'Background', restartRequired: false },
  { key: 'BACKGROUND_SCAN_ENABLED', label: 'Background scan enabled', description: 'Periodic light scans without manual trigger.', type: 'boolean', group: 'Background', restartRequired: false },
  { key: 'PASSIVE_LISTENERS_ENABLED', label: 'Passive listeners', description: 'Continuous mDNS + SSDP listeners.', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'LLDP_PASSIVE_ENABLED', label: 'LLDP passive', description: 'LLDP capture via tcpdump (needs root).', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'SNMP_ENABLED', label: 'SNMP enabled', description: 'SNMP v2c enrichment when snmpget is available.', type: 'boolean', group: 'Discovery', restartRequired: false },
  { key: 'SNMP_COMMUNITY', label: 'SNMP community', description: 'Primary SNMP v2c community (default public).', type: 'string', group: 'Discovery', restartRequired: false },
  { key: 'SNMP_COMMUNITIES', label: 'SNMP communities', description: 'Comma-separated list tried in order.', type: 'string', group: 'Discovery', restartRequired: false },
  { key: 'SNMP_SWITCH_HOST', label: 'SNMP switch host', description: 'Managed switch/AP for BRIDGE-MIB wired/WiFi.', type: 'string', group: 'Discovery', restartRequired: true },
  { key: 'SNMP_WIFI_PORTS', label: 'SNMP WiFi ports', description: 'BRIDGE-MIB bridge-port numbers (dot1dTpFdbPort) where WiFi APs uplink. MACs learned on these ports are treated as wifi.', type: 'string', group: 'Discovery', restartRequired: false },
  { key: 'ROUTER_SNMP_HOST', label: 'Router SNMP host', description: 'Gateway SNMP for ARP/MAC table (no pfSense).', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'ROUTER_SCRAPE_URL', label: 'Router scrape URL', description: 'Base URL of OpenWrt LuCI or Compal router panel (e.g. http://192.168.1.2).', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'ROUTER_SCRAPE_KIND', label: 'Router scrape kind', description: 'Panel type: openwrt (LuCI DHCP) or compal (ARP table).', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'ROUTER_SCRAPE_USER', label: 'Router scrape user', description: 'HTTP login for the router panel.', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'ROUTER_SCRAPE_PASSWORD', label: 'Router scrape password', description: 'HTTP password for the router panel.', type: 'secret', group: 'Integrations', restartRequired: true },
  { key: 'ROUTER_SCRAPE_TARGETS', label: 'Router scrape targets', description: 'Multiple routers: url|kind|user|password separated by ; (e.g. http://192.168.1.2|openwrt|root|pass;http://192.168.10.3|openwrt|root|pass2). Overrides single URL when set.', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'FRITZBOX_URL', label: 'Fritz!Box URL', description: 'Base URL for Fritz!Box host list.', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'FRITZBOX_USER', label: 'Fritz!Box user', description: 'Fritz!Box login username.', type: 'string', group: 'Integrations', restartRequired: true },
  { key: 'FRITZBOX_PASSWORD', label: 'Fritz!Box password', description: 'Fritz!Box login password.', type: 'secret', group: 'Integrations', restartRequired: true },
  { key: 'PASSIVE_DNS_ENABLED', label: 'DNS passive', description: 'tcpdump :53 for hostname hints.', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'PASSIVE_IGMP_ENABLED', label: 'IGMP passive', description: 'Multicast joins (Chromecast, TVs).', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'PASSIVE_DHCPV6_ENABLED', label: 'DHCPv6/RA passive', description: 'IPv6 DHCP and router advertisements.', type: 'boolean', group: 'Discovery', restartRequired: true },
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
    '# NetScanner runtime config — edited via /admin or manually.',
    `# Updated ${new Date().toISOString()}`,
    '',
  ];
  for (const field of CONFIG_FIELDS) {
    if (field.hidden) continue;
    const v = values[field.key];
    if (v === undefined || v === null || v === '') continue;
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
    }
    if (v === null || v === undefined || v === '') continue;
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
  resetConfigCache();
  loadEnvFile(configPath);
  return loadConfig();
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
