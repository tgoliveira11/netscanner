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
  { key: 'BACKGROUND_ENRICH_INTERVAL_MS', label: 'Background enrich interval (ms)', description: 'How often to re-enrich stale devices.', type: 'number', group: 'Background', restartRequired: false },
  { key: 'BACKGROUND_SCAN_INTERVAL_MS', label: 'Background scan interval (ms)', description: 'How often to run light ping+ARP scans.', type: 'number', group: 'Background', restartRequired: false },
  { key: 'BACKGROUND_SCAN_ENABLED', label: 'Background scan enabled', description: 'Periodic light scans without manual trigger.', type: 'boolean', group: 'Background', restartRequired: false },
  { key: 'PASSIVE_LISTENERS_ENABLED', label: 'Passive listeners', description: 'Continuous mDNS + SSDP listeners.', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'LLDP_PASSIVE_ENABLED', label: 'LLDP passive', description: 'LLDP capture via tcpdump (needs root).', type: 'boolean', group: 'Discovery', restartRequired: true },
  { key: 'SNMP_ENABLED', label: 'SNMP enabled', description: 'SNMP v2c enrichment when snmpget is available.', type: 'boolean', group: 'Discovery', restartRequired: false },
  { key: 'SNMP_COMMUNITY', label: 'SNMP community', description: 'SNMP v2c community string.', type: 'string', group: 'Discovery', restartRequired: false },
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
