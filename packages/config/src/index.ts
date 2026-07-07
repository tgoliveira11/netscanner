import { z } from 'zod';

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  GATEWAY_PORT: z.coerce.number().default(4000),
  // Bind to loopback by default: the agent is a local tool and must not be
  // reachable from the LAN. Override only if you understand the exposure.
  GATEWAY_HOST: z.string().default('127.0.0.1'),
  WEB_ORIGIN: z.string().default('http://localhost:3000'),
  /** Origin of the hosted onboarding site, allowed to poll /api/health (CORS). */
  ONBOARDING_ORIGIN: z.string().optional(),
  DATABASE_URL: z.string().default('file:./netscanner.db'),
  /** Max concurrent host probes during discovery/scan (efficiency guard). */
  SCAN_CONCURRENCY: z.coerce.number().default(64),
  /** Per-host discovery timeout in ms. */
  DISCOVERY_TIMEOUT_MS: z.coerce.number().default(1000),
  /** Force-disable nmap even if installed. */
  DISABLE_NMAP: z.coerce.boolean().default(false),

  /** pfSense integration (optional): read DHCP leases via the REST API package. */
  PFSENSE_URL: z.string().optional(), // e.g. https://10.0.51.1
  PFSENSE_API_KEY: z.string().optional(),
  PFSENSE_LEASES_PATH: z.string().default('/api/v2/status/dhcp_server/leases'),
  /** pfSense uses a self-signed cert by default. */
  PFSENSE_INSECURE_TLS: z.coerce.boolean().default(true),

  /** Fingerbank (optional): exact device model/OS from the DHCP fingerprint. */
  FINGERBANK_API_KEY: z.string().optional(),
  /** Passive DHCP sniffing on :67 (needs root); feeds Fingerbank. */
  DHCP_SNIFF: z.coerce.boolean().default(true),

  /** Background: re-check inventory for new DHCP fingerprints (ms). */
  BACKGROUND_ENRICH_INTERVAL_MS: z.coerce.number().default(60_000),
  /** Background: periodic ping+ARP light scan (ms). */
  BACKGROUND_SCAN_INTERVAL_MS: z.coerce.number().default(900_000),
  BACKGROUND_SCAN_ENABLED: z.coerce.boolean().default(true),

  /** Tier-1 passive listeners (mDNS, SSDP, LLDP). */
  PASSIVE_LISTENERS_ENABLED: z.coerce.boolean().default(true),
  LLDP_PASSIVE_ENABLED: z.coerce.boolean().default(true),
  /** SNMP v2c enrichment when snmpget is installed. */
  SNMP_ENABLED: z.coerce.boolean().default(true),
  SNMP_COMMUNITY: z.string().default('public'),

  /** Bearer token for POST /api/agent/restart (localhost). Set by install-root-service.sh. */
  AGENT_CONTROL_TOKEN: z.string().optional(),
});

export type AppConfig = z.infer<typeof EnvSchema>;

let cached: AppConfig | null = null;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  if (cached) return cached;
  cached = EnvSchema.parse(env);
  return cached;
}
