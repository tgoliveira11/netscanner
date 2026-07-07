import { z } from 'zod';

export const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  GATEWAY_PORT: z.coerce.number().default(4000),
  GATEWAY_HOST: z.string().default('127.0.0.1'),
  WEB_ORIGIN: z.string().default('http://localhost:3000'),
  ONBOARDING_ORIGIN: z.string().optional(),
  DATABASE_URL: z.string().default('file:./netscanner.db'),
  SCAN_CONCURRENCY: z.coerce.number().default(64),
  DISCOVERY_TIMEOUT_MS: z.coerce.number().default(1000),
  DISABLE_NMAP: z.coerce.boolean().default(false),
  PFSENSE_URL: z.string().optional(),
  PFSENSE_API_KEY: z.string().optional(),
  PFSENSE_LEASES_PATH: z.string().default('/api/v2/status/dhcp_server/leases'),
  PFSENSE_INSECURE_TLS: z.coerce.boolean().default(true),
  FINGERBANK_API_KEY: z.string().optional(),
  DHCP_SNIFF: z.coerce.boolean().default(true),
  BACKGROUND_ENRICH_INTERVAL_MS: z.coerce.number().default(60_000),
  BACKGROUND_SCAN_INTERVAL_MS: z.coerce.number().default(900_000),
  BACKGROUND_SCAN_ENABLED: z.coerce.boolean().default(true),
  PASSIVE_LISTENERS_ENABLED: z.coerce.boolean().default(true),
  LLDP_PASSIVE_ENABLED: z.coerce.boolean().default(true),
  SNMP_ENABLED: z.coerce.boolean().default(true),
  SNMP_COMMUNITY: z.string().default('public'),
  AGENT_CONTROL_TOKEN: z.string().optional(),
});

export type AppConfig = z.infer<typeof EnvSchema>;
