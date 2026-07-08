import { z } from 'zod';
import { envBool } from './env-bool.js';

export const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  GATEWAY_PORT: z.coerce.number().default(4000),
  GATEWAY_HOST: z.string().default('127.0.0.1'),
  WEB_ORIGIN: z.string().default('http://localhost:3000'),
  ONBOARDING_ORIGIN: z.string().optional(),
  DATABASE_URL: z.string().default('file:./netscanner.db'),
  SCAN_CONCURRENCY: z.coerce.number().default(64),
  DISCOVERY_TIMEOUT_MS: z.coerce.number().default(1000),
  DISABLE_NMAP: envBool(false),
  PFSENSE_URL: z.string().optional(),
  PFSENSE_API_KEY: z.string().optional(),
  PFSENSE_LEASES_PATH: z.string().default('/api/v2/status/dhcp_server/leases'),
  PFSENSE_INSECURE_TLS: envBool(true),
  FINGERBANK_API_KEY: z.string().optional(),
  DHCP_SNIFF: envBool(true),
  /**
   * Comma-separated local ifaces for DHCP tcpdump fallback (e.g. `any,en0`).
   * Empty = auto from sniffable local interfaces; prefer `any` when multiple.
   */
  DHCP_SNIFF_IFACES: z.string().default(''),
  /** Optional SSH password for remote DHCP sniff on SNMP_SWITCH_HOST (else ROUTER_SCRAPE_* for that IP). */
  DHCP_SNIFF_SSH_PASSWORD: z.string().optional(),
  BACKGROUND_ENRICH_INTERVAL_MS: z.coerce.number().default(60_000),
  BACKGROUND_SCAN_INTERVAL_MS: z.coerce.number().default(900_000),
  BACKGROUND_SCAN_ENABLED: envBool(true),
  PASSIVE_LISTENERS_ENABLED: envBool(true),
  LLDP_PASSIVE_ENABLED: envBool(true),
  SNMP_ENABLED: envBool(true),
  SNMP_COMMUNITY: z.string().default('public'),
  /** Comma-separated communities tried in order (falls back to SNMP_COMMUNITY). */
  SNMP_COMMUNITIES: z.string().optional(),
  /** Managed switch/AP for BRIDGE-MIB wired/WiFi (SNMP v2c). */
  SNMP_SWITCH_HOST: z.string().optional(),
  /** Bridge port numbers treated as WiFi/radio uplinks (comma-separated). */
  SNMP_WIFI_PORTS: z.string().default(''),
  PASSIVE_DNS_ENABLED: envBool(true),
  PASSIVE_IGMP_ENABLED: envBool(true),
  PASSIVE_DHCPV6_ENABLED: envBool(true),
  /** Continuous tcpdump LLDP stream vs periodic burst capture. */
  LLDP_STREAM_ENABLED: envBool(true),
  /** Extra subnets to scan (comma-separated CIDRs). Local interfaces are always included. */
  SCAN_CIDRS: z.string().default(''),
  ADAPTIVE_SCAN_ENABLED: envBool(true),
  MASSCAN_ENABLED: envBool(false),
  MASSCAN_RATE: z.coerce.number().default(1000),
  /** Gateway SNMP for ipNetToMedia (DHCP-like MAC↔IP without pfSense). */
  ROUTER_SNMP_HOST: z.string().optional(),
  FRITZBOX_URL: z.string().optional(),
  FRITZBOX_USER: z.string().default(''),
  FRITZBOX_PASSWORD: z.string().optional(),
  SNMP_V3_USER: z.string().optional(),
  SNMP_V3_AUTH_PASS: z.string().optional(),
  SNMP_V3_PRIV_PASS: z.string().optional(),
  SNMP_V3_AUTH_PROTO: z.string().default('SHA'),
  SNMP_V3_PRIV_PROTO: z.string().default('AES'),
  SNMP_V3_SEC_LEVEL: z.enum(['noAuthNoPriv', 'authNoPriv', 'authPriv']).default('authPriv'),
  UNIFI_URL: z.string().optional(),
  UNIFI_API_KEY: z.string().optional(),
  UNIFI_SITE: z.string().default('default'),
  OMADA_URL: z.string().optional(),
  OMADA_CLIENT_ID: z.string().optional(),
  OMADA_CLIENT_SECRET: z.string().optional(),
  OMADA_SITE_ID: z.string().optional(),
  ROUTER_SCRAPE_URL: z.string().optional(),
  ROUTER_SCRAPE_KIND: z.enum(['openwrt', 'compal']).optional(),
  ROUTER_SCRAPE_USER: z.string().optional(),
  ROUTER_SCRAPE_PASSWORD: z.string().optional(),
  /** Semicolon-separated scrape targets: url|kind|user|password (password may contain |). */
  ROUTER_SCRAPE_TARGETS: z.string().optional(),
  MAC_DNS_CACHE_ENABLED: envBool(true),
  PROTOCOL_PROBE_ENABLED: envBool(true),
  AGENT_CONTROL_TOKEN: z.string().optional(),
  /** Shared secret for pfSense package push (Bearer token). */
});

export type AppConfig = z.infer<typeof EnvSchema>;
