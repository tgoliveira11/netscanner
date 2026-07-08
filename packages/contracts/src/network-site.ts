import { z } from 'zod';

/** Persisted fingerprint used to recognize a physical network location. */
export const NetworkFingerprintSchema = z.object({
  gatewayIp: z.string().nullable().optional(),
  gatewayMac: z.string().nullable().optional(),
  cidrs: z.array(z.string()).default([]),
  dnsServers: z.array(z.string()).default([]),
  routerId: z.string().nullable().optional(),
  publicIp: z.string().nullable().optional(),
  geoLat: z.number().nullable().optional(),
  geoLon: z.number().nullable().optional(),
  geoLabel: z.string().nullable().optional(),
  ssids: z.array(z.string()).default([]),
  vpnDetected: z.boolean().default(false),
  collectedAt: z.string().optional(),
});
export type NetworkFingerprint = z.infer<typeof NetworkFingerprintSchema>;

/** Per-site integration overrides (merged over global env). */
export const SiteIntegrationsSchema = z.object({
  PFSENSE_URL: z.string().optional(),
  PFSENSE_API_KEY: z.string().optional(),
  SNMP_SWITCH_HOST: z.string().optional(),
  ROUTER_SCRAPE_TARGETS: z.string().optional(),
  SCAN_CIDRS: z.string().optional(),
  TOPOLOGY_MODE: z.enum(['simple', 'vlan']).optional(),
  TOPOLOGY_VLAN_ORDER: z.string().optional(),
  TOPOLOGY_WIRED_VLAN: z.string().optional(),
  TOPOLOGY_MAC_SHARING_PREFIX: z.string().optional(),
});
export type SiteIntegrations = z.infer<typeof SiteIntegrationsSchema>;

export const NetworkSiteSchema = z.object({
  id: z.string(),
  name: z.string(),
  slug: z.string(),
  createdAt: z.string(),
  lastSeenAt: z.string(),
  fingerprint: NetworkFingerprintSchema,
  integrations: SiteIntegrationsSchema.default({}),
  isDefault: z.boolean().default(false),
});
export type NetworkSite = z.infer<typeof NetworkSiteSchema>;

export const SiteMatchCandidateSchema = z.object({
  site: NetworkSiteSchema,
  score: z.number(),
});
export type SiteMatchCandidate = z.infer<typeof SiteMatchCandidateSchema>;

export const ActiveSiteResponseSchema = z.object({
  site: NetworkSiteSchema.nullable(),
  action: z.enum(['match', 'create', 'confirm', 'locked']),
  confidence: z.number().nullable(),
  vpnDetected: z.boolean(),
  locked: z.boolean(),
  observation: NetworkFingerprintSchema.optional(),
  candidates: z.array(SiteMatchCandidateSchema).default([]),
});
export type ActiveSiteResponse = z.infer<typeof ActiveSiteResponseSchema>;

export const UpdateSiteRequestSchema = z.object({
  name: z.string().min(1).max(80).optional(),
  integrations: SiteIntegrationsSchema.optional(),
});
export type UpdateSiteRequest = z.infer<typeof UpdateSiteRequestSchema>;

export const ConfirmSiteRequestSchema = z.object({
  siteId: z.string(),
});
export type ConfirmSiteRequest = z.infer<typeof ConfirmSiteRequestSchema>;

export const LockSiteRequestSchema = z.object({
  siteId: z.string().nullable(),
});
export type LockSiteRequest = z.infer<typeof LockSiteRequestSchema>;

/** Default site id used for migration of legacy inventory rows. */
export const LEGACY_DEFAULT_SITE_ID = '00000000-0000-4000-8000-000000000001';
