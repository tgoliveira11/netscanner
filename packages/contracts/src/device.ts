import { z } from 'zod';

/** High-level device categories the classifier can assign. */
export const DeviceType = z.enum([
  'router',
  'switch',
  'access-point',
  'firewall',
  'computer',
  'laptop',
  'phone',
  'tablet',
  'wearable',
  'printer',
  'nas',
  'tv',
  'streaming-device',
  'game-console',
  'camera',
  'smart-speaker',
  'smart-home',
  'iot',
  'server',
  'virtual-machine',
  'unknown',
]);
export type DeviceType = z.infer<typeof DeviceType>;

/** How the device attaches to the network. Often "unknown" from a remote host. */
export const ConnectionType = z.enum(['wired', 'wifi', 'unknown']);
export type ConnectionType = z.infer<typeof ConnectionType>;

export const PortState = z.enum(['open', 'closed', 'filtered']);
export type PortState = z.infer<typeof PortState>;

export const ServiceInfoSchema = z.object({
  port: z.number().int().min(0).max(65535),
  protocol: z.enum(['tcp', 'udp']),
  state: PortState,
  serviceName: z.string().optional(),
  product: z.string().optional(),
  version: z.string().optional(),
  banner: z.string().optional(),
});
export type ServiceInfo = z.infer<typeof ServiceInfoSchema>;

export const OsGuessSchema = z.object({
  family: z.string().optional(),
  name: z.string().optional(),
  version: z.string().optional(),
  accuracy: z.number().min(0).max(100).optional(),
  /**
   * How the OS was determined. `nmap` is an active fingerprint (-O); `inferred`
   * is a best-effort heuristic from banners/ports/vendor used when nmap yields
   * nothing (e.g. a firewalled host with no open+closed port pair). Consumers
   * should treat `inferred` as lower-confidence than an nmap match.
   */
  source: z.enum(['nmap', 'inferred']).optional(),
});
export type OsGuess = z.infer<typeof OsGuessSchema>;

export const SecurityFlagSchema = z.object({
  code: z.string(),
  severity: z.enum(['info', 'low', 'medium', 'high']),
  message: z.string(),
});
export type SecurityFlag = z.infer<typeof SecurityFlagSchema>;

/** Full device record surfaced to the API and dashboard. */
export const DeviceSchema = z.object({
  id: z.string(),
  ip: z.string(),
  mac: z.string().nullable(),
  vendor: z.string().nullable(),
  /** Manufacturer / brand (Fingerbank, UPnP, or OUI). */
  brand: z.string().nullable().optional(),
  /** Product model when known (Fingerbank or UPnP). */
  model: z.string().nullable().optional(),
  hostname: z.string().nullable(),
  deviceType: DeviceType,
  classificationConfidence: z.number().min(0).max(1),
  os: OsGuessSchema.nullable(),
  connectionType: ConnectionType,
  services: z.array(ServiceInfoSchema),
  latencyMs: z.number().nullable(),
  isOnline: z.boolean(),
  securityFlags: z.array(SecurityFlagSchema),
  label: z.string().nullable(),
  notes: z.string().nullable(),
  /** LuCI / router panel login saved per device (password never returned by API). */
  routerScrapeUser: z.string().nullable().optional(),
  routerScrapePasswordSet: z.boolean().optional(),
  firstSeen: z.string(), // ISO 8601
  lastSeen: z.string(),
  /** Raw discovery signals kept for auditability/debugging. */
  signals: z.record(z.unknown()).default({}),
});
export type Device = z.infer<typeof DeviceSchema>;
