import { z } from 'zod';

export const PingRequestSchema = z.object({
  ip: z.string(),
  count: z.coerce.number().min(1).max(10).default(3),
});
export type PingRequest = z.infer<typeof PingRequestSchema>;

export const PingResponseSchema = z.object({
  ip: z.string(),
  alive: z.boolean(),
  packetsSent: z.number(),
  packetsReceived: z.number(),
  avgLatencyMs: z.number().nullable(),
  output: z.string(),
});
export type PingResponse = z.infer<typeof PingResponseSchema>;

export const TracerouteRequestSchema = z.object({
  ip: z.string(),
  maxHops: z.coerce.number().min(1).max(30).default(20),
});
export type TracerouteRequest = z.infer<typeof TracerouteRequestSchema>;

export const TracerouteHopSchema = z.object({
  hop: z.number(),
  host: z.string().nullable(),
  ip: z.string().nullable(),
  latencyMs: z.number().nullable(),
});
export type TracerouteHop = z.infer<typeof TracerouteHopSchema>;

export const TracerouteResponseSchema = z.object({
  ip: z.string(),
  hops: z.array(TracerouteHopSchema),
  output: z.string(),
});
export type TracerouteResponse = z.infer<typeof TracerouteResponseSchema>;

export const DnsLookupRequestSchema = z.object({
  name: z.string(),
  type: z.enum(['A', 'AAAA', 'PTR', 'CNAME', 'MX']).default('A'),
  server: z.string().optional(),
});
export type DnsLookupRequest = z.infer<typeof DnsLookupRequestSchema>;

export const DnsLookupResponseSchema = z.object({
  name: z.string(),
  type: z.string(),
  records: z.array(z.string()),
  output: z.string().optional(),
});
export type DnsLookupResponse = z.infer<typeof DnsLookupResponseSchema>;

export const PortScanRequestSchema = z.object({
  ip: z.string(),
  depth: z.enum(['quick', 'standard']).default('quick'),
});
export type PortScanRequest = z.infer<typeof PortScanRequestSchema>;

export const PortScanResponseSchema = z.object({
  ip: z.string(),
  services: z.array(
    z.object({
      port: z.number(),
      protocol: z.string(),
      state: z.string(),
      product: z.string().optional(),
      version: z.string().optional(),
    }),
  ),
  durationMs: z.number(),
});
export type PortScanResponse = z.infer<typeof PortScanResponseSchema>;

export const WifiApSchema = z.object({
  ssid: z.string(),
  bssid: z.string().optional(),
  channel: z.number().optional(),
  rssi: z.number().optional(),
  security: z.string().optional(),
});
export type WifiAp = z.infer<typeof WifiApSchema>;

export const WifiScanResponseSchema = z.object({
  currentSsid: z.string().nullable(),
  aps: z.array(WifiApSchema),
  channelCollisions: z.array(z.object({ channel: z.number(), count: z.number() })),
});
export type WifiScanResponse = z.infer<typeof WifiScanResponseSchema>;

export const CameraScanRequestSchema = z.object({
  cidr: z.string().optional(),
});
export type CameraScanRequest = z.infer<typeof CameraScanRequestSchema>;

export const CameraCandidateSchema = z.object({
  ip: z.string(),
  mac: z.string().nullable(),
  hostname: z.string().nullable(),
  reasons: z.array(z.string()),
  rtspOpen: z.boolean(),
  confidence: z.number(),
});
export type CameraCandidate = z.infer<typeof CameraCandidateSchema>;

export const CameraScanResponseSchema = z.object({
  candidates: z.array(CameraCandidateSchema),
  disclaimer: z.string(),
});
export type CameraScanResponse = z.infer<typeof CameraScanResponseSchema>;
