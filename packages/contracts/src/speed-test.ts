import { z } from 'zod';

export type SpeedTestTrigger = 'background' | 'manual';
export type SpeedTestKind = 'agent' | 'wan';
/** Observed egress path when testKind=agent (from pfSense telemetry at test time). */
export type SpeedTestEgressRoute = 'vpn' | 'lb' | 'wan' | 'unknown';

export interface SpeedTestResult {
  id: string;
  measuredAt: string;
  downloadMbps: number | null;
  uploadMbps: number | null;
  latencyMs: number | null;
  downloadBytes: number | null;
  uploadBytes: number | null;
  server: string;
  trigger: SpeedTestTrigger;
  error: string | null;
  /** pfSense gateway name when testKind=wan (e.g. WAN_DHCP). */
  wanGateway?: string | null;
  wanInterface?: string | null;
  testKind?: SpeedTestKind;
  /** Active pfSense gateway name when testKind=agent (e.g. GW_SURFSHARK). */
  egressGateway?: string | null;
  egressRoute?: SpeedTestEgressRoute | null;
}

export interface SpeedTestReport {
  periodDays: number;
  count: number;
  latest: SpeedTestResult | null;
  avgDownloadMbps: number | null;
  avgUploadMbps: number | null;
  avgLatencyMs: number | null;
  maxDownloadMbps: number | null;
  minDownloadMbps: number | null;
  /** Newest first. */
  samples: SpeedTestResult[];
}

export const SpeedTestRunRequestSchema = z.object({
  target: z.enum(['agent', 'wan-all']).default('agent'),
});
export type SpeedTestRunRequest = z.infer<typeof SpeedTestRunRequestSchema>;

export const SpeedTestListQuerySchema = z.object({
  limit: z.coerce.number().min(1).max(2000).default(200),
  since: z.string().optional(),
  testKind: z.enum(['agent', 'wan']).optional(),
  wanGateway: z.string().optional(),
});

export const SpeedTestReportQuerySchema = z.object({
  days: z.coerce.number().min(1).max(365).default(90),
  limit: z.coerce.number().min(1).max(5000).default(2000),
  testKind: z.enum(['agent', 'wan']).optional(),
  wanGateway: z.string().optional(),
});
