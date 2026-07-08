import { z } from 'zod';

export type SpeedTestTrigger = 'background' | 'manual';

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
  samples: SpeedTestResult[];
}

export const SpeedTestListQuerySchema = z.object({
  limit: z.coerce.number().min(1).max(2000).default(200),
  since: z.string().optional(),
});

export const SpeedTestReportQuerySchema = z.object({
  days: z.coerce.number().min(1).max(365).default(30),
  limit: z.coerce.number().min(1).max(500).default(100),
});
