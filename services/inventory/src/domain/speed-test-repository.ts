import type { SpeedTestResult, SpeedTestTrigger } from '@netscanner/contracts';

export interface SpeedTestInsert {
  downloadMbps: number | null;
  uploadMbps: number | null;
  latencyMs: number | null;
  downloadBytes: number | null;
  uploadBytes: number | null;
  server: string;
  trigger: SpeedTestTrigger;
  error: string | null;
}

export interface SpeedTestListFilter {
  limit?: number;
  since?: Date;
}

export interface ISpeedTestRepository {
  insert(row: SpeedTestInsert): Promise<SpeedTestResult>;
  list(filter?: SpeedTestListFilter): Promise<SpeedTestResult[]>;
  listSince(since: Date, limit?: number): Promise<SpeedTestResult[]>;
  latest(): Promise<SpeedTestResult | null>;
}
