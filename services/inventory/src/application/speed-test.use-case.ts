import type { SpeedTestResult } from '@netscanner/contracts';
import type { ISpeedTestRepository, SpeedTestInsert } from '../domain/speed-test-repository.js';

export class RecordSpeedTestUseCase {
  constructor(private readonly repo: ISpeedTestRepository) {}

  execute(row: SpeedTestInsert): Promise<SpeedTestResult> {
    return this.repo.insert(row);
  }
}

function avg(values: number[]): number | null {
  if (!values.length) return null;
  return Math.round((values.reduce((a, b) => a + b, 0) / values.length) * 10) / 10;
}

export class BuildSpeedTestReportUseCase {
  constructor(private readonly repo: ISpeedTestRepository) {}

  async execute(days: number, sampleLimit = 100): Promise<import('@netscanner/contracts').SpeedTestReport> {
    const since = new Date(Date.now() - days * 86_400_000);
    const samples = await this.repo.listSince(since, sampleLimit);
    const latest = samples[0] ?? (await this.repo.latest());
    const downloads = samples.map((s) => s.downloadMbps).filter((v): v is number => v != null);
    const uploads = samples.map((s) => s.uploadMbps).filter((v): v is number => v != null);
    const latencies = samples.map((s) => s.latencyMs).filter((v): v is number => v != null);

    return {
      periodDays: days,
      count: samples.length,
      latest: latest ?? null,
      avgDownloadMbps: avg(downloads),
      avgUploadMbps: avg(uploads),
      avgLatencyMs: avg(latencies),
      maxDownloadMbps: downloads.length ? Math.max(...downloads) : null,
      minDownloadMbps: downloads.length ? Math.min(...downloads) : null,
      samples: [...samples].reverse(),
    };
  }
}

export class ListSpeedTestsUseCase {
  constructor(private readonly repo: ISpeedTestRepository) {}

  execute(filter?: { limit?: number; since?: Date }): Promise<SpeedTestResult[]> {
    return this.repo.list(filter);
  }
}
