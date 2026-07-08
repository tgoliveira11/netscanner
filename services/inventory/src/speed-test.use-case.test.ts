import { describe, expect, it } from 'vitest';
import { InMemorySpeedTestRepository } from './infrastructure/speed-test.repository.js';
import { BuildSpeedTestReportUseCase, RecordSpeedTestUseCase } from './application/speed-test.use-case.js';

describe('speed test report', () => {
  it('computes averages over the period', async () => {
    const repo = new InMemorySpeedTestRepository();
    const record = new RecordSpeedTestUseCase(repo);
    await record.execute({
      downloadMbps: 100,
      uploadMbps: 50,
      latencyMs: 10,
      downloadBytes: 1_000_000,
      uploadBytes: 500_000,
      server: 'cloudflare',
      trigger: 'background',
      error: null,
    });
    await record.execute({
      downloadMbps: 200,
      uploadMbps: 70,
      latencyMs: 12,
      downloadBytes: 1_000_000,
      uploadBytes: 500_000,
      server: 'cloudflare',
      trigger: 'manual',
      error: null,
    });
    const report = await new BuildSpeedTestReportUseCase(repo).execute(30, 50);
    expect(report.count).toBe(2);
    expect(report.avgDownloadMbps).toBe(150);
    expect(report.avgUploadMbps).toBe(60);
    expect(report.maxDownloadMbps).toBe(200);
    expect(report.minDownloadMbps).toBe(100);
  });
});
