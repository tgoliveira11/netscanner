import type { SpeedTestResult } from '@netscanner/contracts';
import type { SpeedTestInsert, SpeedTestListFilter, ISpeedTestRepository } from '../domain/speed-test-repository.js';

export type SpeedTestRow = {
  id: string;
  measuredAt: Date;
  downloadMbps: number | null;
  uploadMbps: number | null;
  latencyMs: number | null;
  downloadBytes: number | null;
  uploadBytes: number | null;
  server: string;
  trigger: string;
  error: string | null;
  testKind?: string;
  wanGateway?: string | null;
  wanInterface?: string | null;
  egressGateway?: string | null;
  egressRoute?: string | null;
};

export function mapSpeedTestRow(row: SpeedTestRow): SpeedTestResult {
  return {
    id: row.id,
    measuredAt: row.measuredAt.toISOString(),
    downloadMbps: row.downloadMbps,
    uploadMbps: row.uploadMbps,
    latencyMs: row.latencyMs,
    downloadBytes: row.downloadBytes,
    uploadBytes: row.uploadBytes,
    server: row.server,
    trigger: row.trigger as SpeedTestResult['trigger'],
    error: row.error,
    testKind: (row.testKind as SpeedTestResult['testKind']) ?? 'agent',
    wanGateway: row.wanGateway ?? null,
    wanInterface: row.wanInterface ?? null,
    egressGateway: row.egressGateway ?? null,
    egressRoute: (row.egressRoute as SpeedTestResult['egressRoute']) ?? null,
  };
}

export class PrismaSpeedTestRepository implements ISpeedTestRepository {
  constructor(private readonly prisma: { speedTestRecord: {
    create: (args: { data: Record<string, unknown> }) => Promise<SpeedTestRow>;
    findMany: (args: Record<string, unknown>) => Promise<SpeedTestRow[]>;
    findFirst: (args: Record<string, unknown>) => Promise<SpeedTestRow | null>;
    deleteMany: (args: Record<string, unknown>) => Promise<{ count: number }>;
  } }) {}

  async insert(row: SpeedTestInsert): Promise<SpeedTestResult> {
    const id = crypto.randomUUID();
    const created = await this.prisma.speedTestRecord.create({
      data: {
        id,
        measuredAt: new Date(),
        downloadMbps: row.downloadMbps,
        uploadMbps: row.uploadMbps,
        latencyMs: row.latencyMs,
        downloadBytes: row.downloadBytes,
        uploadBytes: row.uploadBytes,
        server: row.server,
        trigger: row.trigger,
        error: row.error,
        testKind: row.testKind ?? 'agent',
        wanGateway: row.wanGateway ?? null,
        wanInterface: row.wanInterface ?? null,
        egressGateway: row.egressGateway ?? null,
        egressRoute: row.egressRoute ?? null,
      },
    });
    return mapSpeedTestRow(created);
  }

  async list(filter: SpeedTestListFilter = {}): Promise<SpeedTestResult[]> {
    const limit = filter.limit ?? 200;
    const where: Record<string, unknown> = {};
    if (filter.since) where.measuredAt = { gte: filter.since };
    if (filter.testKind) where.testKind = filter.testKind;
    if (filter.wanGateway) where.wanGateway = filter.wanGateway;
    const rows = await this.prisma.speedTestRecord.findMany({
      where: Object.keys(where).length ? where : undefined,
      orderBy: { measuredAt: 'desc' },
      take: limit,
    });
    return rows.map(mapSpeedTestRow);
  }

  async listSince(since: Date, limit = 500): Promise<SpeedTestResult[]> {
    return this.list({ since, limit });
  }

  async latest(): Promise<SpeedTestResult | null> {
    const row = await this.prisma.speedTestRecord.findFirst({
      orderBy: { measuredAt: 'desc' },
    });
    return row ? mapSpeedTestRow(row) : null;
  }

  async deleteOlderThan(before: Date): Promise<number> {
    const result = await this.prisma.speedTestRecord.deleteMany({
      where: { measuredAt: { lt: before } },
    });
    return result.count;
  }
}

export class InMemorySpeedTestRepository implements ISpeedTestRepository {
  private readonly rows: SpeedTestResult[] = [];

  async insert(row: SpeedTestInsert): Promise<SpeedTestResult> {
    const result: SpeedTestResult = {
      id: crypto.randomUUID(),
      measuredAt: new Date().toISOString(),
      downloadMbps: row.downloadMbps,
      uploadMbps: row.uploadMbps,
      latencyMs: row.latencyMs,
      downloadBytes: row.downloadBytes,
      uploadBytes: row.uploadBytes,
      server: row.server,
      trigger: row.trigger,
      error: row.error,
      testKind: row.testKind ?? 'agent',
      wanGateway: row.wanGateway ?? null,
      wanInterface: row.wanInterface ?? null,
      egressGateway: row.egressGateway ?? null,
      egressRoute: (row.egressRoute as SpeedTestResult['egressRoute']) ?? null,
    };
    this.rows.unshift(result);
    if (this.rows.length > 2000) this.rows.length = 2000;
    return result;
  }

  async list(filter: SpeedTestListFilter = {}): Promise<SpeedTestResult[]> {
    let out = [...this.rows];
    if (filter.since) {
      const t = filter.since.getTime();
      out = out.filter((r) => Date.parse(r.measuredAt) >= t);
    }
    if (filter.testKind) out = out.filter((r) => (r.testKind ?? 'agent') === filter.testKind);
    if (filter.wanGateway) out = out.filter((r) => r.wanGateway === filter.wanGateway);
    const limit = filter.limit ?? 200;
    return out.slice(0, limit);
  }

  async listSince(since: Date, limit = 500): Promise<SpeedTestResult[]> {
    return this.list({ since, limit });
  }

  async latest(): Promise<SpeedTestResult | null> {
    return this.rows[0] ?? null;
  }

  async deleteOlderThan(before: Date): Promise<number> {
    const t = before.getTime();
    const beforeLen = this.rows.length;
    const kept = this.rows.filter((r) => Date.parse(r.measuredAt) >= t);
    this.rows.length = 0;
    this.rows.push(...kept);
    return beforeLen - kept.length;
  }
}
