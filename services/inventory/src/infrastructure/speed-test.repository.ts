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
  };
}

export class PrismaSpeedTestRepository implements ISpeedTestRepository {
  constructor(private readonly prisma: { speedTestRecord: {
    create: (args: { data: Record<string, unknown> }) => Promise<SpeedTestRow>;
    findMany: (args: Record<string, unknown>) => Promise<SpeedTestRow[]>;
    findFirst: (args: Record<string, unknown>) => Promise<SpeedTestRow | null>;
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
      },
    });
    return mapSpeedTestRow(created);
  }

  async list(filter: SpeedTestListFilter = {}): Promise<SpeedTestResult[]> {
    const limit = filter.limit ?? 200;
    const rows = await this.prisma.speedTestRecord.findMany({
      where: filter.since ? { measuredAt: { gte: filter.since } } : undefined,
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
}

export class InMemorySpeedTestRepository implements ISpeedTestRepository {
  private readonly rows: SpeedTestResult[] = [];

  async insert(row: SpeedTestInsert): Promise<SpeedTestResult> {
    const result: SpeedTestResult = {
      id: crypto.randomUUID(),
      measuredAt: new Date().toISOString(),
      ...row,
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
    const limit = filter.limit ?? 200;
    return out.slice(0, limit);
  }

  async listSince(since: Date, limit = 500): Promise<SpeedTestResult[]> {
    return this.list({ since, limit });
  }

  async latest(): Promise<SpeedTestResult | null> {
    return this.rows[0] ?? null;
  }
}
