import type { CpeAccessSessionRow, ICpeAccessSessionStore } from '../domain/cpe-access-session-store.js';

type PrismaCpe = {
  cpeAccessSessionRecord: {
    findMany: (args?: Record<string, unknown>) => Promise<CpeAccessSessionRow[]>;
    upsert: (args: {
      where: { id: string };
      create: Record<string, unknown>;
      update: Record<string, unknown>;
    }) => Promise<unknown>;
    update: (args: { where: { id: string }; data: Record<string, unknown> }) => Promise<unknown>;
    delete: (args: { where: { id: string } }) => Promise<unknown>;
  };
};

export class PrismaCpeAccessSessionStore implements ICpeAccessSessionStore {
  constructor(private readonly prisma: PrismaCpe) {}

  async list(): Promise<CpeAccessSessionRow[]> {
    const rows = await this.prisma.cpeAccessSessionRecord.findMany({
      orderBy: { createdAt: 'desc' },
    });
    return rows.map(normalizeRow);
  }

  async upsert(row: CpeAccessSessionRow): Promise<void> {
    const data = {
      id: row.id,
      ip: row.ip,
      port: row.port,
      tls: row.tls,
      label: row.label,
      username: row.username,
      passwordEnc: row.passwordEnc,
      via: row.via,
      autoLoginPending: row.autoLoginPending,
      createdAt: row.createdAt,
    };
    await this.prisma.cpeAccessSessionRecord.upsert({
      where: { id: row.id },
      create: data,
      update: {
        ip: data.ip,
        port: data.port,
        tls: data.tls,
        label: data.label,
        username: data.username,
        passwordEnc: data.passwordEnc,
        via: data.via,
        autoLoginPending: data.autoLoginPending,
      },
    });
  }

  async updateAutoLogin(id: string, autoLoginPending: boolean): Promise<void> {
    await this.prisma.cpeAccessSessionRecord.update({
      where: { id },
      data: { autoLoginPending },
    });
  }

  async delete(id: string): Promise<void> {
    try {
      await this.prisma.cpeAccessSessionRecord.delete({ where: { id } });
    } catch {
      /* already gone */
    }
  }
}

export class InMemoryCpeAccessSessionStore implements ICpeAccessSessionStore {
  private readonly rows = new Map<string, CpeAccessSessionRow>();

  async list(): Promise<CpeAccessSessionRow[]> {
    return [...this.rows.values()].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
  }

  async upsert(row: CpeAccessSessionRow): Promise<void> {
    this.rows.set(row.id, { ...row });
  }

  async updateAutoLogin(id: string, autoLoginPending: boolean): Promise<void> {
    const row = this.rows.get(id);
    if (row) this.rows.set(id, { ...row, autoLoginPending });
  }

  async delete(id: string): Promise<void> {
    this.rows.delete(id);
  }
}

function normalizeRow(row: CpeAccessSessionRow): CpeAccessSessionRow {
  return {
    id: row.id,
    ip: row.ip,
    port: row.port,
    tls: Boolean(row.tls),
    label: row.label ?? null,
    username: row.username,
    passwordEnc: row.passwordEnc,
    via: row.via === 'pfsense-tunnel' ? 'pfsense-tunnel' : 'direct',
    autoLoginPending: Boolean(row.autoLoginPending),
    createdAt: row.createdAt instanceof Date ? row.createdAt : new Date(row.createdAt),
  };
}
