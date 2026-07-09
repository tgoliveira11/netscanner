import { v4 as uuid } from 'uuid';
import type { PolicyAuditEntry } from '@netscanner/contracts';

export interface IPolicyAuditRepository {
  append(entry: Omit<PolicyAuditEntry, 'id' | 'createdAt'>): Promise<PolicyAuditEntry>;
  list(limit?: number): Promise<PolicyAuditEntry[]>;
  markUndone(id: string): Promise<void>;
}

export class InMemoryPolicyAuditRepository implements IPolicyAuditRepository {
  private readonly rows: PolicyAuditEntry[] = [];

  async append(entry: Omit<PolicyAuditEntry, 'id' | 'createdAt'>): Promise<PolicyAuditEntry> {
    const row: PolicyAuditEntry = {
      ...entry,
      id: uuid(),
      createdAt: new Date().toISOString(),
    };
    this.rows.unshift(row);
    return row;
  }

  async list(limit = 100): Promise<PolicyAuditEntry[]> {
    return this.rows.slice(0, limit);
  }

  async markUndone(id: string): Promise<void> {
    const row = this.rows.find((r) => r.id === id);
    if (row) row.undone = true;
  }
}

export class PrismaPolicyAuditRepository implements IPolicyAuditRepository {
  constructor(private readonly prisma: { policyAuditRecord: {
    create: (args: { data: Record<string, unknown> }) => Promise<{ id: string; action: string; target: string; detailJson: string; actor: string; createdAt: Date; undone: boolean }>;
    findMany: (args: Record<string, unknown>) => Promise<Array<{ id: string; action: string; target: string; detailJson: string; actor: string; createdAt: Date; undone: boolean }>>;
    update: (args: Record<string, unknown>) => Promise<unknown>;
  } }) {}

  async append(entry: Omit<PolicyAuditEntry, 'id' | 'createdAt'>): Promise<PolicyAuditEntry> {
    const id = uuid();
    const row = await this.prisma.policyAuditRecord.create({
      data: {
        id,
        action: entry.action,
        target: entry.target,
        detailJson: JSON.stringify(entry.detail),
        actor: entry.actor,
        undone: entry.undone,
      },
    });
    return toEntry(row);
  }

  async list(limit = 100): Promise<PolicyAuditEntry[]> {
    const rows = await this.prisma.policyAuditRecord.findMany({
      orderBy: { createdAt: 'desc' },
      take: limit,
    });
    return rows.map(toEntry);
  }

  async markUndone(id: string): Promise<void> {
    await this.prisma.policyAuditRecord.update({ where: { id }, data: { undone: true } });
  }
}

function toEntry(row: {
  id: string;
  action: string;
  target: string;
  detailJson: string;
  actor: string;
  createdAt: Date;
  undone: boolean;
}): PolicyAuditEntry {
  return {
    id: row.id,
    action: row.action,
    target: row.target,
    detail: JSON.parse(row.detailJson || '{}') as Record<string, unknown>,
    actor: row.actor,
    createdAt: row.createdAt.toISOString(),
    undone: row.undone,
  };
}
