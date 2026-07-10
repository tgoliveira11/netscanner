import type {
  DevicePolicyKind,
  DevicePolicyRow,
  IDevicePolicyRepository,
} from '../domain/device-policy-repository.js';

export class InMemoryDevicePolicyRepository implements IDevicePolicyRepository {
  private readonly rows: DevicePolicyRow[] = [];

  async list(kind?: DevicePolicyKind): Promise<DevicePolicyRow[]> {
    return this.rows.filter((r) => !kind || r.kind === kind);
  }

  async listForDevice(deviceId: string): Promise<DevicePolicyRow[]> {
    return this.rows.filter((r) => r.deviceId === deviceId);
  }

  async setValues(deviceId: string, siteId: string, kind: 'dns' | 'dest', values: string[]): Promise<void> {
    for (let i = this.rows.length - 1; i >= 0; i--) {
      if (this.rows[i]?.deviceId === deviceId && this.rows[i]?.kind === kind) this.rows.splice(i, 1);
    }
    const now = new Date().toISOString();
    for (const value of [...new Set(values)]) {
      this.rows.push({
        id: crypto.randomUUID(),
        siteId,
        deviceId,
        kind,
        value,
        updatedAt: now,
        createdAt: now,
      });
    }
  }

  async setRoute(deviceId: string, siteId: string, gatewayName: string | null): Promise<void> {
    for (let i = this.rows.length - 1; i >= 0; i--) {
      if (this.rows[i]?.deviceId === deviceId && this.rows[i]?.kind === 'route') this.rows.splice(i, 1);
    }
    if (!gatewayName) return;
    const now = new Date().toISOString();
    this.rows.push({
      id: crypto.randomUUID(),
      siteId,
      deviceId,
      kind: 'route',
      value: gatewayName,
      updatedAt: now,
      createdAt: now,
    });
  }
}

type PrismaDevicePolicy = {
  devicePolicyRecord: {
    findMany: (args: Record<string, unknown>) => Promise<
      Array<{
        id: string;
        siteId: string;
        deviceId: string;
        kind: string;
        value: string;
        updatedAt: Date;
        createdAt: Date;
      }>
    >;
    deleteMany: (args: Record<string, unknown>) => Promise<unknown>;
    createMany: (args: { data: Record<string, unknown>[] }) => Promise<unknown>;
    create: (args: { data: Record<string, unknown> }) => Promise<unknown>;
  };
};

function mapRow(r: {
  id: string;
  siteId: string;
  deviceId: string;
  kind: string;
  value: string;
  updatedAt: Date;
  createdAt: Date;
}): DevicePolicyRow {
  return {
    id: r.id,
    siteId: r.siteId,
    deviceId: r.deviceId,
    kind: r.kind as DevicePolicyKind,
    value: r.value,
    updatedAt: r.updatedAt.toISOString(),
    createdAt: r.createdAt.toISOString(),
  };
}

export class PrismaDevicePolicyRepository implements IDevicePolicyRepository {
  constructor(private readonly prisma: PrismaDevicePolicy) {}

  async list(kind?: DevicePolicyKind): Promise<DevicePolicyRow[]> {
    const rows = await this.prisma.devicePolicyRecord.findMany({
      where: kind ? { kind } : undefined,
      orderBy: { updatedAt: 'desc' },
    });
    return rows.map(mapRow);
  }

  async listForDevice(deviceId: string): Promise<DevicePolicyRow[]> {
    const rows = await this.prisma.devicePolicyRecord.findMany({
      where: { deviceId },
      orderBy: { updatedAt: 'desc' },
    });
    return rows.map(mapRow);
  }

  async setValues(deviceId: string, siteId: string, kind: 'dns' | 'dest', values: string[]): Promise<void> {
    await this.prisma.devicePolicyRecord.deleteMany({ where: { deviceId, kind } });
    const unique = [...new Set(values.map((v) => v.trim()).filter(Boolean))];
    if (!unique.length) return;
    await this.prisma.devicePolicyRecord.createMany({
      data: unique.map((value) => ({
        id: crypto.randomUUID(),
        siteId,
        deviceId,
        kind,
        value,
      })),
    });
  }

  async setRoute(deviceId: string, siteId: string, gatewayName: string | null): Promise<void> {
    await this.prisma.devicePolicyRecord.deleteMany({ where: { deviceId, kind: 'route' } });
    if (!gatewayName) return;
    await this.prisma.devicePolicyRecord.create({
      data: {
        id: crypto.randomUUID(),
        siteId,
        deviceId,
        kind: 'route',
        value: gatewayName,
      },
    });
  }
}
