import type { PrismaClient } from '@prisma/client';
import type {
  CloudDeviceIdentity,
  ICloudDeviceIdentityCatalogStore,
} from '@netscanner/discovery';

/** SQLite-backed Tuya / Smart Life identity catalog. */
export class PrismaCloudDeviceIdentityStore implements ICloudDeviceIdentityCatalogStore {
  constructor(private readonly prisma: PrismaClient) {}

  async loadAll(): Promise<CloudDeviceIdentity[]> {
    const rows = await this.prisma.cloudDeviceIdentityRecord.findMany();
    return rows.map((r) => ({
      deviceId: r.deviceId,
      name: r.name,
      productName: r.productName,
      category: r.category,
      mac: r.mac,
      ip: r.ip,
      online: r.online,
    }));
  }

  async replaceAll(rows: readonly CloudDeviceIdentity[]): Promise<void> {
    await this.prisma.$transaction(async (tx) => {
      await tx.cloudDeviceIdentityRecord.deleteMany({});
      if (rows.length === 0) return;
      await tx.cloudDeviceIdentityRecord.createMany({
        data: rows.map((r) => ({
          deviceId: r.deviceId,
          name: r.name,
          productName: r.productName,
          category: r.category,
          mac: r.mac,
          ip: r.ip,
          online: r.online,
        })),
      });
    });
  }
}
