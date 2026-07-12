import type {
  CloudDeviceIdentity,
  ICloudDeviceIdentityCatalogStore,
} from '@netscanner/discovery';

/** Ephemeral catalog store (used when Prisma is unavailable). */
export class InMemoryCloudDeviceIdentityStore implements ICloudDeviceIdentityCatalogStore {
  private rows: CloudDeviceIdentity[] = [];

  async loadAll(): Promise<CloudDeviceIdentity[]> {
    return this.rows.map((r) => ({ ...r }));
  }

  async replaceAll(rows: readonly CloudDeviceIdentity[]): Promise<void> {
    this.rows = rows.map((r) => ({ ...r }));
  }
}
