import type { Device } from '@netscanner/contracts';
import { LEGACY_DEFAULT_SITE_ID } from '@netscanner/contracts';
import type { DeviceFilter, IDeviceRepository, RouterScrapeCredential } from '../domain/device-repository.js';
import type { StoredDevice } from '../domain/device-public.js';
import { toPublicDevice } from '../domain/device-public.js';
import { isEncryptedSecret, SecretCipher } from './secret-cipher.js';

/**
 * Encrypts router scrape passwords before persistence and decrypts on read.
 * Plaintext rows are transparently migrated on the next save.
 */
export class SecretProtectingDeviceRepository implements IDeviceRepository {
  constructor(
    private readonly inner: IDeviceRepository,
    private readonly cipher: SecretCipher,
  ) {}

  findByMac(siteId: string, mac: string): Promise<Device | null> {
    return this.inner.findByMac(siteId, mac);
  }

  findByIp(siteId: string, ip: string): Promise<Device | null> {
    return this.inner.findByIp(siteId, ip);
  }

  findById(id: string): Promise<Device | null> {
    return this.inner.findById(id);
  }

  async findStoredById(id: string): Promise<StoredDevice | null> {
    const stored = await this.inner.findStoredById(id);
    return stored ? this.decryptStored(stored) : null;
  }

  async save(device: Device | StoredDevice, siteId: string): Promise<void> {
    const stored = device as StoredDevice;
    const next: StoredDevice = {
      ...(stored as StoredDevice),
      siteId: stored.siteId ?? siteId,
      routerScrapePassword: this.encryptField(stored.routerScrapePassword),
    };
    await this.inner.save(next, siteId);
  }

  list(filter?: DeviceFilter): Promise<Device[]> {
    return this.inner.list(filter);
  }

  async listRouterScrapeCredentials(siteId: string): Promise<RouterScrapeCredential[]> {
    const rows = await this.inner.listRouterScrapeCredentials(siteId);
    return rows.map((row) => ({
      ...row,
      routerScrapePassword: this.decryptField(row.routerScrapePassword),
    }));
  }

  markOfflineExcept(onlineIds: string[], siteId: string): Promise<string[]> {
    return this.inner.markOfflineExcept(onlineIds, siteId);
  }

  updatePresence(
    id: string,
    patch: { isOnline: boolean; latencyMs?: number | null },
  ): Promise<Device | null> {
    return this.inner.updatePresence(id, patch);
  }

  /** Re-encrypt any legacy plaintext passwords still in the DB. */
  async migratePlaintextSecrets(): Promise<number> {
    const devices = await this.inner.list();
    let migrated = 0;
    for (const device of devices) {
      const stored = await this.inner.findStoredById(device.id);
      if (!stored?.routerScrapePassword) continue;
      if (isEncryptedSecret(stored.routerScrapePassword)) continue;
      await this.save(stored, stored.siteId ?? LEGACY_DEFAULT_SITE_ID);
      migrated += 1;
    }
    return migrated;
  }

  private encryptField(value: string | null | undefined): string | null | undefined {
    if (!value) return value ?? null;
    if (isEncryptedSecret(value)) return value;
    return this.cipher.encrypt(value);
  }

  private decryptField(value: string): string {
    if (!isEncryptedSecret(value)) return value;
    return this.cipher.decrypt(value);
  }

  private decryptStored(stored: StoredDevice): StoredDevice {
    if (!stored.routerScrapePassword) return stored;
    return {
      ...stored,
      routerScrapePassword: this.decryptField(stored.routerScrapePassword),
    };
  }
}

export function wrapWithSecretProtection(
  repo: IDeviceRepository,
  cipher: SecretCipher | null,
): IDeviceRepository {
  return cipher ? new SecretProtectingDeviceRepository(repo, cipher) : repo;
}
