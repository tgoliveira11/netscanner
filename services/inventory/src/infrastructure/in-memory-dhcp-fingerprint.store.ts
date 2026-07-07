import type { IDhcpFingerprintStore, StoredDhcpFingerprint } from '../domain/dhcp-fingerprint-store.js';

/** Ephemeral DHCP fingerprint store (used when Prisma is unavailable). */
export class InMemoryDhcpFingerprintStore implements IDhcpFingerprintStore {
  private readonly map = new Map<string, StoredDhcpFingerprint>();

  async save(fp: StoredDhcpFingerprint): Promise<void> {
    this.map.set(fp.mac.toLowerCase(), fp);
  }

  async loadAll(): Promise<StoredDhcpFingerprint[]> {
    return [...this.map.values()];
  }
}
