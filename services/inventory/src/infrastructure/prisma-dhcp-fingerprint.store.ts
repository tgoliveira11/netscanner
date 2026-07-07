import type { PrismaClient } from '@prisma/client';
import type { IDhcpFingerprintStore, StoredDhcpFingerprint } from '../domain/dhcp-fingerprint-store.js';

export class PrismaDhcpFingerprintStore implements IDhcpFingerprintStore {
  constructor(private readonly prisma: PrismaClient) {}

  async save(fp: StoredDhcpFingerprint): Promise<void> {
    await this.prisma.dhcpFingerprintRecord.upsert({
      where: { mac: fp.mac.toLowerCase() },
      create: {
        mac: fp.mac.toLowerCase(),
        fingerprint: fp.fingerprint,
        vendorClass: fp.vendorClass,
        hostname: fp.hostname,
        capturedAt: new Date(fp.capturedAt),
      },
      update: {
        fingerprint: fp.fingerprint,
        vendorClass: fp.vendorClass,
        hostname: fp.hostname,
        capturedAt: new Date(fp.capturedAt),
      },
    });
  }

  async loadAll(): Promise<StoredDhcpFingerprint[]> {
    const rows = await this.prisma.dhcpFingerprintRecord.findMany();
    return rows.map((r: { mac: string; fingerprint: string; vendorClass: string | null; hostname: string | null; capturedAt: Date }) => ({
      mac: r.mac,
      fingerprint: r.fingerprint,
      vendorClass: r.vendorClass,
      hostname: r.hostname,
      capturedAt: r.capturedAt.toISOString(),
    }));
  }
}
