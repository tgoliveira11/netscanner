import type { PrismaClient } from '@prisma/client';
import { LEGACY_DEFAULT_SITE_ID } from '@netscanner/contracts';
import type { IDhcpFingerprintStore, StoredDhcpFingerprint } from '../domain/dhcp-fingerprint-store.js';

export class PrismaDhcpFingerprintStore implements IDhcpFingerprintStore {
  constructor(
    private readonly prisma: PrismaClient,
    private readonly siteId: string = LEGACY_DEFAULT_SITE_ID,
  ) {}

  async save(fp: StoredDhcpFingerprint): Promise<void> {
    const mac = fp.mac.toLowerCase();
    await this.prisma.dhcpFingerprintRecord.upsert({
      where: { siteId_mac: { siteId: this.siteId, mac } },
      create: {
        siteId: this.siteId,
        mac,
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
