import type { PrismaClient } from '@prisma/client';
import { LEGACY_DEFAULT_SITE_ID } from '@netscanner/contracts';
import {
  mergePassiveSignals,
  type IPassiveSignalStore,
  type PassiveObservation,
} from '@netscanner/discovery';

/** SQLite-backed passive signal cache (survives agent restarts). */
export class PrismaPassiveSignalStore implements IPassiveSignalStore {
  private readonly mem = new Map<string, { mac: string | null; hostname: string | null; signals: Record<string, unknown> }>();
  private readonly byMac = new Map<string, Record<string, unknown>>();
  private readonly handlers = new Set<(ip: string) => void>();

  constructor(
    private readonly prisma: PrismaClient,
    private readonly siteId: string = LEGACY_DEFAULT_SITE_ID,
  ) {}

  async hydrate(): Promise<void> {
    const rows = await this.prisma.passiveSignalRecord.findMany();
    for (const r of rows) {
      this.mem.set(r.ip, {
        mac: r.mac,
        hostname: r.hostname,
        signals: JSON.parse(r.signalsJson) as Record<string, unknown>,
      });
      if (r.mac) this.byMac.set(r.mac.toLowerCase(), JSON.parse(r.signalsJson) as Record<string, unknown>);
    }
  }

  async ingest(obs: PassiveObservation): Promise<void> {
    const prev = this.mem.get(obs.ip);
    const before = JSON.stringify(prev?.signals ?? {});
    const nextSignals = mergePassiveSignals(prev?.signals ?? {}, obs.signals);
    const hostname = obs.hostname ?? prev?.hostname ?? null;
    const mac = obs.mac ?? prev?.mac ?? null;
    if (JSON.stringify(nextSignals) === before && prev?.hostname === hostname) return;

    this.mem.set(obs.ip, { mac, hostname, signals: nextSignals });
    if (mac) this.byMac.set(mac.toLowerCase(), mergePassiveSignals(this.byMac.get(mac.toLowerCase()) ?? {}, nextSignals));
    await this.prisma.passiveSignalRecord.upsert({
      where: { siteId_ip: { siteId: this.siteId, ip: obs.ip } },
      create: {
        siteId: this.siteId,
        ip: obs.ip,
        mac,
        hostname,
        signalsJson: JSON.stringify(nextSignals),
      },
      update: { mac, hostname, signalsJson: JSON.stringify(nextSignals) },
    });
    for (const h of this.handlers) h(obs.ip);
  }

  get(ip: string): Record<string, unknown> {
    return { ...(this.mem.get(ip)?.signals ?? {}) };
  }

  getByMac(mac: string): Record<string, unknown> {
    return { ...(this.byMac.get(mac.toLowerCase()) ?? {}) };
  }

  findIpByMac(mac: string): string | undefined {
    const needle = mac.toLowerCase();
    for (const [ip, row] of this.mem) {
      if (row.mac?.toLowerCase() === needle) return ip;
    }
    return undefined;
  }

  list(): PassiveObservation[] {
    return [...this.mem.entries()].map(([ip, r]) => ({
      ip,
      mac: r.mac,
      hostname: r.hostname,
      source: 'cache',
      signals: r.signals,
    }));
  }

  onUpdated(handler: (ip: string) => void): () => void {
    this.handlers.add(handler);
    return () => this.handlers.delete(handler);
  }
}
