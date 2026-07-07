import {
  mergePassiveSignals,
  type IPassiveSignalStore,
  type PassiveObservation,
} from '../domain/passive-signal-store.js';

interface Row {
  ip: string;
  mac: string | null;
  hostname: string | null;
  signals: Record<string, unknown>;
}

/** Ephemeral passive-signal cache when Prisma is unavailable. */
export class InMemoryPassiveSignalStore implements IPassiveSignalStore {
  private readonly byIp = new Map<string, Row>();
  private readonly byMac = new Map<string, Record<string, unknown>>();
  private readonly handlers = new Set<(ip: string) => void>();

  async ingest(obs: PassiveObservation): Promise<void> {
    const prev = this.byIp.get(obs.ip);
    const before = JSON.stringify(prev?.signals ?? {});
    const nextSignals = mergePassiveSignals(prev?.signals ?? {}, obs.signals);
    if (JSON.stringify(nextSignals) === before && prev?.hostname === (obs.hostname ?? prev?.hostname ?? null)) {
      if (obs.mac) this.indexMac(obs.mac, obs.signals);
      return;
    }
    this.byIp.set(obs.ip, {
      ip: obs.ip,
      mac: obs.mac ?? prev?.mac ?? null,
      hostname: obs.hostname ?? prev?.hostname ?? null,
      signals: nextSignals,
    });
    if (obs.mac) this.indexMac(obs.mac, obs.signals);
    for (const h of this.handlers) h(obs.ip.startsWith('lldp:') && obs.mac ? obs.ip : obs.ip);
  }

  private indexMac(mac: string, signals: Record<string, unknown>): void {
    const key = mac.toLowerCase();
    this.byMac.set(key, mergePassiveSignals(this.byMac.get(key) ?? {}, signals));
  }

  get(ip: string): Record<string, unknown> {
    return { ...(this.byIp.get(ip)?.signals ?? {}) };
  }

  getByMac(mac: string): Record<string, unknown> {
    return { ...(this.byMac.get(mac.toLowerCase()) ?? {}) };
  }

  findIpByMac(mac: string): string | undefined {
    const needle = mac.toLowerCase();
    for (const row of this.byIp.values()) {
      if (row.mac?.toLowerCase() === needle) return row.ip;
    }
    return undefined;
  }

  list(): PassiveObservation[] {
    return [...this.byIp.values()].map((r) => ({
      ip: r.ip,
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
