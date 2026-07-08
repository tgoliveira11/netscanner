import type { Traffic } from '@netscanner/contracts';
import type { ITrafficSource, TrafficSample } from '../domain/traffic-source.js';
import { RateCalculator } from '../domain/traffic-source.js';

/** Latest per-IP traffic counters + derived rate from successive pf samples. */
export class TrafficMonitor {
  private readonly rates = new RateCalculator();
  private readonly samples = new Map<string, TrafficSample & { rateBps: number }>();

  ingest(samples: readonly TrafficSample[], now = Date.now()): void {
    for (const s of samples) {
      const cumulative = s.bytesIn + s.bytesOut;
      const rateBps = this.rates.update(s.ip, cumulative, now);
      this.samples.set(s.ip, { ...s, rateBps });
    }
  }

  async refresh(source: ITrafficSource): Promise<number> {
    const samples = await source.sample();
    this.ingest(samples);
    return samples.length;
  }

  get(ip: string): Traffic | null {
    const s = this.samples.get(ip);
    if (!s) return null;
    return {
      bytesIn: s.bytesIn,
      bytesOut: s.bytesOut,
      rateBps: s.rateBps,
      connections: s.connections,
      topPeers: s.topPeers,
    };
  }

  size(): number {
    return this.samples.size;
  }
}
