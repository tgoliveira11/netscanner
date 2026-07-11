import type { ITrafficSource, TrafficSample } from '../domain/traffic-source.js';

function mergeSamples(into: Map<string, TrafficSample>, sample: TrafficSample): void {
  const prev = into.get(sample.ip);
  if (!prev) {
    into.set(sample.ip, {
      ...sample,
      topPeers: sample.topPeers ? [...sample.topPeers] : undefined,
    });
    return;
  }
  const peerMap = new Map<string, number>();
  for (const p of prev.topPeers ?? []) peerMap.set(p.ip, p.bytes);
  for (const p of sample.topPeers ?? []) {
    peerMap.set(p.ip, (peerMap.get(p.ip) ?? 0) + p.bytes);
  }
  into.set(sample.ip, {
    ip: sample.ip,
    bytesIn: Math.max(prev.bytesIn, sample.bytesIn),
    bytesOut: Math.max(prev.bytesOut, sample.bytesOut),
    connections: Math.max(prev.connections, sample.connections),
    topPeers: [...peerMap.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([ip, bytes]) => ({ ip, bytes })),
  });
}

/**
 * Prefer primary sources (e.g. pfSense REST); merge SSH states / ntopng as
 * fallback so top-talkers still populate when REST is weak or empty.
 */
export class CompositeTrafficSource implements ITrafficSource {
  readonly name: string;

  constructor(private readonly sources: readonly ITrafficSource[]) {
    this.name = `composite(${sources.map((s) => s.name).join('+')})`;
  }

  async sample(): Promise<TrafficSample[]> {
    const byIp = new Map<string, TrafficSample>();
    for (const source of this.sources) {
      try {
        const rows = await source.sample();
        for (const row of rows) mergeSamples(byIp, row);
      } catch {
        // skip unreachable adapters
      }
    }
    return [...byIp.values()];
  }
}
