import { describe, it, expect } from 'vitest';
import { CompositeTrafficSource } from './infrastructure/composite-traffic-source.js';
import type { ITrafficSource, TrafficSample } from './domain/traffic-source.js';

class StubSource implements ITrafficSource {
  constructor(
    readonly name: string,
    private readonly rows: TrafficSample[],
  ) {}
  async sample(): Promise<TrafficSample[]> {
    return this.rows;
  }
}

describe('CompositeTrafficSource', () => {
  it('merges samples by IP preferring max counters', async () => {
    const composite = new CompositeTrafficSource([
      new StubSource('rest', [
        { ip: '10.0.0.1', bytesIn: 100, bytesOut: 50, connections: 2, topPeers: [{ ip: '1.1.1.1', bytes: 10 }] },
      ]),
      new StubSource('ssh', [
        { ip: '10.0.0.1', bytesIn: 200, bytesOut: 40, connections: 5, topPeers: [{ ip: '8.8.8.8', bytes: 20 }] },
        { ip: '10.0.0.2', bytesIn: 1, bytesOut: 1, connections: 1 },
      ]),
    ]);
    const rows = await composite.sample();
    expect(rows).toHaveLength(2);
    const a = rows.find((r) => r.ip === '10.0.0.1')!;
    expect(a.bytesIn).toBe(200);
    expect(a.connections).toBe(5);
    expect(a.topPeers?.map((p) => p.ip).sort()).toEqual(['1.1.1.1', '8.8.8.8']);
  });
});
