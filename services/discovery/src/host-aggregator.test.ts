import { describe, it, expect } from 'vitest';
import { HostAggregator } from './domain/host-aggregator.js';

describe('HostAggregator', () => {
  it('merges signals from multiple probes into one host per IP', () => {
    const agg = new HostAggregator();
    agg.ingest({ ip: '192.168.1.5', source: 'ping', latencyMs: 4 });
    agg.ingest({ ip: '192.168.1.5', source: 'arp', mac: 'aa:bb:cc:dd:ee:ff' });
    agg.ingest({ ip: '192.168.1.5', source: 'mdns', hostname: 'printer', extra: { mdnsType: 'ipp' } });

    const [host] = agg.all();
    expect(host?.mac).toBe('aa:bb:cc:dd:ee:ff');
    expect(host?.hostname).toBe('printer');
    expect(host?.latencyMs).toBe(4);
    expect(host?.sources).toEqual(['ping', 'arp', 'mdns']);
    expect(host?.signals.mdnsType).toBe('ipp');
  });

  it('does not overwrite existing data with empty signals and reports no-op merges', () => {
    const agg = new HostAggregator();
    agg.ingest({ ip: '192.168.1.6', source: 'arp', mac: 'aa:bb:cc:dd:ee:ff' });
    const changed = agg.ingest({ ip: '192.168.1.6', source: 'arp', mac: 'aa:bb:cc:dd:ee:ff' });
    expect(changed).toBeNull(); // identical signal → no change emitted
    expect(agg.all()[0]?.mac).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('ignores signals without an IP', () => {
    const agg = new HostAggregator();
    expect(agg.ingest({ source: 'ssdp', mac: 'aa:bb:cc:dd:ee:ff' })).toBeNull();
    expect(agg.all()).toHaveLength(0);
  });
});
