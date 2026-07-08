import { describe, it, expect } from 'vitest';
import { RateCalculator } from './domain/traffic-source.js';
import { parsePfStates } from './infrastructure/pf-states-traffic.parser.js';
import {
  ipFromPfEndpoint,
  parseRestFirewallStates,
} from './infrastructure/pf-rest-states.parser.js';

describe('RateCalculator', () => {
  it('derives bits/s from successive cumulative byte counters', () => {
    const rc = new RateCalculator();
    expect(rc.update('192.168.1.5', 1000, 0)).toBe(0); // first sample → no rate
    expect(rc.update('192.168.1.5', 2000, 1000)).toBe(8000); // +1000 bytes / 1s = 8000 bps
  });

  it('returns 0 on a counter reset', () => {
    const rc = new RateCalculator();
    rc.update('ip', 5000, 0);
    expect(rc.update('ip', 100, 1000)).toBe(0);
  });
});

describe('TrafficMonitor', () => {
  it('stores samples and derives rate', async () => {
    const { TrafficMonitor } = await import('./infrastructure/traffic-monitor.js');
    const mon = new TrafficMonitor();
    mon.ingest([{ ip: '192.168.1.5', bytesIn: 100, bytesOut: 200, connections: 1 }], 0);
    mon.ingest([{ ip: '192.168.1.5', bytesIn: 200, bytesOut: 400, connections: 2 }], 1000);
    const t = mon.get('192.168.1.5');
    expect(t?.bytesIn).toBe(200);
    expect(t?.rateBps).toBeGreaterThan(0);
  });
});

describe('parsePfStates', () => {
  it('aggregates bytes per private LAN IP from pfctl -vvs state output', () => {
    const out = [
      'all tcp 10.0.51.100:52344 -> 1.2.3.4:443       ESTABLISHED:ESTABLISHED',
      '   age 00:01:23, expires in 00:10:00, 10:20 pkts, 1000:5000 bytes, rule 5',
      'all udp 8.8.8.8:53 -> 10.0.51.100:41000       SINGLE:NO_TRAFFIC',
      '   age 00:00:02, expires in 00:00:30, 1:1 pkts, 60:120 bytes, rule 1',
    ].join('\n');
    const samples = parsePfStates(out);
    const dev = samples.find((s) => s.ip === '10.0.51.100');
    expect(dev).toBeDefined();
    expect(dev!.bytesOut).toBe(1000 + 120);
    expect(dev!.bytesIn).toBe(5000 + 60);
    expect(dev!.connections).toBe(2);
    expect(dev!.topPeers!.some((p) => p.ip === '1.2.3.4')).toBe(true);
    expect(dev!.topPeers!.some((p) => p.ip === '8.8.8.8')).toBe(true);
    expect(samples.some((s) => s.ip === '1.2.3.4' || s.ip === '8.8.8.8')).toBe(false);
  });

  it('handles pfSense <- direction and NAT parentheses', () => {
    const out = [
      'igb0.20 tcp 172.217.7.14:443 <- 10.1.20.60:57309       ESTABLISHED:ESTABLISHED',
      '   age 17:04:30, 239:237 pkts, 109178:80245 bytes, rule 122',
      'em0 tcp 10.0.52.105:443 (10.0.51.1:12345) -> 8.8.8.8:443       ESTABLISHED:ESTABLISHED',
      '   age 00:00:10, 5:5 pkts, 100:200 bytes, rule 1',
    ].join('\n');
    const samples = parsePfStates(out);
    const lan = samples.find((s) => s.ip === '10.1.20.60');
    const nat = samples.find((s) => s.ip === '10.0.52.105');
    expect(lan?.topPeers?.[0]?.ip).toBe('172.217.7.14');
    expect(nat?.topPeers?.[0]?.ip).toBe('8.8.8.8');
  });

  it('uses remote endpoint as peer, not NAT gateway in parentheses', () => {
    const out = [
      'em0 tcp 10.0.40.2:52444 (10.0.51.1:12345) -> 142.250.185.78:443       ESTABLISHED:ESTABLISHED',
      '   age 00:01:00, 10:10 pkts, 5000:3000 bytes, rule 1',
    ].join('\n');
    const samples = parsePfStates(out);
    const dev = samples.find((s) => s.ip === '10.0.40.2');
    expect(dev?.topPeers?.[0]?.ip).toBe('142.250.185.78');
    expect(dev?.topPeers?.some((p) => p.ip === '10.0.51.1')).toBe(false);
  });
});

describe('parseRestFirewallStates', () => {
  it('parses endpoint IPs and aggregates LAN → WAN peers', () => {
    expect(ipFromPfEndpoint('10.0.51.100:52344')).toBe('10.0.51.100');
    const samples = parseRestFirewallStates([
      {
        source: '10.0.51.100:52344',
        destination: '1.2.3.4:443',
        direction: 'out',
        bytes_in: 5000,
        bytes_out: 1000,
        bytes_total: 6000,
      },
      {
        source: '8.8.8.8:53',
        destination: '10.0.51.100:41000',
        direction: 'in',
        bytes_in: 2565,
        bytes_out: 1217,
        bytes_total: 3782,
      },
    ]);
    const dev = samples.find((s) => s.ip === '10.0.51.100');
    expect(dev).toBeDefined();
    expect(dev!.bytesOut).toBe(1000 + 1217);
    expect(dev!.bytesIn).toBe(5000 + 2565);
    expect(dev!.connections).toBe(2);
    expect(dev!.topPeers!.some((p) => p.ip === '1.2.3.4')).toBe(true);
    expect(dev!.topPeers!.some((p) => p.ip === '8.8.8.8')).toBe(true);
    expect(samples.some((s) => s.ip === '1.2.3.4')).toBe(false);
  });
});
