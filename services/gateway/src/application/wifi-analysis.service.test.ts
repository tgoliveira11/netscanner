import { describe, expect, it } from 'vitest';
import {
  analyzeWifi,
  computeChannelCollisions,
  inferWifiBand,
  overlapFactor24,
} from './wifi-analysis.service.js';

describe('inferWifiBand', () => {
  it('maps common channels', () => {
    expect(inferWifiBand(6)).toBe('2.4');
    expect(inferWifiBand(36)).toBe('5');
    expect(inferWifiBand(149)).toBe('5');
  });
});

describe('overlapFactor24', () => {
  it('treats co-channel as full overlap', () => {
    expect(overlapFactor24(6, 6)).toBe(1);
    expect(overlapFactor24(1, 5)).toBe(0.35);
    expect(overlapFactor24(1, 6)).toBe(0);
  });
});

describe('computeChannelCollisions', () => {
  it('counts APs on same channel', () => {
    expect(
      computeChannelCollisions([
        { ssid: 'a', channel: 6 },
        { ssid: 'b', channel: 6 },
        { ssid: 'c', channel: 11 },
      ]),
    ).toEqual([{ channel: 6, count: 2 }]);
  });
});

describe('analyzeWifi', () => {
  it('suggests cleaner channel for own AP on congested 2.4 GHz', () => {
    const aps = [
      { ssid: 'Mine', channel: 6, source: 'router' as const, rssi: -40 },
      { ssid: 'N1', channel: 6, rssi: -55 },
      { ssid: 'N2', channel: 6, rssi: -60 },
      { ssid: 'N3', channel: 5, rssi: -65 },
      { ssid: 'N4', channel: 7, rssi: -62 },
      { ssid: 'Quiet', channel: 1, rssi: -80 },
    ];
    const analysis = analyzeWifi({
      currentSsid: null,
      aps,
      ownNetworks: [{ ssid: 'Mine', channel: 6, device: 'radio0', routerHost: '192.168.51.101', up: true }],
    });
    const rec = analysis.recommendations.find((r) => r.category === 'channel' && r.ssid === 'Mine');
    expect(rec?.suggestedChannel).toBeDefined();
    expect(rec?.suggestedChannel).not.toBe(6);
    expect(analysis.bandSummaries.some((b) => b.band === '2.4')).toBe(true);
  });

  it('flags weak clients on own SSID', () => {
    const analysis = analyzeWifi({
      currentSsid: null,
      aps: [],
      ownNetworks: [
        {
          ssid: 'Home',
          channel: 36,
          device: 'radio1',
          routerHost: 'ap.local',
          clients: [{ mac: 'aa:bb:cc:dd:ee:ff', signal: -78 }],
        },
      ],
    });
    expect(analysis.recommendations.some((r) => r.category === 'clients')).toBe(true);
  });
});
