import { describe, expect, it } from 'vitest';
import type { Device } from '@netscanner/contracts';
import { buildDeviceRelations } from './build-relations.use-case.js';

const device = (over: Partial<Device> & { id: string; ip: string }): Device =>
  ({
    mac: null,
    hostname: null,
    vendor: null,
    brand: null,
    model: null,
    deviceType: 'unknown',
    classificationConfidence: 0.5,
    os: null,
    connectionType: 'unknown',
    services: [],
    latencyMs: null,
    isOnline: true,
    securityFlags: [],
    label: null,
    notes: null,
    firstSeen: '2026-01-01',
    lastSeen: '2026-01-01',
    signals: {},
    ...over,
  }) as Device;

describe('buildDeviceRelations', () => {
  it('builds LAN and WAN traffic edges from topPeers', () => {
    const phone = device({
      id: 'phone',
      ip: '10.0.51.100',
      hostname: 'iphone',
      signals: {
        traffic: {
          bytesIn: 1,
          bytesOut: 2,
          rateBps: 0,
          connections: 2,
          topPeers: [
            { ip: '10.0.51.1', bytes: 5000 },
            { ip: '8.8.8.8', bytes: 9000 },
          ],
        },
      },
    });
    const gw = device({ id: 'gw', ip: '10.0.51.1', deviceType: 'firewall' });
    const { edges } = buildDeviceRelations([phone, gw]);
    expect(edges.some((e) => e.kind === 'traffic' && e.to === 'gw')).toBe(true);
    expect(edges.some((e) => e.kind === 'traffic-external' && e.to === '8.8.8.8')).toBe(true);
  });

  it('merges passive DNS queries per device IP', () => {
    const iot = device({ id: 'iot', ip: '10.0.60.50', hostname: 'plug' });
    const { edges } = buildDeviceRelations([iot], {
      passiveDnsByIp: (ip) =>
        ip === '10.0.60.50' ? ['device.tuyaus.com', 'device.tuyaus.com'] : [],
    });
    expect(edges.some((e) => e.kind === 'dns' && e.to === 'tuyaus.com')).toBe(true);
  });
});
