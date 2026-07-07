import { describe, it, expect } from 'vitest';
import { DeviceEnrichmentService } from './application/device-enrichment.service.js';
import type { Device } from '@netscanner/contracts';

const baseDevice = (over: Partial<Device> = {}): Device => ({
  id: '1',
  ip: '192.168.1.10',
  mac: 'aa:bb:cc:11:22:33',
  vendor: 'Apple, Inc.',
  brand: null,
  model: null,
  hostname: null,
  deviceType: 'phone',
  classificationConfidence: 0.5,
  os: null,
  connectionType: 'wifi',
  services: [],
  latencyMs: 1,
  isOnline: true,
  securityFlags: [],
  label: null,
  notes: null,
  firstSeen: new Date().toISOString(),
  lastSeen: new Date().toISOString(),
  signals: {},
  ...over,
});

describe('DeviceEnrichmentService', () => {
  const dhcpSource = {
    get: (mac: string) =>
      mac === 'aa:bb:cc:11:22:33'
        ? { mac, fingerprint: '1,3,6,15', vendorClass: 'android-dhcp-14', hostname: 'pixel' }
        : undefined,
  };

  it('needs enrichment when DHCP fingerprint is new', () => {
    const svc = new DeviceEnrichmentService({
      classify: { execute: () => ({}) } as never,
      upsert: { execute: async () => ({}) } as never,
      repo: {} as never,
      dhcpSource: dhcpSource as never,
    });
    expect(svc.needsEnrichment(baseDevice())).toBe(true);
    expect(
      svc.needsEnrichment(
        baseDevice({
          signals: { dhcpFingerprint: '1,3,6,15', fingerbankDevice: 'Pixel 7' },
          os: { family: 'Android', version: '14' },
          model: 'Pixel 7',
        }),
      ),
    ).toBe(false);
  });
});
