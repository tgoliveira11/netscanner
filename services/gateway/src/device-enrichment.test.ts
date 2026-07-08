import { describe, it, expect } from 'vitest';
import type { IVendorLookup } from '@netscanner/kernel';
import { DeviceEnrichmentService } from './application/device-enrichment.service.js';
import { ClassifyDeviceUseCase, ClassificationEngine, SecurityAnalyzer, defaultRules } from '@netscanner/classification';
import type { Device } from '@netscanner/contracts';
import { TrafficMonitor } from '@netscanner/scanner';

const stubVendor = (vendor?: string): IVendorLookup => ({ resolve: () => vendor });

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
  routerScrapePasswordSet: false,
  firstSeen: new Date().toISOString(),
  lastSeen: new Date().toISOString(),
  signals: {},
  ...over,
});

const siteDeps = { getSiteId: () => '00000000-0000-4000-8000-000000000001' as const };

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
      ...siteDeps,
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

  it('needs port rescan when online with no prior scan or stale portScanAt', () => {
    const svc = new DeviceEnrichmentService({
      classify: { execute: () => ({}) } as never,
      upsert: { execute: async () => ({}) } as never,
      repo: {} as never,
      ...siteDeps,
    });
    const weekMs = 7 * 24 * 60 * 60 * 1000;
    expect(svc.needsPortRescan(baseDevice(), weekMs)).toBe(true);
    expect(svc.needsPortRescan(baseDevice({ isOnline: false }), weekMs)).toBe(false);
    expect(
      svc.needsPortRescan(
        baseDevice({
          services: [{ port: 443, protocol: 'tcp', state: 'open' }],
          signals: { portScanAt: new Date().toISOString() },
        }),
        weekMs,
      ),
    ).toBe(false);
    expect(
      svc.needsPortRescan(
        baseDevice({
          services: [{ port: 443, protocol: 'tcp', state: 'open' }],
          signals: { portScanAt: new Date(Date.now() - weekMs - 1).toISOString() },
        }),
        weekMs,
      ),
    ).toBe(true);
  });

  it('buildSnapshot attaches DNS profile, CVE findings, and traffic on first pass', async () => {
    const classify = new ClassifyDeviceUseCase(
      new ClassificationEngine(defaultRules()),
      stubVendor('Test'),
      new SecurityAnalyzer(),
    );
    const trafficMonitor = new TrafficMonitor();
    trafficMonitor.ingest([{ ip: '192.168.1.10', bytesIn: 1000, bytesOut: 2000, connections: 3 }], 0);
    trafficMonitor.ingest([{ ip: '192.168.1.10', bytesIn: 2000, bytesOut: 4000, connections: 4 }], 1000);

    const svc = new DeviceEnrichmentService({
      classify,
      upsert: { execute: async () => ({}) } as never,
      repo: {} as never,
      trafficMonitor,
      ...siteDeps,
    });

    const snapshot = await svc.buildSnapshot({
      ip: '192.168.1.10',
      mac: 'aa:bb:cc:11:22:33',
      hostname: 'nas',
      services: [{ port: 22, protocol: 'tcp', state: 'open', product: 'OpenSSH', version: '8.4' }],
      os: null,
      latencyMs: 1,
      signals: { dnsRecentQueries: ['pool.ntp.org', 'update.microsoft.com'] },
      gatewayIp: '192.168.1.1',
    });

    expect(snapshot.signals['dnsProfile']).toBeDefined();
    expect(Array.isArray(snapshot.signals['cveFindings'])).toBe(true);
    expect(typeof snapshot.signals['riskScore']).toBe('number');
    expect(snapshot.signals['traffic']).toMatchObject({ bytesIn: 2000, bytesOut: 4000 });
  });
});
