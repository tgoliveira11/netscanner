import { describe, it, expect } from 'vitest';
import type { IVendorLookup } from '@netscanner/kernel';
import { ClassificationEngine } from './domain/classification-engine.js';
import { ClassifyDeviceUseCase } from './application/classify-device.use-case.js';
import { SecurityAnalyzer } from './domain/security-analyzer.js';
import { defaultRules } from './index.js';

const stubVendor = (vendor: string | undefined): IVendorLookup => ({ resolve: () => vendor });

function build(vendor?: string) {
  return new ClassifyDeviceUseCase(
    new ClassificationEngine(defaultRules()),
    stubVendor(vendor),
    new SecurityAnalyzer(),
  );
}

describe('ClassifyDeviceUseCase', () => {
  it('classifies a printer from an open JetDirect port', () => {
    const result = build('Brother Industries').execute({
      ip: '192.168.1.20',
      mac: 'aa:bb:cc:dd:ee:ff',
      hostname: 'BRW-Office',
      os: null,
      vendorFromScan: null,
      services: [{ port: 9100, protocol: 'tcp', state: 'open' }],
      signals: {},
    });
    expect(result.deviceType).toBe('printer');
    expect(result.confidence).toBeGreaterThan(0.5);
    expect(result.vendor).toBe('Brother Industries');
  });

  it('classifies the default gateway as a router with high confidence', () => {
    const result = build().execute({
      ip: '192.168.1.1',
      mac: null,
      hostname: null,
      os: null,
      vendorFromScan: null,
      services: [],
      gatewayIp: '192.168.1.1',
      signals: {},
    });
    expect(result.deviceType).toBe('router');
    expect(result.confidence).toBeGreaterThan(0.6);
  });

  it('raises a security flag for open telnet and reports unknown connection type', () => {
    const result = build().execute({
      ip: '192.168.1.30',
      mac: null,
      hostname: null,
      os: null,
      vendorFromScan: null,
      services: [{ port: 23, protocol: 'tcp', state: 'open' }],
      signals: {},
    });
    expect(result.securityFlags.some((f) => f.code === 'telnet-open')).toBe(true);
    expect(result.connectionType).toBe('unknown');
  });

  it('infers a phone/laptop from a randomized (locally-administered) MAC instead of unknown', () => {
    const result = build().execute({
      ip: '10.0.1.102',
      mac: 'be:06:60:32:27:c6', // 2nd bit of first octet set → randomized
      hostname: null,
      os: null,
      vendorFromScan: null,
      services: [],
      signals: {},
    });
    expect(result.deviceType).toBe('phone');
    expect(result.confidence).toBeGreaterThan(0.1);
  });

  it('a detected desktop OS (macOS) beats the randomized-MAC phone lean → laptop', () => {
    const result = build().execute({
      ip: '10.0.1.103',
      mac: 'be:06:60:32:27:c6', // randomized → would otherwise lean "phone"
      hostname: null,
      os: { name: 'Apple macOS 26.1', family: 'macOS', accuracy: 95 },
      vendorFromScan: null,
      services: [],
      signals: {},
    });
    expect(result.deviceType).toBe('laptop');
  });

  it('classifies an iOS host as a phone', () => {
    const result = build().execute({
      ip: '10.0.1.90',
      mac: null,
      hostname: null,
      os: { name: 'Apple iPhone OS 17', family: 'iOS', accuracy: 92 },
      vendorFromScan: null,
      services: [],
      signals: {},
    });
    expect(result.deviceType).toBe('phone');
  });

  it('identifies a NAS from a UPnP/HTTP banner even without a useful MAC', () => {
    const result = build().execute({
      ip: '10.0.1.50',
      mac: null,
      hostname: null,
      os: null,
      vendorFromScan: null,
      services: [{ port: 80, protocol: 'tcp', state: 'open' }],
      signals: { upnpManufacturer: 'Synology', upnpModel: 'DS920+', httpTitle: 'DiskStation' },
    });
    expect(result.deviceType).toBe('nas');
    expect(result.confidence).toBeGreaterThan(0.6);
  });

  it('fills the OS field by inference when nmap detected nothing', () => {
    const result = build().execute({
      ip: '192.168.1.60',
      mac: null,
      hostname: null,
      os: null, // nmap -O found nothing (e.g. firewalled host)
      vendorFromScan: null,
      services: [{ port: 22, protocol: 'tcp', state: 'open', banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu' }],
      signals: {},
    });
    expect(result.os?.family).toBe('Linux');
    expect(result.os?.source).toBe('inferred');
    expect(result.reasons.some((r) => /OS inferred/.test(r))).toBe(true);
  });

  it('does not override a real nmap OS with an inferred one', () => {
    const result = build().execute({
      ip: '192.168.1.61',
      mac: null,
      hostname: 'Example-MacBook',
      os: { name: 'Apple macOS 26.1', family: 'macOS', accuracy: 95, source: 'nmap' },
      vendorFromScan: null,
      services: [{ port: 22, protocol: 'tcp', state: 'open', banner: 'OpenSSH Ubuntu' }],
      signals: {},
    });
    expect(result.os?.source).toBe('nmap');
    expect(result.os?.accuracy).toBe(95);
  });

  it('distinguishes an Apple Watch from an iPhone via the DHCP hostname', () => {
    const watch = build().execute({
      ip: '10.0.1.104',
      mac: '4e:01:07:a2:fc:3a',
      hostname: 'watch',
      os: null,
      vendorFromScan: null,
      services: [],
      signals: {},
    });
    expect(watch.deviceType).toBe('wearable');
    expect(watch.os?.name).toMatch(/watchos/i); // OS inferred from hostname

    const phone = build().execute({
      ip: '10.0.1.100',
      mac: 'aa:bb:cc:11:22:33',
      hostname: 'users-iphone',
      os: null,
      vendorFromScan: null,
      services: [],
      signals: {},
    });
    expect(phone.deviceType).toBe('phone');
    expect(phone.os?.family).toMatch(/ios/i);
  });

  it('lets a Fingerbank match (from the DHCP fingerprint) win — Apple Watch vs iPhone', () => {
    const watch = build().execute({
      ip: '10.0.1.104',
      mac: '4e:01:07:a2:fc:3a',
      hostname: null,
      os: null,
      vendorFromScan: null,
      services: [],
      signals: { fingerbankDevice: 'Apple Watch', fingerbankPath: 'Hardware/Apple/Apple Watch' },
    });
    expect(watch.deviceType).toBe('wearable');

    const phone = build().execute({
      ip: '10.0.1.100',
      mac: null,
      hostname: null,
      os: null,
      vendorFromScan: null,
      services: [],
      signals: { fingerbankDevice: 'iPhone', fingerbankPath: 'Hardware/Apple/iPhone/iPhone 15' },
    });
    expect(phone.deviceType).toBe('phone');
  });

  it('classifies a Chromecast from mDNS googlecast signal', () => {
    const result = build().execute({
      ip: '192.168.1.40',
      mac: null,
      hostname: 'Living-Room-TV',
      os: null,
      vendorFromScan: null,
      services: [],
      signals: { mdnsServices: ['googlecast:Chromecast'], mdnsType: 'googlecast' },
    });
    expect(result.deviceType).toBe('streaming-device');
  });
});
