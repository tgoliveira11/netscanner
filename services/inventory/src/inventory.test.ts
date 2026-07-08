import { describe, expect, it } from 'vitest';
import { LEGACY_DEFAULT_SITE_ID } from '@netscanner/contracts';
import { InMemoryDeviceRepository } from './infrastructure/in-memory-device.repository.js';
import { UpsertDeviceUseCase, type DeviceSnapshot } from './application/upsert-device.use-case.js';

const SITE = LEGACY_DEFAULT_SITE_ID;

const snapshot = (over: Partial<DeviceSnapshot> = {}): DeviceSnapshot => ({
  ip: '192.168.1.50',
  mac: 'aa:bb:cc:00:11:22',
  vendor: 'Apple',
  brand: 'Apple',
  model: null,
  hostname: 'macbook',
  deviceType: 'laptop',
  confidence: 0.8,
  os: null,
  connectionType: 'unknown',
  services: [{ port: 22, protocol: 'tcp', state: 'open' }],
  latencyMs: 3,
  securityFlags: [],
  signals: {},
  ...over,
});

describe('UpsertDeviceUseCase', () => {
  it('creates a new device on first sight and flags it as new', async () => {
    const repo = new InMemoryDeviceRepository();
    const upsert = new UpsertDeviceUseCase(repo);
    const res = await upsert.execute(SITE, snapshot());
    expect(res.isNew).toBe(true);
    expect(res.device.firstSeen).toBe(res.device.lastSeen);
    expect((await repo.list({ siteId: SITE }))).toHaveLength(1);
  });

  it('reconciles by MAC, preserves firstSeen/label, and reports changes', async () => {
    const repo = new InMemoryDeviceRepository();
    const upsert = new UpsertDeviceUseCase(repo);
    const first = await upsert.execute(SITE, snapshot());
    await repo.save({ ...first.device, label: 'My Laptop' }, SITE);

    const second = await upsert.execute(
      SITE,
      snapshot({
        ip: '192.168.1.77',
        services: [
          { port: 22, protocol: 'tcp', state: 'open' },
          { port: 445, protocol: 'tcp', state: 'open' },
        ],
      }),
    );
    expect(second.isNew).toBe(false);
    expect(second.device.id).toBe(first.device.id);
    expect(second.device.firstSeen).toBe(first.device.firstSeen);
    expect(second.device.label).toBe('My Laptop');
    expect(second.changes).toContain('ip: 192.168.1.50 → 192.168.1.77');
    expect(second.changes.some((c) => c.includes('445'))).toBe(true);
  });

  it('does not let a flaky rescan erase OS or downgrade a confident classification', async () => {
    const repo = new InMemoryDeviceRepository();
    const upsert = new UpsertDeviceUseCase(repo);
    await upsert.execute(
      SITE,
      snapshot({
        os: { name: 'Apple macOS 26.1', family: 'macOS', accuracy: 95 },
        deviceType: 'laptop',
        confidence: 0.8,
      }),
    );
    const second = await upsert.execute(
      SITE,
      snapshot({ os: null, deviceType: 'phone', confidence: 0.3 }),
    );
    expect(second.device.os?.family).toBe('macOS');
    expect(second.device.deviceType).toBe('laptop');
    expect(second.device.classificationConfidence).toBe(0.8);
  });

  it('marks devices offline only within the same site', async () => {
    const repo = new InMemoryDeviceRepository();
    const upsert = new UpsertDeviceUseCase(repo);
    const a = await upsert.execute(SITE, snapshot({ mac: 'aa:aa:aa:aa:aa:aa', ip: '192.168.1.2' }));
    await upsert.execute(SITE, snapshot({ mac: 'bb:bb:bb:bb:bb:bb', ip: '192.168.1.3' }));
    const otherSite = '00000000-0000-4000-8000-000000000002';
    await upsert.execute(otherSite, snapshot({ mac: 'cc:cc:cc:cc:cc:cc', ip: '192.168.1.4' }));
    const offline = await repo.markOfflineExcept([a.device.id], SITE);
    expect(offline).toHaveLength(1);
    expect((await repo.list({ siteId: otherSite }))[0]?.isOnline).toBe(true);
  });

  it('does not erase a known MAC when a later snapshot omits it', async () => {
    const repo = new InMemoryDeviceRepository();
    const upsert = new UpsertDeviceUseCase(repo);
    await upsert.execute(SITE, snapshot({ mac: '9c:eb:e8:00:00:01', ip: '10.0.52.105', hostname: 'br0813' }));
    const second = await upsert.execute(
      SITE,
      snapshot({
        mac: null,
        ip: '10.0.52.105',
        hostname: 'br0813',
        deviceType: 'unknown',
        confidence: 0.1,
        services: [],
      }),
    );
    expect(second.isNew).toBe(false);
    expect(second.device.mac).toBe('9c:eb:e8:00:00:01');
  });

  it('restores MAC onto an IP-only record when a later snapshot finally has one', async () => {
    const repo = new InMemoryDeviceRepository();
    const upsert = new UpsertDeviceUseCase(repo);
    const first = await upsert.execute(SITE, snapshot({ mac: null, ip: '10.0.52.105', hostname: 'br0813' }));
    expect(first.device.mac).toBeNull();
    const second = await upsert.execute(
      SITE,
      snapshot({ mac: '9c:eb:e8:00:00:01', ip: '10.0.52.105', hostname: 'br0813' }),
    );
    expect(second.device.id).toBe(first.device.id);
    expect(second.device.mac).toBe('9c:eb:e8:00:00:01');
  });
});
