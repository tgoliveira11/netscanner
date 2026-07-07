import { describe, it, expect } from 'vitest';
import { InMemoryDeviceRepository } from './infrastructure/in-memory-device.repository.js';
import { UpsertDeviceUseCase, type DeviceSnapshot } from './application/upsert-device.use-case.js';

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
    const res = await upsert.execute(snapshot());
    expect(res.isNew).toBe(true);
    expect(res.device.firstSeen).toBe(res.device.lastSeen);
    expect((await repo.list())).toHaveLength(1);
  });

  it('reconciles by MAC, preserves firstSeen/label, and reports changes', async () => {
    const repo = new InMemoryDeviceRepository();
    const upsert = new UpsertDeviceUseCase(repo);
    const first = await upsert.execute(snapshot());
    // user labels the device
    await repo.save({ ...first.device, label: 'My Laptop' });

    const second = await upsert.execute(
      snapshot({ ip: '192.168.1.77', services: [
        { port: 22, protocol: 'tcp', state: 'open' },
        { port: 445, protocol: 'tcp', state: 'open' },
      ] }),
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
    // First scan: rich data (OS detected, confident laptop).
    await upsert.execute(
      snapshot({
        os: { name: 'Apple macOS 26.1', family: 'macOS', accuracy: 95 },
        deviceType: 'laptop',
        confidence: 0.8,
      }),
    );
    // Second scan: OS detection failed, weaker classification.
    const second = await upsert.execute(
      snapshot({ os: null, deviceType: 'phone', confidence: 0.3 }),
    );
    expect(second.device.os?.family).toBe('macOS'); // OS preserved
    expect(second.device.deviceType).toBe('laptop'); // better classification kept
    expect(second.device.classificationConfidence).toBe(0.8);
  });

  it('marks devices offline when absent from the latest scan', async () => {
    const repo = new InMemoryDeviceRepository();
    const upsert = new UpsertDeviceUseCase(repo);
    const a = await upsert.execute(snapshot({ mac: 'aa:aa:aa:aa:aa:aa', ip: '192.168.1.2' }));
    await upsert.execute(snapshot({ mac: 'bb:bb:bb:bb:bb:bb', ip: '192.168.1.3' }));
    const offline = await repo.markOfflineExcept([a.device.id]);
    expect(offline).toHaveLength(1);
  });
});
