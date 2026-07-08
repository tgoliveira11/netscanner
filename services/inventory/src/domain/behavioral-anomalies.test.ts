import { describe, expect, it } from 'vitest';
import type { Device } from '@netscanner/contracts';
import { detectBehavioralAnomalies } from './behavioral-anomalies.js';

const base = (over: Partial<Device>): Device =>
  ({
    id: 'd1',
    ip: '192.168.1.50',
    mac: 'aa:bb:cc:00:11:22',
    vendor: 'Apple',
    brand: null,
    model: null,
    hostname: 'phone',
    deviceType: 'phone',
    classificationConfidence: 0.8,
    os: null,
    connectionType: 'unknown',
    services: [{ port: 443, protocol: 'tcp', state: 'open' }],
    latencyMs: 1,
    isOnline: true,
    securityFlags: [],
    label: null,
    notes: null,
    firstSeen: '2026-01-01',
    lastSeen: '2026-01-01',
    signals: {
      baseline: {
        openPorts: [443],
        externalDomains: ['icloud.com'],
        mac: 'aa:bb:cc:00:11:22',
        vendor: 'Apple',
      },
    },
    ...over,
  }) as Device;

describe('detectBehavioralAnomalies', () => {
  it('flags new open ports', () => {
    const prev = base({});
    const next = base({
      services: [
        { port: 443, protocol: 'tcp', state: 'open' },
        { port: 22, protocol: 'tcp', state: 'open' },
      ],
    });
    const anomalies = detectBehavioralAnomalies(prev, next);
    expect(anomalies.some((a) => a.code === 'NEW_OPEN_PORT')).toBe(true);
  });

  it('flags MAC change', () => {
    const anomalies = detectBehavioralAnomalies(
      base({}),
      base({ mac: 'bb:cc:dd:ee:ff:00' }),
    );
    expect(anomalies.some((a) => a.code === 'MAC_CHANGED')).toBe(true);
  });
});
