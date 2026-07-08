import { describe, expect, it } from 'vitest';
import type { Device } from '@netscanner/contracts';
import {
  collapseInfrastructureAliases,
  isInfrastructureInterface,
  isPfSenseSelfNic,
  pickCanonicalInfrastructure,
} from './infrastructure-aliases.js';

const ifaces = [
  { name: 'igc0', descr: 'LAN_MAIN', ipaddr: '192.168.51.1', mac: '60:be:b4:23:9c:60' },
  { name: 'vlan0.52', descr: 'LAN_GUEST', ipaddr: '192.168.52.1', mac: '60:be:b4:23:9c:61' },
  { name: 'vlan0.60', descr: 'LAN_IOT', ipaddr: '192.168.60.1', mac: '60:be:b4:23:9c:62' },
  { name: 'opt1', descr: 'WAN_CLARO', ipaddr: '192.168.15.86', mac: '60:be:b4:23:9c:5f' },
];

const base = (over: Partial<Device>): Device =>
  ({
    id: 'd1',
    ip: '192.168.1.50',
    mac: null,
    hostname: null,
    vendor: null,
    brand: null,
    model: null,
    deviceType: 'router',
    classificationConfidence: 0.8,
    os: null,
    connectionType: 'unknown',
    services: [],
    latencyMs: null,
    isOnline: true,
    securityFlags: [],
    label: null,
    notes: null,
    firstSeen: '2026-01-01T00:00:00.000Z',
    lastSeen: '2026-01-01T00:00:00.000Z',
    signals: { pfsenseInterfaces: ifaces },
    ...over,
  }) as Device;

describe('infrastructure aliases', () => {
  it('detects pfSense VLAN NICs from shared interface telemetry', () => {
    const guest = base({ id: 'guest', ip: '192.168.52.1' });
    expect(isInfrastructureInterface(guest, ifaces)).toBe(true);
    expect(isPfSenseSelfNic(guest)).toBe(true);
  });

  it('does not treat regular clients as infrastructure interfaces', () => {
    const phone = base({
      id: 'phone',
      ip: '192.168.51.100',
      mac: '44:f2:1b:24:fb:60',
      deviceType: 'phone',
    });
    expect(isInfrastructureInterface(phone, ifaces)).toBe(false);
  });

  it('picks configured primary IP as canonical', () => {
    const rows = [
      base({ id: 'guest', ip: '192.168.52.1', deviceType: 'router' }),
      base({ id: 'main', ip: '192.168.51.1', deviceType: 'firewall', mac: '60:be:b4:23:9c:60' }),
      base({ id: 'iot', ip: '192.168.60.1', deviceType: 'router' }),
    ];
    expect(
      pickCanonicalInfrastructure(rows, { preferredIp: '192.168.51.1' }).id,
    ).toBe('main');
  });

  it('collapses duplicate pfSense NIC rows into one device with alias metadata', () => {
    const rows = [
      base({ id: 'guest', ip: '192.168.52.1', deviceType: 'router' }),
      base({ id: 'main', ip: '192.168.51.1', deviceType: 'firewall', mac: '60:be:b4:23:9c:60' }),
      base({ id: 'iot', ip: '192.168.60.1', deviceType: 'router' }),
      base({ id: 'phone', ip: '192.168.51.100', mac: '44:f2:1b:24:fb:60', deviceType: 'phone', signals: {} }),
    ];
    const collapsed = collapseInfrastructureAliases(rows, { preferredIp: '192.168.51.1' });
    const infra = collapsed.filter((d) =>
      (d.signals?.infrastructureIps as string[] | undefined)?.length,
    );
    expect(infra).toHaveLength(1);
    expect(infra[0]!.ip).toBe('192.168.51.1');
    expect(infra[0]!.signals.infrastructureIps).toEqual([
      '192.168.51.1',
      '192.168.52.1',
      '192.168.60.1',
    ]);
    expect(collapsed).toHaveLength(2);
    expect(collapsed.some((d) => d.ip === '192.168.52.1')).toBe(false);
    expect(collapsed.some((d) => d.ip === '192.168.51.100')).toBe(true);
  });
});
