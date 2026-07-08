import { describe, expect, it } from 'vitest';
import {
  mergePfSenseLeases,
  normalizePfSenseArpLease,
  normalizePfSenseLease,
} from './pfsense-lease-normalize.js';

describe('normalizePfSenseLease', () => {
  it('maps pfSense v2 dhcp fields', () => {
    expect(
      normalizePfSenseLease({
        ip: '10.0.1.10',
        mac: 'aa:bb:cc:dd:ee:ff',
        hostname: 'iphone',
        if: 'VLAN10',
        descr: 'Kids',
        online_status: 'active/online',
      }),
    ).toEqual({
      ip: '10.0.1.10',
      mac: 'aa:bb:cc:dd:ee:ff',
      hostname: 'iphone',
      interface: 'VLAN10',
      description: 'Kids',
      online: true,
    });
  });

  it('marks idle leases offline', () => {
    expect(
      normalizePfSenseLease({ ip: '10.0.0.2', mac: '00:11:22:33:44:55', online_status: 'idle/offline' })
        ?.online,
    ).toBe(false);
  });
});

describe('mergePfSenseLeases', () => {
  it('prefers dhcp over arp for hostname and interface', () => {
    const dhcp = [
      {
        ip: '10.0.1.10',
        mac: 'aa:bb:cc:dd:ee:ff',
        hostname: 'iphone',
        interface: 'VLAN10',
        description: null,
        online: true,
      },
    ];
    const arp = [normalizePfSenseArpLease({ ip: '10.0.1.10', mac: 'aa:bb:cc:dd:ee:ff' })!];
    const merged = mergePfSenseLeases(dhcp, arp);
    expect(merged[0]?.hostname).toBe('iphone');
    expect(merged[0]?.interface).toBe('VLAN10');
  });

  it('adds arp-only hosts', () => {
    const merged = mergePfSenseLeases(
      [],
      [normalizePfSenseArpLease({ ip: '10.0.3.5', mac: '00:11:22:33:44:55' })!],
    );
    expect(merged).toHaveLength(1);
    expect(merged[0]?.ip).toBe('10.0.3.5');
  });
});
