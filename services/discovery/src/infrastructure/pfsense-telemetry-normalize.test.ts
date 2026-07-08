import { describe, expect, it } from 'vitest';
import {
  applyInterfaceLabels,
  buildInterfaceLabelMap,
  normalizePfSenseArpRow,
  normalizePfSenseGatewayRow,
  normalizePfSenseInterfaceRow,
} from './pfsense-telemetry-normalize.js';

describe('normalizePfSenseArpRow', () => {
  it('maps REST API arp_table fields', () => {
    expect(
      normalizePfSenseArpRow({
        ip_address: '10.0.1.10',
        mac_address: 'aa:bb:cc:dd:ee:ff',
        interface: 'opt4',
        hostname: 'iphone',
      }),
    ).toMatchObject({
      ip: '10.0.1.10',
      mac: 'aa:bb:cc:dd:ee:ff',
      interface: 'opt4',
      hostname: 'iphone',
    });
  });

  it('drops placeholder hostnames', () => {
    expect(
      normalizePfSenseArpRow({
        ip_address: '10.0.1.10',
        mac_address: 'aa:bb:cc:dd:ee:ff',
        hostname: '?',
      })?.hostname,
    ).toBeNull();
  });
});

describe('buildInterfaceLabelMap', () => {
  it('maps internal iface names to GUI labels', () => {
    const map = buildInterfaceLabelMap([
      normalizePfSenseInterfaceRow({ name: 'opt4', descr: 'VLAN10' }),
    ]);
    expect(map.get('opt4')).toBe('VLAN10');
    expect(applyInterfaceLabels(
      [{ ip: '1.1.1.1', mac: 'aa:bb:cc:dd:ee:ff', hostname: null, interface: 'opt4', description: null, online: true }],
      map,
    )[0]?.interface).toBe('VLAN10');
  });
});

describe('normalizePfSenseGatewayRow', () => {
  it('maps status/gateway fields', () => {
    expect(
      normalizePfSenseGatewayRow({
        name: 'GW_WAN',
        srcip: '10.0.0.2',
        monitorip: '1.1.1.1',
        status: 'online',
        delay: 6.2,
        loss: 0,
      }),
    ).toEqual({
      name: 'GW_WAN',
      gateway: '10.0.0.2',
      monitor: '1.1.1.1',
      status: 'online',
      delay: 6.2,
      loss: 0,
      interface: null,
    });
  });
});
