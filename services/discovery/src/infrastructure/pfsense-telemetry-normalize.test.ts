import { describe, expect, it } from 'vitest';
import {
  applyInterfaceLabels,
  buildInterfaceLabelMap,
  mergePfSenseGatewayRows,
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
      normalizePfSenseInterfaceRow({ name: 'opt4', descr: 'LAN_MAIN' }),
    ]);
    expect(map.get('opt4')).toBe('LAN_MAIN');
    expect(
      applyInterfaceLabels(
        [
          {
            ip: '1.1.1.1',
            mac: 'aa:bb:cc:dd:ee:ff',
            hostname: null,
            interface: 'opt4',
            description: null,
            online: true,
          },
        ],
        map,
      )[0]?.interface,
    ).toBe('LAN_MAIN');
  });
});

describe('normalizePfSenseGatewayRow', () => {
  it('does not treat srcip as the gateway next-hop', () => {
    expect(
      normalizePfSenseGatewayRow({
        name: 'WAN_CLARO_DHCP',
        srcip: '10.0.0.2',
        monitorip: '8.8.8.8',
        status: 'online',
        delay: 6.2,
        loss: 0,
      }),
    ).toEqual({
      name: 'WAN_CLARO_DHCP',
      gateway: null,
      srcip: '10.0.0.2',
      monitor: '8.8.8.8',
      status: 'online',
      delay: 6.2,
      loss: 0,
      interface: null,
    });
  });

  it('keeps an explicit next-hop and ignores dynamic placeholders', () => {
    expect(
      normalizePfSenseGatewayRow({
        name: 'GW_WAN',
        gateway: '10.0.0.1',
        srcip: '10.0.0.2',
        interface: 'opt1',
      }),
    ).toMatchObject({ gateway: '10.0.0.1', srcip: '10.0.0.2', interface: 'opt1' });

    expect(
      normalizePfSenseGatewayRow({
        name: 'WAN_DHCP',
        gateway: 'dynamic',
        interface: 'wan',
      }).gateway,
    ).toBeNull();
  });
});

describe('mergePfSenseGatewayRows', () => {
  it('overlays routing config next-hop / interface onto status rows', () => {
    const merged = mergePfSenseGatewayRows(
      [
        normalizePfSenseGatewayRow({
          name: 'WAN_EXAMPLE',
          srcip: '10.0.0.2',
          status: 'online',
          monitorip: '8.8.8.8',
        }),
      ],
      [
        normalizePfSenseGatewayRow({
          name: 'WAN_EXAMPLE',
          gateway: '10.0.0.1',
          interface: 'opt1',
        }),
      ],
    );
    expect(merged[0]).toMatchObject({
      name: 'WAN_EXAMPLE',
      gateway: '10.0.0.1',
      srcip: '10.0.0.2',
      interface: 'opt1',
      status: 'online',
    });
  });
});
