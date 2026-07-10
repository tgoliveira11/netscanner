import { describe, expect, it } from 'vitest';
import {
  applyInterfaceLabels,
  buildGatewayGroupInsights,
  buildHwifToGatewayMap,
  buildInterfaceLabelMap,
  mergePfSenseGatewayRows,
  normalizePfSenseArpRow,
  normalizePfSenseDefaultGateway,
  normalizePfSenseGatewayGroups,
  normalizePfSenseGatewayRow,
  normalizePfSenseInterfaceRow,
  summarizePfSenseEgress,
  formatPfSenseAddresses,
  normalizePfSenseWireGuardTunnels,
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
    ).toBe('VLAN10');
  });
});

describe('normalizePfSenseGatewayRow', () => {
  it('does not treat srcip as the gateway next-hop', () => {
    expect(
      normalizePfSenseGatewayRow({
        name: 'WAN_ISP_DHCP',
        srcip: '10.0.0.2',
        monitorip: '8.8.8.8',
        status: 'online',
        delay: 6.2,
        loss: 0,
      }),
    ).toEqual({
      name: 'WAN_ISP_DHCP',
      gateway: null,
      srcip: '10.0.0.2',
      monitor: '8.8.8.8',
      status: 'online',
      delay: 6.2,
      loss: 0,
      interface: null,
      isDefault: false,
      description: null,
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

describe('normalizePfSenseDefaultGateway', () => {
  it('parses ipv4/ipv6 default gateway names', () => {
    expect(
      normalizePfSenseDefaultGateway({ defaultgw4: 'GW_SURFSHARK_SP', defaultgw6: '' }),
    ).toEqual({ ipv4: 'GW_SURFSHARK_SP', ipv6: null });
  });
});

describe('normalizePfSenseGatewayGroups', () => {
  it('parses tier members', () => {
    const groups = normalizePfSenseGatewayGroups([
      {
        name: 'GW_SURFSHARK_SP',
        descr: 'Surfshark failover',
        item: [
          { gateway: 'WAN_DHCP', tier: 1 },
          { gateway: 'OVPN_SURFSHARK_UY_VPNV4', tier: 2 },
        ],
      },
    ]);
    expect(groups[0]?.members).toHaveLength(2);
    expect(groups[0]?.members[0]).toMatchObject({ name: 'WAN_DHCP', tier: 1 });
  });

  it('parses priorities field from REST API v2', () => {
    const groups = normalizePfSenseGatewayGroups([
      {
        name: 'SSVPN_Failover',
        descr: 'Surfshark failover',
        priorities: [
          { gateway: 'GW_SURFSHARK_SP', tier: 1 },
          { gateway: 'OVPN_SURFSHARK_UY_VPNV4', tier: 3 },
        ],
      },
    ]);
    expect(groups[0]?.members).toHaveLength(2);
    expect(groups[0]?.members[1]).toMatchObject({ name: 'OVPN_SURFSHARK_UY_VPNV4', tier: 3 });
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

describe('summarizePfSenseEgress', () => {
  it('maps states to gateway names via hwif', () => {
    const ifaces = [
      normalizePfSenseInterfaceRow({ name: 'opt9', hwif: 'ovpnc1', descr: 'OVPN_UY' }),
    ];
    const gateways = [
      normalizePfSenseGatewayRow({ name: 'OVPN_UY', interface: 'opt9', status: 'online' }),
    ];
    const map = buildHwifToGatewayMap(ifaces, gateways);
    const { egress, stateCount } = summarizePfSenseEgress(
      [{ if: 'ovpnc1', bytes: 1000 }, { if: 'ovpnc1', bytes: 500 }],
      map,
    );
    expect(stateCount).toBe(2);
    expect(egress[0]).toMatchObject({ gateway: 'OVPN_UY', stateCount: 2, bytesOut: 1500 });
  });
});

describe('buildGatewayGroupInsights', () => {
  it('picks lowest online tier and highest egress member', () => {
    const groups = normalizePfSenseGatewayGroups([
      {
        name: 'SSVPN_Failover',
        item: [
          { gateway: 'GW_WG', tier: 1 },
          { gateway: 'GW_UY', tier: 3 },
        ],
      },
    ]);
    const gateways = [
      normalizePfSenseGatewayRow({ name: 'GW_WG', status: 'online' }),
      normalizePfSenseGatewayRow({ name: 'GW_UY', status: 'online' }),
    ];
    const egress = [{ gateway: 'GW_UY', interface: 'ovpnc1', stateCount: 42, bytesOut: 0 }];
    const insights = buildGatewayGroupInsights(groups, gateways, egress);
    expect(insights[0]).toMatchObject({
      preferredGateway: 'GW_WG',
      preferredTier: 1,
      activeGateway: 'GW_UY',
      activeStateCount: 42,
    });
  });
});

describe('normalizePfSenseWireGuardTunnels', () => {
  it('formats addresses array from REST API', () => {
    const rows = normalizePfSenseWireGuardTunnels([
      {
        descr: 'WG_SURFSHARK_SP',
        name: 'tun_wg2',
        enabled: true,
        addresses: [{ address: '10.14.0.2', mask: 16 }],
      },
    ]);
    expect(rows[0]).toMatchObject({
      name: 'WG_SURFSHARK_SP',
      type: 'wireguard',
      virtualAddress: '10.14.0.2/16',
      interface: 'tun_wg2',
      enabled: true,
    });
  });
});

describe('formatPfSenseAddresses', () => {
  it('joins multiple address rows', () => {
    expect(
      formatPfSenseAddresses([
        { address: '10.14.0.2', mask: 16 },
        { address: 'fd00::2', mask: 64 },
      ]),
    ).toBe('10.14.0.2/16, fd00::2/64');
  });
});
