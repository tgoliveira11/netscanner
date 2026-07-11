import { describe, expect, it } from 'vitest';
import { isPhysicalWanGateway, listPhysicalWanTargets } from './wan-gateway-list.js';

describe('isPhysicalWanGateway', () => {
  it('accepts ISP WANs and rejects VPN monitors', () => {
    expect(isPhysicalWanGateway('WAN_DHCP')).toBe(true);
    expect(isPhysicalWanGateway('WAN_CLARO_DHCP')).toBe(true);
    expect(isPhysicalWanGateway('OVPN_SURFSHARK_MIA_VPNV4')).toBe(false);
    expect(isPhysicalWanGateway('GW_SURFSHARK_SP')).toBe(false);
  });
});

describe('listPhysicalWanTargets', () => {
  const interfaces = [
    { name: 'wan', descr: 'WAN_VIVO', ipaddr: '192.168.15.86', subnet: null, vlan: null, hwif: 'igc0', mac: null, status: 'up' },
    { name: 'opt1', descr: 'WAN_CLARO', ipaddr: '192.168.0.135', subnet: null, vlan: null, hwif: 'igc1', mac: null, status: 'up' },
  ];

  it('resolves hwif from srcip when gateway.interface is missing', () => {
    const targets = listPhysicalWanTargets(
      [
        { name: 'WAN_DHCP', gateway: null, srcip: '192.168.15.86', monitor: null, status: 'online', delay: null, loss: null, interface: null, isDefault: false, description: null },
        { name: 'WAN_CLARO_DHCP', gateway: null, srcip: '192.168.0.135', monitor: null, status: 'online', delay: null, loss: null, interface: null, isDefault: false, description: null },
      ],
      interfaces,
    );
    expect(targets.map((t) => ({ name: t.name, hwif: t.hwif }))).toEqual([
      { name: 'WAN_CLARO_DHCP', hwif: 'igc1' },
      { name: 'WAN_DHCP', hwif: 'igc0' },
    ]);
  });

  it('dedupes by physical hwif', () => {
    const targets = listPhysicalWanTargets(
      [
        { name: 'WAN_DHCP', gateway: null, srcip: '192.168.15.86', monitor: null, status: 'online', delay: null, loss: null, interface: 'wan', isDefault: true, description: null },
        { name: 'WAN_VIVO', gateway: null, srcip: '192.168.15.86', monitor: null, status: 'online', delay: null, loss: null, interface: 'wan', isDefault: false, description: null },
      ],
      interfaces,
    );
    expect(targets).toHaveLength(1);
    expect(targets[0]?.hwif).toBe('igc0');
  });
});
