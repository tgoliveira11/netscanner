import { describe, expect, it } from 'vitest';
import type { Device } from '@netscanner/contracts';
import {
  collectVlans,
  isPfSenseSelfNic,
  isTopologyClient,
  isWanOrSideIp,
  looksLikeWifiAp,
  pickGateway,
  pickMacSharingHost,
  pickWanModems,
  pickWifiAccessPoints,
  pickWiredInfra,
  resolveClientAttachment,
  resolveWiredParent,
  wiredEdge,
} from './build-topology.use-case.js';

const syntheticIfaces = [
  {
    name: 'opt1',
    descr: 'WAN_EXAMPLE',
    ipaddr: '10.0.0.2',
    mac: 'aa:bb:cc:00:00:60',
  },
  {
    name: 'opt3',
    descr: 'LAN_INFRA',
    ipaddr: '10.0.10.1',
    mac: 'aa:bb:cc:00:00:62',
  },
];

const baseDevice = (overrides: Partial<Device>): Device =>
  ({
    id: 'd1',
    ip: '10.0.1.50',
    mac: 'aa:bb:cc:dd:ee:01',
    hostname: null,
    deviceType: 'desktop',
    connectionType: 'unknown',
    isOnline: true,
    isGateway: false,
    signals: {},
    ...overrides,
  }) as Device;

describe('pickGateway', () => {
  it('prefers configured pfSense / SNMP host over other routers', () => {
    const devices = [
      baseDevice({ id: 'ap', ip: '10.0.1.101', deviceType: 'router' }),
      baseDevice({ id: 'gw', ip: '10.0.1.1', deviceType: 'router' }),
      baseDevice({ id: 'sw', ip: '10.0.10.2', deviceType: 'router' }),
    ];
    expect(
      pickGateway(devices, [], { PFSENSE_URL: 'https://10.0.1.1' } as never)!.id,
    ).toBe('gw');
  });

  it('skips local scanner bridge', () => {
    const ifaces = [
      {
        name: 'bridge100',
        address: '192.168.64.1',
        netmask: '255.255.255.0',
        mac: '62:3e:5f:a5:ff:64',
        cidr: '192.168.64.0/24',
      },
    ];
    const devices = [
      baseDevice({ id: 'bridge', ip: '192.168.64.1', deviceType: 'router', mac: '62:3e:5f:a5:ff:64' }),
      baseDevice({ id: 'gw', ip: '10.0.1.1', deviceType: 'router' }),
    ];
    expect(pickGateway(devices, ifaces, {} as never)!.id).toBe('gw');
  });

  it('does not pick a WAN modem as the LAN gateway', () => {
    const devices = [
      baseDevice({
        id: 'modem',
        ip: '10.0.0.1',
        deviceType: 'router',
        signals: {
          pfsenseInterface: 'WAN_EXAMPLE',
          pfsenseInterfaces: syntheticIfaces,
          pfsenseGateways: [{ name: 'WAN_EXAMPLE_DHCP', gateway: '10.0.0.1', interface: 'opt1' }],
        },
      }),
      baseDevice({ id: 'gw', ip: '10.0.10.1', deviceType: 'router', signals: { pfsenseHostname: 'pfsense' } }),
    ];
    expect(pickGateway(devices, [], {} as never)!.id).toBe('gw');
  });
});

describe('pickWiredInfra / pickWifiAccessPoints', () => {
  const gateway = baseDevice({ id: 'gw', ip: '10.0.1.1', deviceType: 'router' });
  const eligibility = {
    localIfaces: [],
    managedRouterIps: new Set(['10.0.10.2', '10.0.1.101', '10.0.2.101', '10.0.3.100']),
    gatewayId: 'gw',
  };

  it('picks Ubiquiti on LAN_INFRA as wired infra', () => {
    const sw = baseDevice({
      id: 'sw',
      ip: '10.0.10.2',
      deviceType: 'router',
      brand: 'Ubiquiti',
      connectionType: 'wired',
      signals: { pfsenseInterface: 'LAN_INFRA' },
    });
    const ap = baseDevice({
      id: 'ap',
      ip: '10.0.1.101',
      deviceType: 'router',
      hostname: 'cbnre-example',
      brand: 'OpenWRT',
      signals: { pfsenseInterface: 'LAN_MAIN' },
    });
    expect(
      pickWiredInfra([gateway, sw, ap], gateway, eligibility, {
        SNMP_SWITCH_HOST: '10.0.10.2',
      } as never)?.id,
    ).toBe('sw');
  });

  it('picks Compal cbnre* as wifi APs', () => {
    const devices = [
      gateway,
      baseDevice({
        id: 'ap-main',
        ip: '10.0.1.101',
        deviceType: 'router',
        hostname: 'cbnre-example-a',
        brand: 'Compal',
        signals: { pfsenseInterface: 'LAN_MAIN' },
      }),
      baseDevice({
        id: 'ap-iot',
        ip: '10.0.3.100',
        deviceType: 'router',
        hostname: 'cbnre-example-b',
        brand: 'Compal',
        signals: { pfsenseInterface: 'LAN_IOT' },
      }),
      baseDevice({
        id: 'sw',
        ip: '10.0.10.2',
        deviceType: 'router',
        brand: 'Ubiquiti',
        signals: { pfsenseInterface: 'LAN_INFRA' },
      }),
    ];
    const aps = pickWifiAccessPoints(devices, gateway, eligibility, [], [
      { baseUrl: 'http://10.0.1.101', kind: 'compal', username: 'u', password: 'p' },
      { baseUrl: 'http://10.0.3.100', kind: 'compal', username: 'u', password: 'p' },
    ]);
    expect(aps.map((a) => a.id).sort()).toEqual(['ap-iot', 'ap-main']);
  });
});

describe('WAN modems / pfSense self NIC', () => {
  const gateway = baseDevice({
    id: 'gw',
    ip: '10.0.10.1',
    deviceType: 'router',
    signals: { pfsenseHostname: 'pfsense', pfsenseInterfaces: syntheticIfaces },
  });

  it('detects pfSense self NICs by MAC/IP', () => {
    const wanNic = baseDevice({
      id: 'wan-nic',
      ip: '10.0.0.2',
      mac: 'aa:bb:cc:00:00:60',
      deviceType: 'firewall',
      signals: {
        pfsenseInterface: 'WAN_EXAMPLE',
        pfsenseInterfaces: syntheticIfaces,
      },
    });
    expect(isPfSenseSelfNic(wanNic)).toBe(true);
    expect(isTopologyClient(wanNic, gateway, [])).toBe(false);
  });

  it('picks ISP CPE (.1 on WAN*) as a wan modem, not a client', () => {
    const modem = baseDevice({
      id: 'modem',
      ip: '10.0.0.1',
      mac: 'd4:92:5e:00:00:01',
      deviceType: 'router',
      signals: {
        pfsenseInterface: 'WAN_EXAMPLE',
        pfsenseInterfaces: syntheticIfaces,
        pfsenseGateways: [{ name: 'WAN_EXAMPLE_DHCP', gateway: null, srcip: '10.0.0.2' }],
      },
    });
    expect(pickWanModems([gateway, modem], gateway).map((d) => d.id)).toEqual(['modem']);
    expect(isTopologyClient(modem, gateway, [])).toBe(false);
  });
});

describe('Mac Internet Sharing', () => {
  const ifaces = [
    {
      name: 'en0',
      address: '10.0.1.50',
      netmask: '255.255.255.0',
      mac: '11:22:33:44:55:66',
      cidr: '10.0.1.0/24',
    },
    {
      name: 'bridge100',
      address: '192.168.64.1',
      netmask: '255.255.255.0',
      mac: '62:3e:5f:a5:ff:64',
      cidr: '192.168.64.0/24',
    },
  ];

  it('parents Mac Sharing to the LAN host that owns the bridge, not pfSense', () => {
    const macHost = baseDevice({
      id: 'mac',
      ip: '10.0.1.50',
      mac: '11:22:33:44:55:66',
      deviceType: 'laptop',
      hostname: 'mac',
    });
    const shareGw = baseDevice({
      id: 'bridge',
      ip: '192.168.64.1',
      mac: '62:3e:5f:a5:ff:64',
      deviceType: 'router',
    });
    const guest = baseDevice({
      id: 'guest',
      ip: '192.168.64.2',
      mac: '9a:59:ac:a1:7b:b6',
      deviceType: 'phone',
    });
    expect(pickMacSharingHost([macHost, shareGw, guest], ifaces)?.id).toBe('mac');
    expect(isWanOrSideIp('192.168.64.2')).toBe(true);
  });
});

describe('isTopologyClient', () => {
  it('includes phones and excludes routers / vpn / side nets', () => {
    const gw = baseDevice({ id: 'gw', ip: '10.0.1.1', deviceType: 'router' });
    expect(
      isTopologyClient(
        baseDevice({ id: 'phone', ip: '10.0.1.100', deviceType: 'phone', connectionType: 'wifi' }),
        gw,
        [],
      ),
    ).toBe(true);
    expect(isTopologyClient(baseDevice({ id: 'r', ip: '10.0.1.101', deviceType: 'router' }), gw, [])).toBe(
      false,
    );
    expect(isWanOrSideIp('10.0.0.1')).toBe(false); // not classic 192.168.0 handoff in synthetic lab
    expect(isWanOrSideIp('192.168.0.1')).toBe(true);
    expect(isWanOrSideIp('192.168.64.2')).toBe(true);
    expect(isWanOrSideIp('10.8.8.4')).toBe(true);
    expect(isWanOrSideIp('10.0.1.100')).toBe(false);
  });
});

describe('looksLikeWifiAp', () => {
  it('detects cbnre hostnames and compal scrape', () => {
    expect(
      looksLikeWifiAp(
        baseDevice({ id: 'ap', ip: '10.0.2.101', hostname: 'cbnre-example', deviceType: 'router' }),
        [],
        [],
      ),
    ).toBe(true);
    expect(
      looksLikeWifiAp(
        baseDevice({ id: 'sw', ip: '10.0.10.2', brand: 'Ubiquiti', deviceType: 'router' }),
        [],
        [],
      ),
    ).toBe(false);
  });
});

describe('resolveWiredParent', () => {
  it('prefers SNMP switch hub over gateway', () => {
    expect(
      resolveWiredParent(
        baseDevice({}),
        { type: 'wired', basis: 'SNMP', ifName: 'eth2' },
        'switch-id',
        'gw-id',
      ),
    ).toBe('switch-id');
  });
});

describe('resolveClientAttachment', () => {
  const gateway = baseDevice({ id: 'gw', ip: '10.0.1.1', deviceType: 'router' });
  const switchDevice = baseDevice({
    id: 'sw',
    ip: '10.0.10.2',
    deviceType: 'switch',
    signals: { pfsenseInterface: 'LAN_INFRA' },
  });
  const ap = baseDevice({
    id: 'ap',
    ip: '10.0.1.101',
    deviceType: 'access-point',
    signals: { pfsenseInterface: 'LAN_MAIN' },
  });
  const apByVlan = new Map([['LAN_MAIN', ap]]);

  it('hangs SNMP-wired clients under the switch even if connectionType is wifi', () => {
    const phone = baseDevice({
      id: 'phone',
      ip: '10.0.1.100',
      connectionType: 'wifi',
      signals: { pfsenseInterface: 'LAN_MAIN' },
    });
    const result = resolveClientAttachment({
      device: phone,
      vlan: { id: 'LAN_MAIN', label: 'LAN_MAIN' },
      snmp: { type: 'wired', port: 2, ifName: 'eth1', basis: 'SNMP BRIDGE-MIB port 2 (eth1)' },
      switchDevice,
      gateway,
      wifiAps: [ap],
      apByVlan,
      wireless: [],
    });
    expect(result).toMatchObject({ parentId: 'sw', kind: 'wired', label: 'eth1' });
  });

  it('hangs SNMP wifi / device wifi under the AP', () => {
    const phone = baseDevice({
      id: 'phone',
      ip: '10.0.1.100',
      connectionType: 'wifi',
      signals: { pfsenseInterface: 'LAN_MAIN' },
    });
    expect(
      resolveClientAttachment({
        device: phone,
        vlan: { id: 'LAN_MAIN', label: 'LAN_MAIN' },
        snmp: null,
        switchDevice,
        gateway,
        wifiAps: [ap],
        apByVlan,
        wireless: [],
      })?.parentId,
    ).toBe('ap');
  });

  it('hangs non-SNMP wired LAN_MAIN clients under gateway, not the switch', () => {
    const desktop = baseDevice({
      id: 'pc',
      ip: '10.0.1.50',
      connectionType: 'wired',
      signals: { pfsenseInterface: 'LAN_MAIN' },
    });
    expect(
      resolveClientAttachment({
        device: desktop,
        vlan: { id: 'LAN_MAIN', label: 'LAN_MAIN' },
        snmp: null,
        switchDevice,
        gateway,
        wifiAps: [ap],
        apByVlan,
        wireless: [],
      }),
    ).toMatchObject({ parentId: 'gw', kind: 'wired' });
  });
});

describe('collectVlans', () => {
  it('orders core VLANs and skips WAN', () => {
    const edges = [
      wiredEdge('a', 'b', 'uplink', { id: 'LAN_IOT', label: 'LAN_IOT' }),
      wiredEdge('c', 'b', 'uplink', { id: 'LAN_MAIN', label: 'LAN_MAIN' }),
      wiredEdge('d', 'b', 'uplink', { id: 'WAN', label: 'WAN' }),
      wiredEdge('e', 'b', 'uplink', { id: 'LAN_INFRA', label: 'LAN_INFRA' }),
    ];
    expect(collectVlans(edges).map((v) => v.id)).toEqual(['LAN_INFRA', 'LAN_MAIN', 'LAN_IOT']);
  });
});
