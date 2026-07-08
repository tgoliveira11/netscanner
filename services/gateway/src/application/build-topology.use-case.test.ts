import { describe, expect, it } from 'vitest';
import type { Device } from '@netscanner/contracts';
import {
  collectVlans,
  isTopologyClient,
  isWanOrSideIp,
  looksLikeWifiAp,
  pickGateway,
  pickWifiAccessPoints,
  pickWiredInfra,
  resolveWiredParent,
  wiredEdge,
} from './build-topology.use-case.js';

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
        mac: '62:3e:5f:00:00:01',
        cidr: '192.168.64.0/24',
      },
    ];
    const devices = [
      baseDevice({ id: 'bridge', ip: '192.168.64.1', deviceType: 'router', mac: '62:3e:5f:00:00:01' }),
      baseDevice({ id: 'gw', ip: '10.0.1.1', deviceType: 'router' }),
    ];
    expect(pickGateway(devices, ifaces, {} as never)!.id).toBe('gw');
  });
});

describe('pickWiredInfra / pickWifiAccessPoints', () => {
  const gateway = baseDevice({ id: 'gw', ip: '10.0.1.1', deviceType: 'router' });
  const eligibility = {
    localIfaces: [],
    managedRouterIps: new Set(['10.0.10.2', '10.0.1.101', '10.0.2.101', '10.0.3.100']),
    gatewayId: 'gw',
  };

  it('picks Ubiquiti on VLAN40 as wired infra', () => {
    const sw = baseDevice({
      id: 'sw',
      ip: '10.0.10.2',
      deviceType: 'router',
      brand: 'Ubiquiti',
      connectionType: 'wired',
      signals: { pfsenseInterface: 'VLAN40' },
    });
    const ap = baseDevice({
      id: 'ap',
      ip: '10.0.1.101',
      deviceType: 'router',
      hostname: 'cbnre-example',
      brand: 'OpenWRT',
      signals: { pfsenseInterface: 'VLAN10' },
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
        signals: { pfsenseInterface: 'VLAN10' },
      }),
      baseDevice({
        id: 'ap-iot',
        ip: '10.0.3.100',
        deviceType: 'router',
        hostname: 'cbnre-example-b',
        brand: 'Compal',
        signals: { pfsenseInterface: 'VLAN20' },
      }),
      baseDevice({
        id: 'sw',
        ip: '10.0.10.2',
        deviceType: 'router',
        brand: 'Ubiquiti',
        signals: { pfsenseInterface: 'VLAN40' },
      }),
    ];
    const aps = pickWifiAccessPoints(devices, gateway, eligibility, [], [
      { baseUrl: 'http://10.0.1.101', kind: 'compal', username: 'u', password: 'p' },
      { baseUrl: 'http://10.0.3.100', kind: 'compal', username: 'u', password: 'p' },
    ]);
    expect(aps.map((a) => a.id).sort()).toEqual(['ap-iot', 'ap-main']);
  });
});

describe('isTopologyClient', () => {
  it('includes phones and excludes routers / wan / side net', () => {
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
    expect(isWanOrSideIp('192.168.0.1')).toBe(true);
    expect(isWanOrSideIp('192.168.64.2')).toBe(true);
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

describe('collectVlans', () => {
  it('orders core VLANs and skips WAN', () => {
    const edges = [
      wiredEdge('a', 'b', 'uplink', { id: 'VLAN20', label: 'VLAN20' }),
      wiredEdge('c', 'b', 'uplink', { id: 'VLAN10', label: 'VLAN10' }),
      wiredEdge('d', 'b', 'uplink', { id: 'WAN', label: 'WAN' }),
      wiredEdge('e', 'b', 'uplink', { id: 'VLAN40', label: 'VLAN40' }),
    ];
    expect(collectVlans(edges).map((v) => v.id)).toEqual(['VLAN40', 'VLAN10', 'VLAN20']);
  });
});
