import { describe, expect, it } from 'vitest';
import { classifyGatewayKind, routeAliasForGateway } from '@netscanner/contracts';
import { buildRouteOptions } from './network-control.service.js';
import type { PfSenseTelemetry } from '@netscanner/discovery';

describe('routeAliasForGateway', () => {
  it('sanitizes gateway names into NS_RT_* aliases', () => {
    expect(routeAliasForGateway('WAN_DHCP')).toBe('NS_RT_WAN_DHCP');
    expect(routeAliasForGateway('SSVPN_Failover')).toBe('NS_RT_SSVPN_Failover');
    expect(routeAliasForGateway('GW SURFSHARK!')).toBe('NS_RT_GW_SURFSHARK');
  });
});

describe('classifyGatewayKind', () => {
  it('classifies common names', () => {
    expect(classifyGatewayKind('WAN_DHCP')).toBe('wan');
    expect(classifyGatewayKind('LB_WAN')).toBe('lb');
    expect(classifyGatewayKind('SSVPN_Failover')).toBe('vpn');
  });
});

describe('buildRouteOptions', () => {
  it('merges groups and gateways', () => {
    const telemetry = {
      gatewayGroups: [{ name: 'LB_WAN', description: 'load', members: [] }],
      gateways: [
        { name: 'WAN_DHCP', status: 'Online', description: 'Vivo' },
        { name: 'WAN_CLARO_DHCP', status: 'Online', description: 'Claro' },
      ],
    } as unknown as PfSenseTelemetry;
    const opts = buildRouteOptions(telemetry);
    expect(opts.map((o) => o.name)).toContain('LB_WAN');
    expect(opts.map((o) => o.name)).toContain('WAN_DHCP');
    expect(opts.find((o) => o.name === 'WAN_DHCP')?.kind).toBe('wan');
  });
});
