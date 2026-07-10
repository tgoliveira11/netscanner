import { describe, expect, it } from 'vitest';
import type { PfSenseTelemetry } from '@netscanner/discovery';
import { resolveAgentEgress } from './resolve-agent-egress.js';

describe('resolveAgentEgress', () => {
  it('returns null when telemetry missing', () => {
    expect(resolveAgentEgress(null)).toEqual({ egressGateway: null, egressRoute: 'unknown' });
  });

  it('prefers LB_WAN active gateway', () => {
    const telemetry = {
      gatewayGroupInsights: [
        { group: 'LB_WAN', activeGateway: 'WAN_DHCP', activeStateCount: 10, preferredGateway: null, preferredTier: null, description: null, members: [] },
        { group: 'SSVPN_Failover', activeGateway: 'GW_VPN', activeStateCount: 2, preferredGateway: null, preferredTier: null, description: null, members: [] },
      ],
      egress: [],
      defaultGateway: null,
    } as unknown as PfSenseTelemetry;
    expect(resolveAgentEgress(telemetry)).toEqual({ egressGateway: 'WAN_DHCP', egressRoute: 'lb' });
  });

  it('classifies VPN group', () => {
    const telemetry = {
      gatewayGroupInsights: [
        { group: 'SSVPN_Failover', activeGateway: 'GW_SURFSHARK', activeStateCount: 50, preferredGateway: null, preferredTier: null, description: null, members: [] },
      ],
      egress: [],
      defaultGateway: null,
    } as unknown as PfSenseTelemetry;
    expect(resolveAgentEgress(telemetry).egressRoute).toBe('vpn');
  });
});
