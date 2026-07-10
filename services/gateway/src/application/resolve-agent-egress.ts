import type { SpeedTestEgressRoute } from '@netscanner/contracts';
import type { PfSenseTelemetry } from '@netscanner/discovery';

export interface AgentEgressSnapshot {
  egressGateway: string | null;
  egressRoute: SpeedTestEgressRoute;
}

const POLICY_GROUPS = ['LB_WAN', 'SSVPN_Failover', 'WAN_Failover'] as const;

function classifyRoute(group: string | null, gateway: string): SpeedTestEgressRoute {
  if (group === 'LB_WAN') return 'lb';
  if (group === 'SSVPN_Failover' || /vpn|surfshark|wireguard|openvpn|tun_/i.test(gateway)) return 'vpn';
  if (/WAN/i.test(gateway)) return 'wan';
  return 'unknown';
}

/** Infer which gateway group/path carries agent traffic from cached pfSense telemetry. */
export function resolveAgentEgress(telemetry: PfSenseTelemetry | null): AgentEgressSnapshot {
  if (!telemetry) return { egressGateway: null, egressRoute: 'unknown' };

  for (const groupName of POLICY_GROUPS) {
    const insight = telemetry.gatewayGroupInsights.find((g) => g.group === groupName);
    if (insight?.activeGateway) {
      return {
        egressGateway: insight.activeGateway,
        egressRoute: classifyRoute(groupName, insight.activeGateway),
      };
    }
  }

  const top = [...telemetry.egress].sort((a, b) => b.stateCount - a.stateCount)[0];
  if (top?.gateway) {
    return {
      egressGateway: top.gateway,
      egressRoute: classifyRoute(null, top.gateway),
    };
  }

  const def = telemetry.defaultGateway?.ipv4;
  if (def) {
    return { egressGateway: def, egressRoute: 'unknown' };
  }

  return { egressGateway: null, egressRoute: 'unknown' };
}
