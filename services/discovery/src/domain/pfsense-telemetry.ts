/** Live pfSense telemetry from the REST API package (read-only). */
export interface PfSenseGatewayRow {
  name: string | null;
  /** Next-hop IP when known. Never the local WAN iface IP (`srcip`). */
  gateway: string | null;
  /** Local source IP used for monitor probes (WAN iface address). Not a next-hop. */
  srcip: string | null;
  monitor: string | null;
  status: string | null;
  delay: number | null;
  loss: number | null;
  interface: string | null;
  /** True when pfSense marks this gateway as the system default route. */
  isDefault?: boolean;
  description?: string | null;
}

export interface PfSenseDefaultGateway {
  ipv4: string | null;
  ipv6: string | null;
}

export interface PfSenseGatewayGroupMember {
  name: string;
  tier: number;
  status?: string | null;
}

export interface PfSenseGatewayGroup {
  name: string;
  description?: string | null;
  members: PfSenseGatewayGroupMember[];
}

export interface PfSenseInterfaceRow {
  name: string | null;
  descr: string | null;
  ipaddr: string | null;
  subnet: string | null;
  vlan: string | null;
  /** OS interface name (e.g. igc0, tun_wg2, ovpnc1). */
  hwif: string | null;
  mac: string | null;
  status: string | null;
}

export interface PfSenseSystemStatus {
  platform: string | null;
  uptime: string | null;
  version: string | null;
  hostname: string | null;
  domain: string | null;
}

export interface PfSenseVpnClientRow {
  name: string;
  type: 'openvpn' | 'wireguard';
  status: string | null;
  virtualAddress: string | null;
  remoteHost: string | null;
  interface: string | null;
  enabled: boolean;
}

export interface PfSenseEgressSummary {
  /** Gateway name inferred from state interface (e.g. GW_SURFSHARK_SP). */
  gateway: string;
  interface: string;
  stateCount: number;
  bytesOut: number;
}

export interface PfSenseGatewayGroupInsight {
  group: string;
  description: string | null;
  /** Lowest tier with an online member — pfSense failover preference. */
  preferredGateway: string | null;
  preferredTier: number | null;
  /** Gateway with the most egress states right now (observed). */
  activeGateway: string | null;
  activeStateCount: number;
  members: PfSenseGatewayGroupMember[];
}

export interface PfSenseTelemetry {
  version: string | null;
  hostname: string | null;
  system: PfSenseSystemStatus | null;
  gateways: PfSenseGatewayRow[];
  interfaces: PfSenseInterfaceRow[];
  defaultGateway: PfSenseDefaultGateway | null;
  gatewayGroups: PfSenseGatewayGroup[];
  gatewayGroupInsights: PfSenseGatewayGroupInsight[];
  vpnClients: PfSenseVpnClientRow[];
  egress: PfSenseEgressSummary[];
  stateCount: number;
  fetchedAt: string;
}
