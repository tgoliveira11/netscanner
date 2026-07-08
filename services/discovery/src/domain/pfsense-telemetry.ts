/** Live pfSense telemetry from the REST API package (read-only). */
export interface PfSenseGatewayRow {
  name: string | null;
  gateway: string | null;
  monitor: string | null;
  status: string | null;
  delay: number | null;
  loss: number | null;
  interface: string | null;
}

export interface PfSenseInterfaceRow {
  name: string | null;
  descr: string | null;
  ipaddr: string | null;
  subnet: string | null;
  vlan: string | null;
  mac: string | null;
  status: string | null;
}

export interface PfSenseTelemetry {
  version: string | null;
  hostname: string | null;
  gateways: PfSenseGatewayRow[];
  interfaces: PfSenseInterfaceRow[];
  fetchedAt: string;
}
