/** An authoritative device fact from the router's DHCP server. */
export interface RouterLease {
  ip: string;
  mac: string | null;
  hostname: string | null;
  /** Router interface/VLAN the device is attached to (e.g. "VLAN20"). */
  interface: string | null;
  description: string | null;
  online: boolean;
}

/**
 * Port for a router integration that yields DHCP leases (DIP). Adapters (pfSense
 * REST API, SSH, SNMP…) are interchangeable. The router is authoritative for
 * hostname↔MAC↔VLAN across every segment — including subnets the local scan
 * cannot reach — so it is the strongest identity source available.
 */
export interface IRouterLeaseSource {
  readonly name: string;
  getLeases(): Promise<RouterLease[]>;
}
