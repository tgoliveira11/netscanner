import type { ConnectionType } from './device.js';

export interface ConnectionLookup {
  type: ConnectionType;
  port?: number;
  ifName?: string;
  basis: string;
}

/** Authoritative wired/WiFi from switch/AP SNMP or controller APIs. */
export interface IConnectionSource {
  readonly name: string;
  refresh(): Promise<void>;
  lookupByMac(mac: string): ConnectionLookup | null;
}
