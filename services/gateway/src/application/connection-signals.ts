import type { IConnectionSource } from '@netscanner/contracts';

/** Apply authoritative wired/WiFi from switch/AP SNMP when available. */
export function applyConnectionSignals(
  mac: string | null,
  signals: Record<string, unknown>,
  source?: IConnectionSource,
): Record<string, unknown> {
  if (!mac || !source) return signals;
  const conn = source.lookupByMac(mac);
  if (!conn) return signals;
  return {
    ...signals,
    connectionAuthoritative: conn.type,
    connectionAuthoritativeBasis: conn.basis,
    snmpBridgePort: conn.port,
    snmpIfName: conn.ifName,
  };
}
