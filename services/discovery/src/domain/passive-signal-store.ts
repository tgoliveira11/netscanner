/** Observation from a continuous passive listener (mDNS, SSDP, LLDP…). */
export interface PassiveObservation {
  ip: string;
  mac?: string | null;
  hostname?: string | null;
  source: string;
  signals: Record<string, unknown>;
}

/**
 * Durable cache of passively observed host signals. Listeners write here;
 * scans and the background enricher read merged signals per IP.
 */
export interface IPassiveSignalStore {
  ingest(obs: PassiveObservation): Promise<void>;
  get(ip: string): Record<string, unknown>;
  /** Signals keyed by MAC (e.g. LLDP before IP is known). */
  getByMac(mac: string): Record<string, unknown>;
  findIpByMac(mac: string): string | undefined;
  list(): PassiveObservation[];
  onUpdated(handler: (ip: string) => void): () => void;
}

export function mergePassiveSignals(
  base: Record<string, unknown>,
  incoming: Record<string, unknown>,
): Record<string, unknown> {
  const out = { ...base };
  for (const [key, value] of Object.entries(incoming)) {
    if (value == null || value === '') continue;
    if (key === 'mdnsServices' && Array.isArray(out[key]) && Array.isArray(value)) {
      const merged = [...new Set([...(out[key] as string[]), ...(value as string[])])];
      out[key] = merged;
      continue;
    }
    if (key === 'igmpGroups' && Array.isArray(out[key]) && Array.isArray(value)) {
      out[key] = [...new Set([...(out[key] as string[]), ...(value as string[])])];
      continue;
    }
    if (key === 'dnsRecentQueries' && Array.isArray(out[key]) && Array.isArray(value)) {
      const merged = [...new Set([...(out[key] as string[]), ...(value as string[])])];
      out[key] = merged.slice(-30);
      continue;
    }
    if (key === 'mdnsTxt' && out[key] && typeof out[key] === 'object' && typeof value === 'object') {
      out[key] = { ...(out[key] as Record<string, unknown>), ...(value as Record<string, unknown>) };
      continue;
    }
    out[key] = value;
  }
  return out;
}
