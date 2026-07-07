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
    out[key] = value;
  }
  return out;
}
