import type { Logger } from '@netscanner/logger';
import type {
  FingerprintQuery,
  FingerprintResult,
  IDeviceFingerprintResolver,
} from '../domain/fingerprint-resolver.js';

const ENDPOINT = 'https://api.fingerbank.org/api/v2/combinations/interrogate';

/**
 * Fingerbank cloud client. Sends the DHCP fingerprint (option 55), vendor class,
 * MAC and hostname to Fingerbank, which returns the most likely device model/OS
 * and a confidence score. The DHCP fingerprint is what makes exact-model
 * identification possible (e.g. distinguishing an iPhone model from an iPad).
 *
 * A tiny in-memory cache avoids re-querying the same combination within a run,
 * respecting Fingerbank's free-tier rate limits.
 */
export class FingerbankClient implements IDeviceFingerprintResolver {
  private readonly cache = new Map<string, FingerprintResult | null>();

  constructor(
    private readonly apiKey: string,
    private readonly logger: Logger,
    private readonly timeoutMs = 4000,
    /** Discard matches below this Fingerbank score to avoid weak guesses. */
    private readonly minScore = 30,
  ) {}

  async resolve(query: FingerprintQuery): Promise<FingerprintResult | null> {
    // Need at least a fingerprint or a MAC to say anything useful.
    if (!query.dhcpFingerprint && !query.mac) return null;
    const key = JSON.stringify(query);
    if (this.cache.has(key)) return this.cache.get(key) ?? null;

    const result = await this.query(query);
    this.cache.set(key, result);
    return result;
  }

  private async query(query: FingerprintQuery): Promise<FingerprintResult | null> {
    const body: Record<string, string> = {};
    if (query.dhcpFingerprint) body['dhcp_fingerprint'] = query.dhcpFingerprint;
    if (query.dhcpVendor) body['dhcp_vendor'] = query.dhcpVendor;
    if (query.mac) body['mac'] = query.mac;
    if (query.hostname) body['hostname'] = query.hostname;

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      const res = await fetch(`${ENDPOINT}?key=${encodeURIComponent(this.apiKey)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      }).finally(() => clearTimeout(timer));

      if (res.status === 404) return null; // no match
      if (!res.ok) {
        this.logger.warn({ status: res.status }, 'Fingerbank query failed');
        return null;
      }
      const data = (await res.json()) as Record<string, any>;
      const deviceName: string | undefined = data?.device?.name ?? data?.device_name;
      if (!deviceName) return null;
      const score = typeof data?.score === 'number' ? data.score : null;
      // A low score means Fingerbank is unsure — don't let it override heuristics.
      if (score !== null && score < this.minScore) return null;
      return {
        deviceName,
        devicePath: typeof data?.device_name === 'string' ? data.device_name : null,
        version: data?.version || null,
        score,
      };
    } catch (error) {
      this.logger.warn({ error: error instanceof Error ? error.message : error }, 'Fingerbank request error');
      return null;
    }
  }
}
