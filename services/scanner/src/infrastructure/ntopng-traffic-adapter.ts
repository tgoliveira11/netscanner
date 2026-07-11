import type { Logger } from '@netscanner/logger';
import type { ITrafficSource, TrafficSample } from '../domain/traffic-source.js';

export interface NtopngTrafficAdapterOptions {
  baseUrl: string;
  token?: string;
  timeoutMs?: number;
}

/**
 * Optional ntopng REST adapter. Skipped quietly when unreachable or when
 * NTOPNG_URL is unset (CompositeTrafficSource ignores empty results).
 */
export class NtopngTrafficAdapter implements ITrafficSource {
  readonly name = 'ntopng';
  private readonly baseUrl: string;
  private readonly token?: string;
  private readonly timeoutMs: number;

  constructor(
    private readonly logger: Logger,
    options: NtopngTrafficAdapterOptions,
  ) {
    this.baseUrl = options.baseUrl.replace(/\/$/, '');
    this.token = options.token;
    this.timeoutMs = options.timeoutMs ?? 8_000;
  }

  async sample(): Promise<TrafficSample[]> {
    const ctrl = AbortSignal.timeout(this.timeoutMs);
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (this.token) headers['Authorization'] = `Token ${this.token}`;
    try {
      const res = await fetch(`${this.baseUrl}/lua/rest/v2/get/host/active.lua`, {
        headers,
        signal: ctrl,
      });
      if (!res.ok) {
        this.logger.debug({ status: res.status }, 'ntopng traffic unreachable');
        return [];
      }
      const body = (await res.json()) as {
        rsp?: { data?: Array<{ ip?: string; bytes?: { rcvd?: number; sent?: number }; num_alerts?: number }> };
        data?: Array<{ ip?: string; bytes?: { rcvd?: number; sent?: number } }>;
      };
      const rows = body.rsp?.data ?? body.data ?? [];
      return rows
        .filter((r) => r.ip)
        .map((r) => ({
          ip: String(r.ip),
          bytesIn: Number(r.bytes?.rcvd ?? 0),
          bytesOut: Number(r.bytes?.sent ?? 0),
          connections: 0,
        }));
    } catch (err) {
      this.logger.debug({ err: String(err) }, 'ntopng traffic sample failed');
      return [];
    }
  }
}
