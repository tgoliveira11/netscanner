import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import type { Logger } from '@netscanner/logger';
import type { ITrafficSource, TrafficSample } from '../domain/traffic-source.js';
import {
  parseRestFirewallStates,
  type PfRestStateRow,
} from './pf-rest-states.parser.js';

export interface PfRestTrafficSourceOptions {
  baseUrl: string;
  apiKey: string;
  insecureTls?: boolean;
  timeoutMs?: number;
  /** Max pages × pageSize states to pull (safety cap). */
  maxPages?: number;
  pageSize?: number;
}

const DEFAULT_STATES_PATH = '/api/v2/firewall/states';

/**
 * Per-device traffic via pfSense REST API (`GET /api/v2/firewall/states`).
 * Preferred over SSH `pfctl -vvs state` when `PFSENSE_API_KEY` is configured.
 */
export class PfRestTrafficSource implements ITrafficSource {
  readonly name = 'pf-rest';

  constructor(
    private readonly logger: Logger,
    private readonly options: PfRestTrafficSourceOptions,
  ) {}

  async sample(): Promise<TrafficSample[]> {
    const rows = await this.fetchStates();
    const samples = parseRestFirewallStates(rows);
    this.logger.debug(
      { states: rows.length, devices: samples.length },
      'pf REST traffic sample',
    );
    return samples;
  }

  private async fetchStates(): Promise<PfRestStateRow[]> {
    const pageSize = this.options.pageSize ?? 500;
    const maxPages = this.options.maxPages ?? 3;
    const overallMs = this.options.timeoutMs ?? 8_000;
    const deadline = Date.now() + overallMs;
    const all: PfRestStateRow[] = [];

    for (let page = 0; page < maxPages; page++) {
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        this.logger.warn(
          { pages: page, states: all.length },
          'pf REST traffic sample hit overall deadline',
        );
        break;
      }
      const offset = page * pageSize;
      const path = `${DEFAULT_STATES_PATH}?limit=${pageSize}&offset=${offset}`;
      try {
        const raw = await this.getJson(path, Math.min(remaining, overallMs));
        const batch = this.extractArray(raw) as PfRestStateRow[];
        all.push(...batch);
        if (batch.length < pageSize) break;
      } catch (error) {
        this.logger.warn(
          { page, error: error instanceof Error ? error.message : error },
          'pf REST traffic page failed',
        );
        break;
      }
    }

    return all;
  }

  private extractArray(raw: unknown): Record<string, unknown>[] {
    if (Array.isArray(raw)) return raw as Record<string, unknown>[];
    if (raw && typeof raw === 'object') {
      const data = (raw as Record<string, unknown>)['data'];
      if (Array.isArray(data)) return data as Record<string, unknown>[];
    }
    return [];
  }

  private getJson(path: string, timeoutMs = this.options.timeoutMs ?? 8_000): Promise<unknown> {
    const url = new URL(path, this.options.baseUrl);
    const isHttps = url.protocol === 'https:';
    const requester = isHttps ? httpsRequest : httpRequest;

    return new Promise((resolve, reject) => {
      const req = requester(
        url,
        {
          method: 'GET',
          headers: { 'X-API-Key': this.options.apiKey, Accept: 'application/json' },
          timeout: timeoutMs,
          ...(isHttps ? { rejectUnauthorized: !(this.options.insecureTls ?? true) } : {}),
        },
        (res) => {
          let body = '';
          const maxBytes = 4 * 1024 * 1024;
          res.on('data', (c: Buffer | string) => {
            body += c;
            if (body.length > maxBytes) {
              req.destroy(new Error('pfSense states API response too large'));
            }
          });
          res.on('end', () => {
            if ((res.statusCode ?? 500) >= 400) {
              reject(new Error(`pfSense states API ${res.statusCode}: ${body.slice(0, 200)}`));
              return;
            }
            try {
              resolve(JSON.parse(body));
            } catch {
              reject(new Error('pfSense states API returned non-JSON'));
            }
          });
        },
      );
      const hardTimer = setTimeout(() => {
        req.destroy(new Error('pfSense states API hard timeout'));
      }, timeoutMs + 500);
      req.on('timeout', () => req.destroy(new Error('pfSense states API timeout')));
      req.on('error', (err) => {
        clearTimeout(hardTimer);
        reject(err);
      });
      req.on('close', () => clearTimeout(hardTimer));
      req.end();
    });
  }
}
