import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';
import { MacAddress, isOk } from '@netscanner/kernel';
import type { Logger } from '@netscanner/logger';
import type { IRouterLeaseSource, RouterLease } from '../domain/router-lease-source.js';

export interface PfSenseConfig {
  baseUrl: string; // e.g. https://192.168.51.1
  apiKey: string;
  leasesPath: string; // e.g. /api/v2/status/dhcp_server/leases
  insecureTls: boolean;
  timeoutMs?: number;
}

/**
 * Reads DHCP leases from pfSense via the REST API package (v2), authenticated
 * with an API key (`X-API-Key`). Tolerant of field-name variations across API
 * versions. Self-signed TLS is accepted by default (pfSense's GUI cert).
 */
export class PfSenseRestAdapter implements IRouterLeaseSource {
  readonly name = 'pfsense-rest';

  constructor(
    private readonly config: PfSenseConfig,
    private readonly logger: Logger,
  ) {}

  async getLeases(): Promise<RouterLease[]> {
    const url = new URL(this.config.leasesPath, this.config.baseUrl);
    const raw = await this.getJson(url);
    const rows = this.extractArray(raw);
    const leases = rows.map((r) => this.toLease(r)).filter((l): l is RouterLease => l !== null);
    this.logger.info({ count: leases.length, source: this.name }, 'router leases fetched');
    return leases;
  }

  private toLease(r: Record<string, unknown>): RouterLease | null {
    const ip = str(r['ip'] ?? r['address'] ?? r['ip_address']);
    const rawMac = str(r['mac'] ?? r['hwaddr'] ?? r['mac_address']);
    if (!ip && !rawMac) return null;
    let mac: string | null = null;
    if (rawMac) {
      const parsed = MacAddress.create(rawMac);
      mac = isOk(parsed) ? parsed.value.value : null;
    }
    // pfSense v2 returns online_status="active/online" | "idle/offline".
    const state = str(r['online_status'] ?? r['active_status'] ?? r['state'] ?? r['status'] ?? r['act']);
    return {
      ip: ip ?? '',
      mac,
      hostname: str(r['hostname'] ?? r['host'] ?? r['client_hostname']) ?? null,
      interface: str(r['if'] ?? r['interface'] ?? r['iface']) ?? null,
      description: str(r['descr'] ?? r['description']) ?? null,
      online: state ? /online|active|bound/i.test(state) && !/offline/i.test(state) : true,
    };
  }

  /** The REST API wraps results as { data: [...] }; fall back to any array found. */
  private extractArray(raw: unknown): Record<string, unknown>[] {
    if (Array.isArray(raw)) return raw as Record<string, unknown>[];
    if (raw && typeof raw === 'object') {
      const data = (raw as Record<string, unknown>)['data'];
      if (Array.isArray(data)) return data as Record<string, unknown>[];
      for (const value of Object.values(raw as Record<string, unknown>)) {
        if (Array.isArray(value)) return value as Record<string, unknown>[];
      }
    }
    return [];
  }

  private getJson(url: URL): Promise<unknown> {
    const isHttps = url.protocol === 'https:';
    const requester = isHttps ? httpsRequest : httpRequest;
    return new Promise((resolve, reject) => {
      const req = requester(
        url,
        {
          method: 'GET',
          headers: { 'X-API-Key': this.config.apiKey, Accept: 'application/json' },
          timeout: this.config.timeoutMs ?? 5000,
          ...(isHttps ? { rejectUnauthorized: !this.config.insecureTls } : {}),
        },
        (res) => {
          let body = '';
          res.on('data', (c) => (body += c));
          res.on('end', () => {
            if ((res.statusCode ?? 500) >= 400) {
              reject(new Error(`pfSense API ${res.statusCode}: ${body.slice(0, 200)}`));
              return;
            }
            try {
              resolve(JSON.parse(body));
            } catch {
              reject(new Error('pfSense API returned non-JSON (check URL/path/key)'));
            }
          });
        },
      );
      req.on('timeout', () => req.destroy(new Error('pfSense API timeout')));
      req.on('error', reject);
      req.end();
    });
  }
}

function str(v: unknown): string | undefined {
  if (v == null) return undefined;
  const s = String(v).trim();
  return s.length ? s : undefined;
}
