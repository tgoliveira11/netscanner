import { createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { MacAddress, isOk } from '@netscanner/kernel';
import type { Logger } from '@netscanner/logger';
import type { IRouterLeaseSource, RouterLease } from '../domain/router-lease-source.js';

export interface FritzBoxConfig {
  baseUrl: string;
  username?: string;
  password?: string;
  insecureTls?: boolean;
  timeoutMs?: number;
}

/**
 * Reads connected hosts from a Fritz!Box via login_sid.lua + query.lua.
 * Vendor-specific and fragile, but common on European home networks.
 */
export class FritzBoxHttpAdapter implements IRouterLeaseSource {
  readonly name = 'fritzbox-http';

  constructor(
    private readonly config: FritzBoxConfig,
    private readonly logger: Logger,
  ) {}

  async getLeases(): Promise<RouterLease[]> {
    const sid = await this.login();
    if (!sid) return [];

    const url = new URL(`/query.lua?network=network:hosts&sid=${encodeURIComponent(sid)}`, this.config.baseUrl);
    const raw = await this.getText(url);
    const leases = this.parseHostsJson(raw);
    this.logger.info({ count: leases.length }, 'Fritz!Box hosts fetched');
    return leases;
  }

  private async login(): Promise<string | null> {
    const sidUrl = new URL('/login_sid.lua', this.config.baseUrl);
    const sidXml = await this.getText(sidUrl);
    const sid = /<SID>([^<]+)<\/SID>/.exec(sidXml)?.[1];
    const challenge = /<Challenge>([^<]+)<\/Challenge>/.exec(sidXml)?.[1];
    if (!sid || sid !== '0000000000000000') return sid ?? null;
    if (!challenge || !this.config.password) return null;

    const response =
      challenge +
      '-' +
      createHash('md5')
        .update(`${challenge}-${this.config.password}`, 'utf16le')
        .digest('hex');
    const user = this.config.username ?? '';
    const loginUrl = new URL(
      `/login_sid.lua?username=${encodeURIComponent(user)}&response=${response}`,
      this.config.baseUrl,
    );
    const loginXml = await this.getText(loginUrl);
    const newSid = /<SID>([^<]+)<\/SID>/.exec(loginXml)?.[1];
    return newSid && newSid !== '0000000000000000' ? newSid : null;
  }

  private parseHostsJson(raw: string): RouterLease[] {
    let data: unknown;
    try {
      data = JSON.parse(raw);
    } catch {
      return [];
    }
    const hosts = (data as { network?: { hosts?: { host?: unknown[] } } })?.network?.hosts?.host;
    if (!Array.isArray(hosts)) return [];

    const leases: RouterLease[] = [];
    for (const h of hosts) {
      if (!h || typeof h !== 'object') continue;
      const row = h as Record<string, unknown>;
      const ip = str(row['ip'] ?? row['IPAddress']);
      const rawMac = str(row['mac'] ?? row['MACAddress']);
      if (!ip) continue;
      let mac: string | null = null;
      if (rawMac) {
        const parsed = MacAddress.create(rawMac.replace(/-/g, ':'));
        mac = isOk(parsed) ? parsed.value.value : null;
      }
      const active = row['active'] ?? row['Active'];
      leases.push({
        ip,
        mac,
        hostname: str(row['name'] ?? row['HostName']) ?? null,
        interface: null,
        description: str(row['vendor'] ?? row['Manufacturer']) ?? null,
        online: active === true || active === 1 || active === '1' || active === 'true',
      });
    }
    return leases;
  }

  private getText(url: URL): Promise<string> {
    const isHttps = url.protocol === 'https:';
    const requester = isHttps ? httpsRequest : httpRequest;
    return new Promise((resolve, reject) => {
      const req = requester(
        url,
        {
          method: 'GET',
          timeout: this.config.timeoutMs ?? 8000,
          ...(isHttps ? { rejectUnauthorized: !this.config.insecureTls } : {}),
        },
        (res) => {
          let body = '';
          res.on('data', (c) => (body += c));
          res.on('end', () => {
            if ((res.statusCode ?? 500) >= 400) {
              reject(new Error(`Fritz!Box HTTP ${res.statusCode}`));
              return;
            }
            resolve(body);
          });
        },
      );
      req.on('timeout', () => req.destroy(new Error('Fritz!Box timeout')));
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
