import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { MacAddress, isOk } from '@netscanner/kernel';
import type { Logger } from '@netscanner/logger';
import type { IRouterLeaseSource, RouterLease } from '../domain/router-lease-source.js';

export interface HttpRouterScrapeConfig {
  baseUrl: string;
  kind: 'openwrt' | 'compal';
  username?: string;
  password?: string;
  insecureTls?: boolean;
}

/**
 * Generic HTTP router panel scrape (OpenWrt LuCI DHCP leases, Compal-style ARP table).
 * Fragile by design — enable only when you know the vendor.
 */
export class HttpRouterScrapeAdapter implements IRouterLeaseSource {
  readonly name: string;

  constructor(
    private readonly config: HttpRouterScrapeConfig,
    private readonly logger: Logger,
  ) {
    this.name = `router-scrape-${config.kind}`;
  }

  async getLeases(): Promise<RouterLease[]> {
    if (this.config.kind === 'openwrt') return this.scrapeOpenWrt();
    return this.scrapeCompalArp();
  }

  private async scrapeOpenWrt(): Promise<RouterLease[]> {
    const html = await this.getText(new URL('/cgi-bin/luci/admin/status/overview', this.config.baseUrl));
    const leases: RouterLease[] = [];
    const rowRe = /([0-9a-f:]{17})\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)/gi;
    let m: RegExpExecArray | null;
    while ((m = rowRe.exec(html))) {
      const macRaw = m[1]!.replace(/-/g, ':');
      const parsed = MacAddress.create(macRaw);
      leases.push({
        ip: m[2]!,
        mac: isOk(parsed) ? parsed.value.value : null,
        hostname: m[3] !== '*' ? m[3]! : null,
        interface: null,
        description: null,
        online: true,
      });
    }
    this.logger.info({ count: leases.length, kind: 'openwrt' }, 'router scrape leases');
    return leases;
  }

  private async scrapeCompalArp(): Promise<RouterLease[]> {
    const paths = ['/connected_devices_computers.jst', '/cgi-bin/connected_devices_computers.jst', '/'];
    for (const p of paths) {
      try {
        const html = await this.getText(new URL(p, this.config.baseUrl));
        const leases = this.parseCompalHtml(html);
        if (leases.length) {
          this.logger.info({ count: leases.length, kind: 'compal', path: p }, 'router scrape leases');
          return leases;
        }
      } catch {
        /* try next path */
      }
    }
    return [];
  }

  private parseCompalHtml(html: string): RouterLease[] {
    const leases: RouterLease[] = [];
    const re = /(\d+\.\d+\.\d+\.\d+)[^0-9a-fA-F]*([0-9a-f]{2}(?::[0-9a-f]{2}){5})/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(html))) {
      const parsed = MacAddress.create(m[2]!);
      leases.push({
        ip: m[1]!,
        mac: isOk(parsed) ? parsed.value.value : null,
        hostname: null,
        interface: null,
        description: 'compal-scrape',
        online: true,
      });
    }
    return leases;
  }

  private getText(url: URL): Promise<string> {
    const isHttps = url.protocol === 'https:';
    const requester = isHttps ? httpsRequest : httpRequest;
    const auth =
      this.config.username && this.config.password
        ? 'Basic ' + Buffer.from(`${this.config.username}:${this.config.password}`).toString('base64')
        : undefined;
    return new Promise((resolve, reject) => {
      const req = requester(
        url,
        {
          method: 'GET',
          headers: auth ? { Authorization: auth } : {},
          timeout: 8000,
          ...(isHttps ? { rejectUnauthorized: !this.config.insecureTls } : {}),
        },
        (res) => {
          let body = '';
          res.on('data', (c) => (body += c));
          res.on('end', () => {
            if ((res.statusCode ?? 500) >= 400) reject(new Error(`HTTP ${res.statusCode}`));
            else resolve(body);
          });
        },
      );
      req.on('error', reject);
      req.end();
    });
  }
}
