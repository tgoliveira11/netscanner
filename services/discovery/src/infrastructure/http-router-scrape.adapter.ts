import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { MacAddress, isOk } from '@netscanner/kernel';
import type { Logger } from '@netscanner/logger';
import type { IRouterLeaseSource, RouterLease } from '../domain/router-lease-source.js';
import { LuciClient } from './luci-client.js';
import { resolveLuciAuthMode } from './luci-auth-mode.js';

export interface HttpRouterScrapeConfig {
  baseUrl: string;
  kind: 'openwrt' | 'compal';
  username?: string;
  password?: string;
  insecureTls?: boolean;
}

interface HttpResponse {
  status: number;
  body: string;
  headers: Record<string, string | string[] | undefined>;
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
    this.name = `router-scrape-${hostLabel(config.baseUrl)}`;
  }

  async getLeases(): Promise<RouterLease[]> {
    const auth = resolveLuciAuthMode({ kind: this.config.kind, username: this.config.username });
    if (auth === 'compal-rsa' && this.config.username && this.config.password) {
      try {
        return await this.scrapeRsaLuci();
      } catch (error) {
        this.logger.warn(
          {
            host: hostLabel(this.config.baseUrl),
            error: error instanceof Error ? error.message : error,
          },
          'Compal LuCI scrape failed — falling back to HTML ARP',
        );
        if (this.config.kind === 'compal') return this.scrapeCompalArp();
        throw error instanceof Error ? error : new Error(String(error));
      }
    }
    if (this.config.kind === 'openwrt') return this.scrapeOpenWrt();
    return this.scrapeCompalArp();
  }

  /** Claro/CBN Compal LuCI with RSA login — ubus DHCP when available. */
  private async scrapeRsaLuci(): Promise<RouterLease[]> {
    const luci = new LuciClient({
      baseUrl: this.config.baseUrl,
      username: this.config.username!,
      password: this.config.password!,
      insecureTls: this.config.insecureTls,
      auth: 'compal-rsa',
    });
    const { cookie, sessionId, stok } = await luci.session();
    const ubusLeases = await this.scrapeOpenWrtUbus(luci, cookie, sessionId, stok);
    if (ubusLeases.length) {
      this.logger.info(
        { count: ubusLeases.length, kind: 'compal', via: 'ubus', host: hostLabel(this.config.baseUrl) },
        'router scrape leases',
      );
      return ubusLeases;
    }
    return [];
  }

  /** LuCI 23.x loads leases via ubus; legacy builds embed rows in HTML. */
  private async scrapeOpenWrt(): Promise<RouterLease[]> {
    if (!this.config.username || !this.config.password) {
      throw new Error('OpenWrt scrape requires username and password');
    }
    const luci = new LuciClient({
      baseUrl: this.config.baseUrl,
      username: this.config.username,
      password: this.config.password,
      insecureTls: this.config.insecureTls,
    });
    const { cookie, sessionId } = await luci.session();
    const ubusLeases = await this.scrapeOpenWrtUbus(luci, cookie, sessionId);
    if (ubusLeases.length) {
      this.logger.info({ count: ubusLeases.length, kind: 'openwrt', via: 'ubus', host: hostLabel(this.config.baseUrl) }, 'router scrape leases');
      return ubusLeases;
    }

    const overview = await this.request(
      new URL('/cgi-bin/luci/admin/status/overview', this.config.baseUrl),
      { method: 'GET', headers: { Cookie: cookie } },
    );
    const htmlLeases = this.parseOpenWrtHtml(overview.body);
    this.logger.info({ count: htmlLeases.length, kind: 'openwrt', via: 'html', host: hostLabel(this.config.baseUrl) }, 'router scrape leases');
    return htmlLeases;
  }

  private async scrapeOpenWrtUbus(
    luci: LuciClient,
    cookie: string,
    sessionId: string,
    stok?: string,
  ): Promise<RouterLease[]> {
    const leases = this.parseOpenWrtDhcpLeases(
      await luci.ubusCall(cookie, sessionId, 'luci-rpc', 'getDHCPLeases', { family: 4 }, stok),
    );
    if (leases.length) return leases;
    return this.parseOpenWrtHostHints(
      await luci.ubusCall(cookie, sessionId, 'luci-rpc', 'getHostHints', {}, stok),
    );
  }

  private parseOpenWrtDhcpLeases(payload: unknown): RouterLease[] {
    const rows = ubusResult(payload) as { dhcp_leases?: unknown[] } | null;
    const leases: RouterLease[] = [];
    for (const row of rows?.dhcp_leases ?? []) {
      if (!row || typeof row !== 'object') continue;
      const r = row as Record<string, unknown>;
      const ip = String(r.ipaddr ?? r.ip ?? '');
      const macRaw = String(r.macaddr ?? r.mac ?? '');
      if (!ip || !macRaw) continue;
      const parsed = MacAddress.create(macRaw.replace(/-/g, ':'));
      const hostname = r.hostname ?? r.name;
      leases.push({
        ip,
        mac: isOk(parsed) ? parsed.value.value : null,
        hostname: typeof hostname === 'string' && hostname !== '*' ? hostname : null,
        interface: typeof r.ifname === 'string' ? r.ifname : null,
        description: 'openwrt-dhcp',
        online: true,
      });
    }
    return leases;
  }

  private parseOpenWrtHostHints(payload: unknown): RouterLease[] {
    const hints = ubusResult(payload) as Record<string, { ipaddrs?: string[]; name?: string }> | null;
    const leases: RouterLease[] = [];
    for (const [macRaw, hint] of Object.entries(hints ?? {})) {
      const parsed = MacAddress.create(macRaw.replace(/-/g, ':'));
      for (const ip of hint.ipaddrs ?? []) {
        leases.push({
          ip,
          mac: isOk(parsed) ? parsed.value.value : null,
          hostname: hint.name ?? null,
          interface: null,
          description: 'openwrt-hints',
          online: true,
        });
      }
    }
    return leases;
  }

  private parseOpenWrtHtml(html: string): RouterLease[] {
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
        description: 'openwrt-html',
        online: true,
      });
    }
    return leases;
  }

  private async scrapeCompalArp(): Promise<RouterLease[]> {
    const paths = ['/connected_devices_computers.jst', '/cgi-bin/connected_devices_computers.jst', '/'];
    for (const p of paths) {
      try {
        const html = await this.getText(new URL(p, this.config.baseUrl));
        const leases = this.parseCompalHtml(html);
        if (leases.length) {
          this.logger.info({ count: leases.length, kind: 'compal', path: p, host: hostLabel(this.config.baseUrl) }, 'router scrape leases');
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
    const auth =
      this.config.username && this.config.password
        ? 'Basic ' + Buffer.from(`${this.config.username}:${this.config.password}`).toString('base64')
        : undefined;
    return this.request(url, {
      method: 'GET',
      headers: auth ? { Authorization: auth } : {},
    }).then((res) => {
      if (res.status >= 400) throw new Error(`HTTP ${res.status}`);
      return res.body;
    });
  }

  private request(url: URL, opts: { method: string; headers?: Record<string, string>; body?: string }): Promise<HttpResponse> {
    const isHttps = url.protocol === 'https:';
    const requester = isHttps ? httpsRequest : httpRequest;
    const headers = { ...(opts.headers ?? {}) };
    if (opts.body) headers['Content-Length'] = String(Buffer.byteLength(opts.body));

    return new Promise((resolve, reject) => {
      const req = requester(
        url,
        {
          method: opts.method,
          headers,
          timeout: 8000,
          ...(isHttps ? { rejectUnauthorized: !this.config.insecureTls } : {}),
        },
        (res) => {
          let body = '';
          res.on('data', (c) => (body += c));
          res.on('end', () =>
            resolve({
              status: res.statusCode ?? 500,
              body,
              headers: res.headers as HttpResponse['headers'],
            }),
          );
        },
      );
      req.on('error', reject);
      if (opts.body) req.write(opts.body);
      req.end();
    });
  }
}

function ubusResult(payload: unknown): unknown {
  if (!payload || typeof payload !== 'object') return null;
  const result = (payload as { result?: unknown[] }).result;
  if (!Array.isArray(result) || result.length < 2) return null;
  if (result[0] !== 0) return null;
  return result[1];
}

function hostLabel(baseUrl: string): string {
  try {
    return new URL(baseUrl).hostname.replace(/\./g, '-');
  } catch {
    return 'unknown';
  }
}
