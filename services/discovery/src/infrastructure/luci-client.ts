import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import {
  encryptCompalLuciCredentials,
  jsEncryptCacheKey,
  parseCompalWirelessNetworkIds,
  parseCompalWirelessStatusJson,
} from './compal-luci-crypto.js';

export type LuciAuthMode = 'plain' | 'compal-rsa';

export interface LuciClientConfig {
  baseUrl: string;
  username: string;
  password: string;
  insecureTls?: boolean;
  /** Compal/CBN Claro CPEs require RSA-encrypted login fields. */
  auth?: LuciAuthMode;
}

export interface LuciWirelessSsid {
  device: string;
  ifname: string;
  ssid: string;
  up: boolean;
  mode?: string;
  channel?: number | string;
  disabled?: boolean;
  /** WiFi clients associated to this SSID (Compal wireless_status assoclist). */
  clients?: LuciWifiClient[];
}

export interface LuciWifiClient {
  mac: string;
  signal?: number | null;
}

export interface LuciSession {
  cookie: string;
  sessionId: string;
  /** Compal clarostyle LuCI uses stok in authenticated URLs. */
  stok?: string;
}

interface HttpResponse {
  status: number;
  body: string;
  headers: Record<string, string | string[] | undefined>;
}

const jsEncryptScriptCache = new Map<string, string>();

/** LuCI form login + ubus JSON-RPC (OpenWrt 23.x) or Compal RSA + wireless_status. */
export class LuciClient {
  constructor(private readonly config: LuciClientConfig) {}

  async session(): Promise<LuciSession> {
    if (this.config.auth === 'compal-rsa') return this.sessionCompal();
    return this.sessionPlain();
  }

  async ubusCall(
    cookie: string,
    sessionId: string,
    object: string,
    method: string,
    args: Record<string, unknown>,
    stok?: string,
  ): Promise<unknown> {
    const body = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'call',
      params: [sessionId, object, method, args],
    });
    const res = await this.request(this.luciUrl('/admin/ubus', stok), {
      method: 'POST',
      headers: { Cookie: cookie, 'Content-Type': 'application/json' },
      body,
    });
    if (res.status >= 400) throw new Error(`HTTP ${res.status}`);
    return JSON.parse(res.body || '{}') as unknown;
  }

  async getWirelessSsids(): Promise<LuciWirelessSsid[]> {
    if (this.config.auth === 'compal-rsa') return this.getWirelessSsidsCompal();
    const { cookie, sessionId } = await this.session();
    const payload = await this.ubusCall(cookie, sessionId, 'luci-rpc', 'getWirelessDevices', {});
    const radios = this.ubusResult(payload) as Record<
      string,
      { interfaces?: Record<string, Record<string, unknown>> }
    > | null;
    const ssids: LuciWirelessSsid[] = [];
    for (const [device, info] of Object.entries(radios ?? {})) {
      for (const [ifname, iface] of Object.entries(info.interfaces ?? {})) {
        ssids.push({
          device,
          ifname,
          ssid: String(iface.ssid ?? ''),
          up: Boolean(iface.up),
          mode: iface.mode != null ? String(iface.mode) : undefined,
          channel: iface.channel as number | string | undefined,
          disabled: iface.disabled != null ? Boolean(iface.disabled) : undefined,
        });
      }
    }
    return ssids;
  }

  ubusResult(payload: unknown): unknown {
    if (!payload || typeof payload !== 'object') return null;
    const result = (payload as { result?: unknown[] }).result;
    if (!Array.isArray(result) || result.length < 2) return null;
    if (result[0] !== 0) return null;
    return result[1];
  }

  private async sessionPlain(): Promise<LuciSession> {
    const form = new URLSearchParams({
      luci_username: this.config.username,
      luci_password: this.config.password,
    }).toString();
    const login = await this.request(new URL('/cgi-bin/luci/', this.config.baseUrl), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    });
    const cookie = this.extractCookie(login.headers);
    if (!cookie) throw new Error('OpenWrt login failed (no session cookie)');
    if (login.status >= 400 && login.status !== 302) throw new Error(`HTTP ${login.status}`);

    const overview = await this.request(this.luciUrl('/admin/status/overview'), {
      method: 'GET',
      headers: { Cookie: cookie },
    });
    if (overview.status >= 400) throw new Error(`HTTP ${overview.status}`);
    const sessionId = overview.body.match(/"sessionid":\s*"([^"]+)"/)?.[1];
    if (!sessionId) throw new Error('OpenWrt session id not found');
    return { cookie, sessionId };
  }

  /** Compal/CBN Claro: fetch jsencrypt from device, RSA-encrypt login, capture stok. */
  private async sessionCompal(): Promise<LuciSession> {
    const script = await this.loadJsEncryptScript();
    const { encryptedUsername, encryptedPassword } = encryptCompalLuciCredentials(
      script,
      this.config.username,
      this.config.password,
    );
    const form = new URLSearchParams({
      luci_username: encryptedUsername,
      luci_password: encryptedPassword,
    }).toString();
    const login = await this.request(new URL('/cgi-bin/luci', this.config.baseUrl), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
    });
    const cookie = this.extractSysauthCookie(login.headers);
    if (!cookie) throw new Error('Compal LuCI login failed (no sysauth cookie)');
    if (login.status !== 302 && login.status >= 400) throw new Error(`HTTP ${login.status}`);

    const stok = this.extractStok(login.headers);
    if (!stok) throw new Error('Compal LuCI login failed (no stok in redirect)');

    return { cookie, sessionId: stok, stok };
  }

  private async getWirelessSsidsCompal(): Promise<LuciWirelessSsid[]> {
    const { cookie, stok } = await this.session();
    if (!stok) throw new Error('Compal LuCI stok missing');

    const wirelessPage = await this.request(this.luciUrl('/admin/network/wireless', stok), {
      method: 'GET',
      headers: { Cookie: cookie },
    });
    if (wirelessPage.status >= 400) throw new Error(`HTTP ${wirelessPage.status}`);

    const networkIds = parseCompalWirelessNetworkIds(wirelessPage.body);
    if (!networkIds.length) return [];

    const status = await this.request(
      this.luciUrl(`/admin/network/wireless_status/${networkIds.join(',')}`, stok),
      { method: 'GET', headers: { Cookie: cookie } },
    );
    if (status.status >= 400) throw new Error(`HTTP ${status.status}`);

    let parsed: unknown;
    try {
      parsed = JSON.parse(status.body);
    } catch {
      throw new Error('Compal wireless_status returned invalid JSON');
    }

    return parseCompalWirelessStatusJson(parsed).map((row) => ({
      device: row.device?.device ?? row.id ?? 'wifi',
      ifname: row.ifname ?? row.id ?? '',
      ssid: String(row.ssid ?? ''),
      up: Boolean(row.up) && !row.disabled,
      mode: row.mode,
      channel: row.channel,
      disabled: row.disabled,
      clients: Object.entries(row.assoclist ?? {}).map(([mac, info]) => ({
        mac: mac.toLowerCase().replace(/-/g, ':'),
        signal: info.signal ?? null,
      })),
    }));
  }

  private async loadJsEncryptScript(): Promise<string> {
    const res = await this.request(
      new URL('/luci-static/resources/jsencrypt.min.js', this.config.baseUrl),
      { method: 'GET' },
    );
    if (res.status >= 400 || !res.body.trim()) {
      throw new Error(`Failed to fetch jsencrypt.min.js (HTTP ${res.status})`);
    }
    const cacheKey = jsEncryptCacheKey(this.config.baseUrl, res.body);
    const cached = jsEncryptScriptCache.get(cacheKey);
    if (cached) return cached;
    jsEncryptScriptCache.set(cacheKey, res.body);
    return res.body;
  }

  private luciUrl(path: string, stok?: string): URL {
    const normalized = path.startsWith('/') ? path : `/${path}`;
    if (stok) {
      return new URL(`/cgi-bin/luci/;stok=${stok}${normalized}`, this.config.baseUrl);
    }
    return new URL(`/cgi-bin/luci${normalized}`, this.config.baseUrl);
  }

  private extractStok(headers: HttpResponse['headers']): string | undefined {
    const location = headers.location;
    const raw = Array.isArray(location) ? location[0] : location;
    if (!raw) return undefined;
    return raw.match(/stok=([a-f0-9]+)/i)?.[1];
  }

  private extractSysauthCookie(headers: HttpResponse['headers']): string {
    const raw = headers['set-cookie'];
    const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
    const sysauth = list.find((c) => c.toLowerCase().startsWith('sysauth='));
    return sysauth ? sysauth.split(';')[0]! : '';
  }

  private extractCookie(headers: HttpResponse['headers']): string {
    const raw = headers['set-cookie'];
    const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
    return list.map((c) => c.split(';')[0]).filter(Boolean).join('; ');
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
          timeout: 12000,
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
