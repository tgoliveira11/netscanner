import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import {
  encryptCompalLuciCredentials,
  jsEncryptCacheKey,
  parseCompalWirelessNetworkIds,
  parseCompalWirelessStatusJson,
  parseCompalWirelessStatusBody,
} from './compal-luci-crypto.js';
import { buildCompalMeshForm, parseCompalMeshEnabled } from './compal-luci-forms.js';
import { parseCompalSystemStatus, type CompalSystemStatus } from './compal-status.js';

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

export interface LuciWifiNeighbor {
  ssid: string;
  bssid?: string;
  channel?: number;
  rssi?: number;
  security?: string;
  device: string;
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
  private sessionCache: { at: number; value: LuciSession } | null = null;
  private static readonly sessionTtlMs = 45_000;

  constructor(private readonly config: LuciClientConfig) {}

  clearSession(): void {
    this.sessionCache = null;
  }

  async session(): Promise<LuciSession> {
    if (
      this.sessionCache &&
      Date.now() - this.sessionCache.at < LuciClient.sessionTtlMs
    ) {
      return this.sessionCache.value;
    }
    try {
      const value =
        this.config.auth === 'compal-rsa'
          ? await this.sessionCompal()
          : await this.sessionPlain();
      this.sessionCache = { at: Date.now(), value };
      return value;
    } catch (error) {
      this.sessionCache = null;
      throw error;
    }
  }

  async ubusCall(
    cookie: string,
    sessionId: string,
    object: string,
    method: string,
    args: Record<string, unknown>,
    stok?: string,
    timeoutMs = 12_000,
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
      timeoutMs,
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

  /** Active Wi‑Fi scan from the router/AP radio (OpenWrt iwinfo ubus). */
  async scanWifiNeighbors(): Promise<LuciWifiNeighbor[]> {
    const { cookie, sessionId, stok } = await this.session();
    let devices = await this.listIwinfoDevices(cookie, sessionId, stok);
    if (!devices.length) {
      const ssids = await this.getWirelessSsids();
      devices = [
        ...new Set(
          ssids.flatMap((s) => [s.device, s.ifname]).filter((d): d is string => Boolean(d)),
        ),
      ];
    }
    const picked = pickScanDevices(devices);
    const out: LuciWifiNeighbor[] = [];
    const seen = new Set<string>();
    const errors: string[] = [];
    for (const device of picked) {
      try {
        const payload = await this.ubusCall(cookie, sessionId, 'iwinfo', 'scan', { device }, stok, 30_000);
        const body = this.ubusResult(payload) as { results?: unknown[] } | unknown[] | null;
        const rows = Array.isArray(body) ? body : (body?.results ?? []);
        for (const row of rows) {
          const parsed = parseIwinfoScanRow(row, device);
          if (!parsed) continue;
          const key = parsed.bssid ?? `${parsed.ssid}|${parsed.channel}|${parsed.device}`;
          if (seen.has(key)) continue;
          seen.add(key);
          out.push(parsed);
        }
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        errors.push(`${device}: ${msg}`);
      }
    }
    if (!out.length && errors.length) {
      throw new Error(`iwinfo scan failed (${errors.join('; ')})`);
    }
    return out;
  }

  private async listIwinfoDevices(cookie: string, sessionId: string, stok?: string): Promise<string[]> {
    try {
      const payload = await this.ubusCall(cookie, sessionId, 'iwinfo', 'devices', {}, stok);
      const result = this.ubusResult(payload);
      if (Array.isArray(result)) return result.filter((d): d is string => typeof d === 'string');
      if (result && typeof result === 'object') return Object.keys(result as Record<string, unknown>);
    } catch {
      /* iwinfo not exposed */
    }
    return [];
  }

  ubusResult(payload: unknown): unknown {
    if (!payload || typeof payload !== 'object') return null;
    const result = (payload as { result?: unknown[] }).result;
    if (!Array.isArray(result) || result.length < 2) return null;
    if (result[0] !== 0) return null;
    return result[1];
  }

  /** Authenticated GET for Compal/OpenWrt LuCI admin pages. */
  async fetchAdminPage(path: string): Promise<string> {
    const { cookie, stok } = await this.session();
    const res = await this.request(this.luciUrl(path, stok), {
      method: 'GET',
      headers: { Cookie: cookie },
      timeoutMs: 30_000,
    });
    if (res.status >= 400) throw new Error(`HTTP ${res.status}`);
    return res.body;
  }

  /** Authenticated POST for LuCI CBI forms (Compal clarostyle). */
  async postAdminPage(path: string, fields: Record<string, string>): Promise<string> {
    const { cookie, stok } = await this.session();
    const body = new URLSearchParams(fields).toString();
    const res = await this.request(this.luciUrl(path, stok), {
      method: 'POST',
      headers: { Cookie: cookie, 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      timeoutMs: 45_000,
    });
    if (res.status >= 400) throw new Error(`HTTP ${res.status}`);
    return res.body;
  }

  /** Read Compal mesh Wi‑Fi toggle (null when page/field missing or AP busy). */
  async getCompalMeshEnabled(): Promise<boolean | null> {
    if (this.config.auth !== 'compal-rsa') return null;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const html = await this.fetchAdminPage('/admin/network/mesh_wifi');
        const parsed = parseCompalMeshEnabled(html);
        if (parsed != null) return parsed;
      } catch {
        this.clearSession();
      }
      if (attempt < 2) await sleep(2000);
    }
    return null;
  }

  /** Enable/disable Compal mesh Wi‑Fi (LuCI CBI form). */
  async setCompalMeshEnabled(enabled: boolean): Promise<void> {
    if (this.config.auth !== 'compal-rsa') throw new Error('Compal LuCI only');
    const html = await this.fetchAdminPage('/admin/network/mesh_wifi');
    const fields = buildCompalMeshForm(html, enabled);
    await this.postAdminPage('/admin/network/mesh_wifi', fields);
  }

  /** Reboot Compal device — LuCI uses GET `/admin/system/reboot?reboot=1` (link on reboot page). */
  async rebootCompal(): Promise<void> {
    if (this.config.auth !== 'compal-rsa') throw new Error('Compal LuCI only');
    const { cookie, stok } = await this.session();
    const url = this.luciUrl('/admin/system/reboot', stok);
    url.searchParams.set('reboot', '1');
    try {
      await this.request(url, {
        method: 'GET',
        headers: { Cookie: cookie },
        timeoutMs: 15_000,
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      // Connection drop while the AP reboots is expected.
      if (/ECONNRESET|ECONNREFUSED|EHOSTUNREACH|ETIMEDOUT|socket hang up|aborted/i.test(msg)) return;
      throw error;
    }
  }

  /** Compal status overview JSON (`/admin/status?status=1`) — uptime, load, memory. */
  async getCompalSystemStatus(): Promise<CompalSystemStatus | null> {
    if (this.config.auth !== 'compal-rsa') return null;
    const { cookie, stok } = await this.session();
    const url = this.luciUrl('/admin/status', stok);
    url.searchParams.set('status', '1');
    const res = await this.request(url, {
      method: 'GET',
      headers: { Cookie: cookie },
      timeoutMs: 15_000,
    });
    if (res.status >= 400) throw new Error(`HTTP ${res.status}`);
    return parseCompalSystemStatus(res.body);
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

  /**
   * Build RSA-encrypted LuCI login fields for a same-network browser SSO bounce.
   * The browser POSTs these to the AP so Set-Cookie lands on the AP origin (no proxy).
   */
  async prepareCompalBrowserLogin(): Promise<{
    actionUrl: string;
    fields: { luci_username: string; luci_password: string };
  }> {
    if (this.config.auth !== 'compal-rsa') throw new Error('Compal LuCI only');
    const script = await this.loadJsEncryptScript();
    const { encryptedUsername, encryptedPassword } = encryptCompalLuciCredentials(
      script,
      this.config.username,
      this.config.password,
    );
    return {
      actionUrl: new URL('/cgi-bin/luci', this.config.baseUrl).toString(),
      fields: {
        luci_username: encryptedUsername,
        luci_password: encryptedPassword,
      },
    };
  }

  /** Compal/CBN Claro: fetch jsencrypt from device, RSA-encrypt login, capture stok. */
  private async sessionCompal(): Promise<LuciSession> {
    const prepared = await this.prepareCompalBrowserLogin();
    const form = new URLSearchParams(prepared.fields).toString();
    const login = await this.request(new URL(prepared.actionUrl), {
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
    return this.fetchCompalWirelessSsidsWithRetry();
  }

  private async fetchCompalWirelessSsidsWithRetry(attempt = 0): Promise<LuciWirelessSsid[]> {
    try {
      return await this.fetchCompalWirelessSsidsOnce();
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      const retryable =
        /invalid JSON|HTTP 40[13]|login|sysauth|ECONNRESET|ETIMEDOUT|socket hang up/i.test(msg);
      if (attempt < 1 && retryable) {
        await sleep(1500);
        return this.fetchCompalWirelessSsidsWithRetry(attempt + 1);
      }
      throw error;
    }
  }

  private async fetchCompalWirelessSsidsOnce(): Promise<LuciWirelessSsid[]> {
    const { cookie, stok } = await this.session();
    if (!stok) throw new Error('Compal LuCI stok missing');

    const wirelessPage = await this.request(this.luciUrl('/admin/network/wireless', stok), {
      method: 'GET',
      headers: { Cookie: cookie },
      timeoutMs: 25_000,
    });
    if (wirelessPage.status >= 400) throw new Error(`HTTP ${wirelessPage.status}`);

    const networkIds = parseCompalWirelessNetworkIds(wirelessPage.body);
    if (!networkIds.length) return [];

    const parsed = await this.fetchCompalWirelessStatusJson(networkIds, cookie, stok);
    if (parsed == null) {
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

  private async fetchCompalWirelessStatusJson(
    networkIds: string[],
    cookie: string,
    stok: string,
  ): Promise<unknown | null> {
    const joined = networkIds.join(',');
    const batch = await this.request(
      this.luciUrl(`/admin/network/wireless_status/${joined}`, stok),
      { method: 'GET', headers: { Cookie: cookie }, timeoutMs: 30_000 },
    );
    if (batch.status < 400) {
      const parsed = parseCompalWirelessStatusBody(batch.body);
      if (parsed != null) return parsed;
    }

    const merged: unknown[] = [];
    for (const id of networkIds) {
      try {
        const single = await this.request(
          this.luciUrl(`/admin/network/wireless_status/${id}`, stok),
          { method: 'GET', headers: { Cookie: cookie }, timeoutMs: 20_000 },
        );
        if (single.status >= 400) continue;
        const parsed = parseCompalWirelessStatusBody(single.body);
        if (Array.isArray(parsed)) merged.push(...parsed);
        else if (parsed && typeof parsed === 'object') merged.push(parsed);
      } catch {
        /* skip radio */
      }
    }
    return merged.length ? merged : null;
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

  private request(
    url: URL,
    opts: { method: string; headers?: Record<string, string>; body?: string; timeoutMs?: number },
  ): Promise<HttpResponse> {
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
          timeout: opts.timeoutMs ?? 12_000,
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function pickScanDevices(devices: string[]): string[] {
  const unique = [...new Set(devices.filter(Boolean))];
  if (unique.length <= 4) return unique;
  const prefer = unique.filter((d) => /^(wlan|phy|wifi|ath|ra|rax|rai)\d/i.test(d));
  return (prefer.length ? prefer : unique).slice(0, 4);
}

function parseIwinfoScanRow(row: unknown, device: string): LuciWifiNeighbor | null {
  if (!row || typeof row !== 'object') return null;
  const r = row as Record<string, unknown>;
  const ssid = String(r.ssid ?? r.SSID ?? '').trim();
  if (!ssid) return null;
  const bssid = r.bssid != null ? String(r.bssid) : r.BSSID != null ? String(r.BSSID) : undefined;
  const channelRaw = r.channel ?? r.Channel;
  const channel =
    typeof channelRaw === 'number'
      ? channelRaw
      : typeof channelRaw === 'string'
        ? Number(channelRaw.match(/(\d+)/)?.[1])
        : undefined;
  const signalRaw = r.signal ?? r.Signal ?? r.rssi;
  const rssi =
    typeof signalRaw === 'number'
      ? signalRaw
      : typeof signalRaw === 'string'
        ? Number(signalRaw.match(/(-?\d+)/)?.[1])
        : undefined;
  const enc = r.encryption ?? r.Encryption;
  let security: string | undefined;
  if (typeof enc === 'string') security = enc;
  else if (enc && typeof enc === 'object') {
    const e = enc as Record<string, unknown>;
    security = [e.enabled, e.wpa, e.authentication, e.ciphers]
      .filter((x) => x != null && x !== false && x !== '')
      .map(String)
      .join(' ') || undefined;
  }
  return {
    ssid,
    bssid,
    channel: Number.isFinite(channel) ? channel : undefined,
    rssi: Number.isFinite(rssi) ? rssi : undefined,
    security,
    device,
  };
}
