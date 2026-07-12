import { createHash, createHmac } from 'node:crypto';
import https from 'node:https';
import type { Logger } from '@netscanner/logger';
import type {
  CloudDeviceIdentity,
  ICloudDeviceIdentityCatalogStore,
  ICloudDeviceIdentitySource,
} from '../domain/cloud-device-identity.js';

/**
 * Fetch over IPv4 only. Node's default Happy Eyeballs often stalls on hosts
 * with broken/unroutable IPv6 (ENETUNREACH) while curl still works.
 */
export async function ipv4Fetch(input: string | URL, init?: RequestInit): Promise<Response> {
  const url = typeof input === 'string' ? new URL(input) : new URL(String(input));
  const method = (init?.method ?? 'GET').toUpperCase();
  const headerBag = new Headers(init?.headers);
  const headers: Record<string, string> = {};
  headerBag.forEach((value, key) => {
    headers[key] = value;
  });
  const signal = init?.signal ?? undefined;

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: url.hostname,
        port: url.port ? Number(url.port) : 443,
        path: `${url.pathname}${url.search}`,
        method,
        family: 4,
        servername: url.hostname,
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve(
            new Response(Buffer.concat(chunks), {
              status: res.statusCode ?? 0,
              statusText: res.statusMessage,
              headers: res.headers as HeadersInit,
            }),
          );
        });
      },
    );

    const onAbort = () => {
      req.destroy();
      reject(signal?.reason instanceof Error ? signal.reason : new Error('aborted'));
    };
    if (signal) {
      if (signal.aborted) {
        onAbort();
        return;
      }
      signal.addEventListener('abort', onAbort, { once: true });
    }

    req.on('error', reject);
    if (typeof init?.body === 'string') req.write(init.body);
    else if (init?.body != null) {
      reject(new Error('ipv4Fetch only supports string bodies'));
      return;
    }
    req.end();
  });
}

export type TuyaDataCenter = 'us' | 'us-e' | 'eu' | 'eu-w' | 'cn' | 'in' | 'sg';

const HOST_BY_DC: Record<TuyaDataCenter, string> = {
  us: 'openapi.tuyaus.com',
  'us-e': 'openapi-ueaz.tuyaus.com',
  eu: 'openapi.tuyaeu.com',
  'eu-w': 'openapi-weaz.tuyaeu.com',
  cn: 'openapi.tuyacn.com',
  in: 'openapi.tuyain.com',
  sg: 'openapi-sg.iotbing.com',
};

export function tuyaApiHost(dc: TuyaDataCenter): string {
  return HOST_BY_DC[dc] ?? HOST_BY_DC.us;
}

/** Normalize MAC to lowercase colon-separated hex. */
export function normalizeTuyaMac(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const hex = raw.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (hex.length !== 12) return null;
  return hex.match(/.{2}/g)!.join(':');
}

/** Cloud list endpoints often return the public WAN IP — useless for LAN matching. */
export function isPrivateLanIp(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip.trim());
}

/**
 * Some Tuya device ids/uuids embed the MAC as a 12-hex suffix
 * (e.g. `84015433ecfabcb249ea` → `ec:fa:bc:b2:49:ea`).
 */
export function extractMacFromTuyaId(id: string | null | undefined): string | null {
  if (!id) return null;
  const m = id.toLowerCase().match(/([0-9a-f]{12})$/);
  return m ? normalizeTuyaMac(m[1]) : null;
}

export interface TuyaCloudIdentityOptions {
  accessId: string;
  accessSecret: string;
  dataCenter?: TuyaDataCenter;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
  /** Optional durable catalog (SQLite); hydrate on start, replaceAll after refresh. */
  store?: ICloudDeviceIdentityCatalogStore;
}

interface TuyaApiEnvelope {
  success?: boolean;
  msg?: string;
  code?: number;
  t?: number;
  result?: unknown;
}

interface RawTuyaDevice {
  id?: string;
  name?: string;
  product_name?: string;
  productName?: string;
  category?: string;
  mac?: string;
  ip?: string;
  online?: boolean;
  local_key?: string;
  localKey?: string;
}

/**
 * Build HMAC-SHA256 signature for Tuya OpenAPI (post–2021 algorithm).
 * Token request: no access_token in string-to-sign header chain.
 */
export function buildTuyaSign(params: {
  accessId: string;
  accessSecret: string;
  timestampMs: number;
  method: string;
  /** Path + query as used for signing, e.g. `/v1.0/token?grant_type=1` */
  pathWithQuery: string;
  body?: string;
  accessToken?: string | null;
}): string {
  const bodyHash = createHash('sha256')
    .update(params.body ?? '', 'utf8')
    .digest('hex');
  const stringToSign =
    `${params.method.toUpperCase()}\n` +
    `${bodyHash}\n` +
    `\n` +
    `${params.pathWithQuery}`;
  const prefix = params.accessToken
    ? `${params.accessId}${params.accessToken}${params.timestampMs}`
    : `${params.accessId}${params.timestampMs}`;
  const payload = prefix + stringToSign;
  return createHmac('sha256', params.accessSecret).update(payload, 'utf8').digest('hex').toUpperCase();
}

/** Strip secrets and map a raw Tuya device row into CloudDeviceIdentity. */
export function parseTuyaDeviceRow(raw: RawTuyaDevice): CloudDeviceIdentity | null {
  const deviceId = typeof raw.id === 'string' ? raw.id.trim() : '';
  if (!deviceId) return null;
  const name = typeof raw.name === 'string' ? raw.name.trim() : '';
  const productName =
    (typeof raw.product_name === 'string' && raw.product_name.trim()) ||
    (typeof raw.productName === 'string' && raw.productName.trim()) ||
    null;
  const category = typeof raw.category === 'string' && raw.category.trim() ? raw.category.trim() : null;
  const mac = normalizeTuyaMac(raw.mac) ?? extractMacFromTuyaId(deviceId);
  const rawIp = typeof raw.ip === 'string' && raw.ip.trim() ? raw.ip.trim() : null;
  const ip = rawIp && isPrivateLanIp(rawIp) ? rawIp : null;
  const online = typeof raw.online === 'boolean' ? raw.online : null;
  return {
    deviceId,
    name: name || productName || deviceId,
    productName,
    category,
    mac,
    ip,
    online,
  };
}

/** Parse `/v1.0/devices/factory-infos` rows into deviceId → MAC. */
export function parseFactoryInfoMacs(result: unknown): Map<string, string> {
  const out = new Map<string, string>();
  const rows = Array.isArray(result) ? result : result && typeof result === 'object' ? [result] : [];
  for (const row of rows) {
    if (!row || typeof row !== 'object') continue;
    const r = row as Record<string, unknown>;
    const id =
      (typeof r.id === 'string' && r.id) ||
      (typeof r.device_id === 'string' && r.device_id) ||
      (typeof r.uuid === 'string' && r.uuid) ||
      '';
    const mac = normalizeTuyaMac(
      (typeof r.mac === 'string' && r.mac) ||
        (typeof r.mac_address === 'string' && r.mac_address) ||
        null,
    );
    if (id && mac) out.set(id, mac);
  }
  return out;
}

/** Index devices by MAC and IP for enrichment lookups. */
export function indexTuyaIdentities(devices: readonly CloudDeviceIdentity[]): {
  byMac: Map<string, CloudDeviceIdentity>;
  byIp: Map<string, CloudDeviceIdentity>;
} {
  const byMac = new Map<string, CloudDeviceIdentity>();
  const byIp = new Map<string, CloudDeviceIdentity>();
  for (const d of devices) {
    if (d.mac) byMac.set(d.mac, d);
    if (d.ip) byIp.set(d.ip, d);
  }
  return { byMac, byIp };
}

/**
 * Read-only Tuya Cloud identity client.
 * Syncs the Smart Life–linked device catalog; never sends control commands
 * and never logs local_key.
 */
export class TuyaCloudIdentityClient implements ICloudDeviceIdentitySource {
  private token: string | null = null;
  private byMac = new Map<string, CloudDeviceIdentity>();
  private byIp = new Map<string, CloudDeviceIdentity>();
  private lastCount = 0;
  private readonly host: string;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(
    private readonly opts: TuyaCloudIdentityOptions,
    private readonly logger: Logger,
  ) {
    this.host = tuyaApiHost(opts.dataCenter ?? 'us');
    this.timeoutMs = opts.timeoutMs ?? 20_000;
    this.fetchImpl = opts.fetchImpl ?? ipv4Fetch;
  }

  lookupByMac(mac: string): CloudDeviceIdentity | null {
    const key = normalizeTuyaMac(mac);
    if (!key) return null;
    return this.byMac.get(key) ?? null;
  }

  lookupByIp(ip: string): CloudDeviceIdentity | null {
    const key = ip.trim();
    if (!key) return null;
    return this.byIp.get(key) ?? null;
  }

  size(): number {
    return this.lastCount;
  }

  /** Load catalog from SQLite (or memory store) without hitting the Tuya API. */
  async hydrate(): Promise<number> {
    const store = this.opts.store;
    if (!store) return 0;
    try {
      const rows = await store.loadAll();
      this.applyIdentities(rows);
      this.logger.info(
        { count: rows.length, withMac: this.byMac.size, withIp: this.byIp.size },
        'Tuya device identity catalog hydrated from store',
      );
      return rows.length;
    } catch (error) {
      this.logger.warn(
        { error: error instanceof Error ? error.message : String(error) },
        'Tuya identity catalog hydrate failed',
      );
      return 0;
    }
  }

  async refresh(): Promise<number> {
    try {
      await this.ensureToken();
      const rows = await this.fetchAllDevices();
      let identities = rows
        .map(parseTuyaDeviceRow)
        .filter((d): d is CloudDeviceIdentity => d != null);
      identities = await this.enrichMacsFromFactoryInfos(identities);
      this.applyIdentities(identities);
      if (this.opts.store) {
        try {
          await this.opts.store.replaceAll(identities);
        } catch (error) {
          this.logger.warn(
            { error: error instanceof Error ? error.message : String(error) },
            'Tuya identity catalog persist failed — memory cache still updated',
          );
        }
      }
      this.logger.info(
        { count: identities.length, withMac: this.byMac.size, withIp: this.byIp.size },
        'Tuya device identity catalog refreshed',
      );
      return identities.length;
    } catch (error) {
      this.logger.warn(
        { error: error instanceof Error ? error.message : String(error) },
        'Tuya identity refresh failed — keeping previous cache',
      );
      return this.lastCount;
    }
  }

  private applyIdentities(identities: readonly CloudDeviceIdentity[]): void {
    const indexed = indexTuyaIdentities(identities);
    this.byMac = indexed.byMac;
    this.byIp = indexed.byIp;
    this.lastCount = identities.length;
  }

  /**
   * Associated-users list rarely includes MAC; factory-infos does.
   * Batch by device id so enrichment can match LAN inventory.
   */
  private async enrichMacsFromFactoryInfos(
    identities: CloudDeviceIdentity[],
  ): Promise<CloudDeviceIdentity[]> {
    const missing = identities.filter((d) => !d.mac).map((d) => d.deviceId);
    if (missing.length === 0) return identities;
    const macById = new Map<string, string>();
    const chunkSize = 20;
    for (let i = 0; i < missing.length; i += chunkSize) {
      const chunk = missing.slice(i, i + chunkSize);
      const path = `/v1.0/devices/factory-infos?device_ids=${chunk.join(',')}`;
      try {
        const env = await this.request(path, 'GET', this.token, path);
        if (!env.success) {
          this.logger.warn(
            { code: env.code, msg: env.msg, chunk: chunk.length },
            'Tuya factory-infos MAC lookup failed',
          );
          continue;
        }
        for (const [id, mac] of parseFactoryInfoMacs(env.result)) {
          macById.set(id, mac);
        }
      } catch (error) {
        this.logger.warn(
          { error: error instanceof Error ? error.message : String(error), chunk: chunk.length },
          'Tuya factory-infos MAC lookup error',
        );
      }
    }
    if (macById.size === 0) return identities;
    return identities.map((d) => (d.mac ? d : { ...d, mac: macById.get(d.deviceId) ?? null }));
  }

  private async ensureToken(): Promise<void> {
    if (this.token) return;
    const path = '/v1.0/token?grant_type=1';
    const env = await this.request(path, 'GET', null);
    if (!env.success || !env.result || typeof env.result !== 'object') {
      throw new Error(env.msg ?? 'Tuya token request failed');
    }
    const access = (env.result as { access_token?: string }).access_token;
    if (!access) throw new Error('Tuya token response missing access_token');
    this.token = access;
  }

  private async fetchAllDevices(): Promise<RawTuyaDevice[]> {
    const out: RawTuyaDevice[] = [];
    let lastRowKey: string | undefined;
    let hasMore = true;
    let pages = 0;
    while (hasMore && pages < 40) {
      pages++;
      let path = '/v1.0/iot-01/associated-users/devices?size=50';
      if (lastRowKey) path += `&last_row_key=${encodeURIComponent(lastRowKey)}`;
      // Signing requires unencoded query values in alphabetical order for custom queries;
      // size-only + optional last_row_key: build sign path without encoding issues.
      const signPath = lastRowKey
        ? `/v1.0/iot-01/associated-users/devices?last_row_key=${lastRowKey}&size=50`
        : '/v1.0/iot-01/associated-users/devices?size=50';
      const env = await this.request(path, 'GET', this.token, signPath);
      if (!env.success) {
        if (env.code === 1010 || /token/i.test(env.msg ?? '')) {
          this.token = null;
          await this.ensureToken();
          continue;
        }
        throw new Error(env.msg ?? `Tuya devices failed (${env.code ?? '?'})`);
      }
      const result = env.result as {
        devices?: RawTuyaDevice[];
        list?: RawTuyaDevice[];
        has_more?: boolean;
        last_row_key?: string;
      } | null;
      const batch = result?.devices ?? result?.list ?? [];
      out.push(...batch);
      hasMore = Boolean(result?.has_more);
      lastRowKey = result?.last_row_key;
      if (!hasMore) break;
    }
    return out;
  }

  private async request(
    pathAndQuery: string,
    method: 'GET',
    accessToken: string | null,
    /** Override path used for HMAC (alphabetical query). */
    signPath: string = pathAndQuery,
  ): Promise<TuyaApiEnvelope> {
    const t = Date.now();
    const sign = buildTuyaSign({
      accessId: this.opts.accessId,
      accessSecret: this.opts.accessSecret,
      timestampMs: t,
      method,
      pathWithQuery: signPath,
      body: '',
      accessToken,
    });
    const headers: Record<string, string> = {
      client_id: this.opts.accessId,
      sign,
      t: String(t),
      sign_method: 'HMAC-SHA256',
      mode: 'cors',
      lang: 'en',
    };
    if (accessToken) headers['access_token'] = accessToken;

    const ctrl = AbortSignal.timeout(this.timeoutMs);
    const res = await this.fetchImpl(`https://${this.host}${pathAndQuery}`, {
      method,
      headers,
      signal: ctrl,
    });
    const text = await res.text();
    let env: TuyaApiEnvelope;
    try {
      env = JSON.parse(text) as TuyaApiEnvelope;
    } catch {
      throw new Error(`Tuya non-JSON response HTTP ${res.status}`);
    }
    return env;
  }
}
