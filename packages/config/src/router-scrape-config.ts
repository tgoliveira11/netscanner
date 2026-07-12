import type { AppConfig } from './env-schema.js';

export interface RouterScrapeTarget {
  baseUrl: string;
  kind: 'openwrt' | 'compal';
  username?: string;
  password?: string;
}

/** Compal credentials without a fixed management IP (bound at runtime via discovery). */
export interface FloatingCompalCredential {
  username: string;
  password: string;
}

export interface DeviceRouterScrapeInput {
  ip: string;
  mac?: string | null;
  deviceType: string;
  brand?: string | null;
  hostname?: string | null;
  isOnline?: boolean;
  routerScrapeUser?: string | null;
  routerScrapePassword?: string | null;
}

/** Parse `url|kind|user|password` or identity `compal|user|password` (no fixed IP). */
export function parseRouterScrapeTargetsLine(raw: string): RouterScrapeTarget[] {
  const out: RouterScrapeTarget[] = [];
  for (const entry of raw.split(';')) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const parts = trimmed.split('|');
    if (parts.length < 2) continue;

    // Identity form: compal|CLARO_xxxxxx|password  (IP comes from discovery)
    if (parts[0]!.trim().toLowerCase() === 'compal' && parts.length >= 3) {
      const username = parts[1]?.trim();
      const password = parts.slice(2).join('|').trim();
      if (!username || !password) continue;
      out.push({
        baseUrl: '',
        kind: 'compal',
        username,
        password,
      });
      continue;
    }

    const baseUrl = parts[0]!.trim();
    const kindRaw = parts[1]!.trim().toLowerCase();
    if (kindRaw !== 'openwrt' && kindRaw !== 'compal') continue;
    const username = parts[2]?.trim() || undefined;
    const password = parts.length > 3 ? parts.slice(3).join('|').trim() : undefined;
    if (!baseUrl) continue;
    out.push({ baseUrl, kind: kindRaw, username, password });
  }
  return out;
}

/** Admin UI: one target per line (`url|kind|user|password` or `compal|user|password`). */
export function formatRouterScrapeTargetsForAdmin(raw: string | undefined | null): string {
  if (!raw?.trim()) return '';
  return raw
    .split(';')
    .map((line) => line.trim())
    .filter(Boolean)
    .join('\n');
}

/** Normalize admin multiline input back to semicolon-separated storage. */
export function normalizeRouterScrapeTargetsInput(raw: string): string {
  const lines = raw
    .split(/\r?\n/)
    .flatMap((line) => line.split(';'))
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
  return lines.join(';');
}

function normalizeUrl(baseUrl: string): string {
  return baseUrl.replace(/\/$/, '');
}

/** Last 6 hex chars of a MAC (`b4:f2:67:21:a4:69` → `21A469`). */
export function macTailHex(mac: string | null | undefined): string {
  if (!mac) return '';
  return mac.replace(/[^0-9a-f]/gi, '').slice(-6).toUpperCase();
}

/** True when inventory row looks like a Compal/CBN AP. */
export function isCompalLikeDevice(device: DeviceRouterScrapeInput): boolean {
  if (defaultScrapeKind(device) === 'compal') return true;
  const brand = device.brand?.toLowerCase() ?? '';
  return brand.includes('compal');
}

function defaultScrapeKind(device: DeviceRouterScrapeInput): 'openwrt' | 'compal' {
  const brand = device.brand?.toLowerCase() ?? '';
  if (brand.includes('compal')) return 'compal';
  const host = device.hostname?.toUpperCase() ?? '';
  if (host.startsWith('CBN_RE_') || host.startsWith('CBN_')) return 'compal';
  const user = device.routerScrapeUser?.trim() ?? '';
  if (/^(CLARO_|ISP_|CBN_)/i.test(user)) return 'compal';
  return 'openwrt';
}

/** Match CLARO_/ISP_ username (or hostname suffix) to a discovered device MAC/hostname. */
export function credentialMatchesDevice(username: string, device: DeviceRouterScrapeInput): boolean {
  const u = username.trim().toUpperCase();
  if (!u) return false;
  if (device.routerScrapeUser && device.routerScrapeUser.trim().toUpperCase() === u) return true;

  const tail = macTailHex(device.mac);
  if (tail && (u === `CLARO_${tail}` || u === `ISP_${tail}` || u === `CBN_${tail}` || u.endsWith(tail))) {
    return true;
  }

  const host = device.hostname?.toUpperCase() ?? '';
  const hostTail = host.includes('_') ? host.split('_').pop() ?? '' : '';
  if (hostTail.length >= 6 && (u.endsWith(hostTail) || u === `CLARO_${hostTail}`)) return true;

  return false;
}

/**
 * Fixed-URL targets from env (OpenWrt switches, etc.).
 * Compal entries with URLs are intentionally omitted here — they bind via discovery.
 */
export function resolveRouterScrapeTargets(config: AppConfig): RouterScrapeTarget[] {
  const byUrl = new Map<string, RouterScrapeTarget>();

  const multi = config.ROUTER_SCRAPE_TARGETS?.trim();
  if (multi) {
    for (const t of parseRouterScrapeTargetsLine(multi)) {
      if (t.kind === 'compal') continue; // floating — see extractFloatingCompalCredentials
      if (!t.baseUrl) continue;
      byUrl.set(normalizeUrl(t.baseUrl), t);
    }
  }

  if (config.ROUTER_SCRAPE_URL && config.ROUTER_SCRAPE_KIND) {
    if (config.ROUTER_SCRAPE_KIND === 'compal') {
      // Single-field Compal is also floating; no fixed URL binding.
    } else {
      const baseUrl = normalizeUrl(config.ROUTER_SCRAPE_URL);
      byUrl.set(baseUrl, {
        baseUrl,
        kind: config.ROUTER_SCRAPE_KIND,
        username: config.ROUTER_SCRAPE_USER,
        password: config.ROUTER_SCRAPE_PASSWORD,
      });
    }
  }

  return [...byUrl.values()];
}

/** Compal user/password pairs from env (identity form or legacy URL|compal|… lines). */
export function extractFloatingCompalCredentials(config: AppConfig): FloatingCompalCredential[] {
  const out: FloatingCompalCredential[] = [];
  const seen = new Set<string>();

  const push = (username?: string, password?: string) => {
    const u = username?.trim();
    const p = password?.trim();
    if (!u || !p) return;
    const key = u.toUpperCase();
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ username: u, password: p });
  };

  const multi = config.ROUTER_SCRAPE_TARGETS?.trim();
  if (multi) {
    for (const t of parseRouterScrapeTargetsLine(multi)) {
      if (t.kind !== 'compal') continue;
      push(t.username, t.password);
    }
  }

  if (config.ROUTER_SCRAPE_KIND === 'compal') {
    push(config.ROUTER_SCRAPE_USER, config.ROUTER_SCRAPE_PASSWORD);
  }

  return out;
}

/**
 * Merge env OpenWrt targets with discovery-bound Compal (and per-device) credentials.
 * Compal management IPs always come from inventory `device.ip` — never from fixed env URLs.
 */
export function mergeRouterScrapeTargets(
  config: AppConfig,
  devices: DeviceRouterScrapeInput[],
): RouterScrapeTarget[] {
  const byUrl = new Map<string, RouterScrapeTarget>();
  for (const t of resolveRouterScrapeTargets(config)) {
    byUrl.set(normalizeUrl(t.baseUrl), t);
  }

  const floating = extractFloatingCompalCredentials(config);

  for (const device of devices) {
    if (!device.ip?.trim()) continue;

    let username = device.routerScrapeUser?.trim() || undefined;
    let password = device.routerScrapePassword?.trim() || undefined;
    let kind = defaultScrapeKind(device);

    if ((!username || !password) && (kind === 'compal' || isCompalLikeDevice(device))) {
      const cred = floating.find((c) => credentialMatchesDevice(c.username, device));
      if (cred) {
        username = cred.username;
        password = cred.password;
        kind = 'compal';
      }
    }

    if (!username || !password) continue;

    // Prefer online Compals when duplicates exist; still allow offline with creds.
    const baseUrl = normalizeUrl(`http://${device.ip}`);
    const existing = byUrl.get(baseUrl);
    if (existing?.kind === 'openwrt' && kind === 'compal') {
      // Don't overwrite a fixed OpenWrt URL with Compal on the same IP.
      continue;
    }
    byUrl.set(baseUrl, {
      baseUrl,
      kind: existing?.kind === 'compal' || kind === 'compal' ? 'compal' : (existing?.kind ?? kind),
      username,
      password,
    });
  }

  return [...byUrl.values()];
}
