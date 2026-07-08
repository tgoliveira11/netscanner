import type { AppConfig } from './env-schema.js';

export interface RouterScrapeTarget {
  baseUrl: string;
  kind: 'openwrt' | 'compal';
  username?: string;
  password?: string;
}

export interface DeviceRouterScrapeInput {
  ip: string;
  deviceType: string;
  brand?: string | null;
  routerScrapeUser?: string | null;
  routerScrapePassword?: string | null;
}

/** Parse `url|kind|user|password` entries separated by `;`. Password may contain `|`. */
export function parseRouterScrapeTargetsLine(raw: string): RouterScrapeTarget[] {
  const out: RouterScrapeTarget[] = [];
  for (const entry of raw.split(';')) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const parts = trimmed.split('|');
    if (parts.length < 2) continue;
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

function normalizeUrl(baseUrl: string): string {
  return baseUrl.replace(/\/$/, '');
}

/** All router scrape targets from env config only. */
export function resolveRouterScrapeTargets(config: AppConfig): RouterScrapeTarget[] {
  const byUrl = new Map<string, RouterScrapeTarget>();

  const multi = config.ROUTER_SCRAPE_TARGETS?.trim();
  if (multi) {
    for (const t of parseRouterScrapeTargetsLine(multi)) {
      byUrl.set(normalizeUrl(t.baseUrl), t);
    }
  }

  if (config.ROUTER_SCRAPE_URL && config.ROUTER_SCRAPE_KIND) {
    const baseUrl = normalizeUrl(config.ROUTER_SCRAPE_URL);
    byUrl.set(baseUrl, {
      baseUrl,
      kind: config.ROUTER_SCRAPE_KIND,
      username: config.ROUTER_SCRAPE_USER,
      password: config.ROUTER_SCRAPE_PASSWORD,
    });
  }

  return [...byUrl.values()];
}

function defaultScrapeKind(_device: DeviceRouterScrapeInput): 'openwrt' | 'compal' {
  return 'openwrt';
}

/** Merge env targets with per-device credentials (device wins for same URL). */
export function mergeRouterScrapeTargets(
  config: AppConfig,
  devices: DeviceRouterScrapeInput[],
): RouterScrapeTarget[] {
  const byUrl = new Map<string, RouterScrapeTarget>();
  for (const t of resolveRouterScrapeTargets(config)) {
    byUrl.set(normalizeUrl(t.baseUrl), t);
  }

  for (const device of devices) {
    if (!device.routerScrapeUser || !device.routerScrapePassword) continue;
    const baseUrl = normalizeUrl(`http://${device.ip}`);
    byUrl.set(baseUrl, {
      baseUrl,
      kind: defaultScrapeKind(device),
      username: device.routerScrapeUser,
      password: device.routerScrapePassword,
    });
  }

  return [...byUrl.values()];
}
