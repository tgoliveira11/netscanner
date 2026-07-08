import type { Logger } from '@netscanner/logger';
import { LuciClient, type LuciWirelessSsid } from './luci-client.js';
import { resolveLuciAuthMode } from './luci-auth-mode.js';

export interface OpenWrtScrapeTarget {
  baseUrl: string;
  kind: 'openwrt' | 'compal';
  username?: string;
  password?: string;
}

export interface OpenWrtWirelessResult {
  url: string;
  host: string;
  ok: boolean;
  error?: string;
  wifiCapable: boolean;
  radioCount: number;
  ssids: LuciWirelessSsid[];
}

export async function probeOpenWrtWireless(
  targets: OpenWrtScrapeTarget[],
  logger: Logger,
): Promise<OpenWrtWirelessResult[]> {
  const results: OpenWrtWirelessResult[] = [];
  for (const target of targets) {
    const host = safeHost(target.baseUrl);
    if (!target.username || !target.password) {
      results.push({
        url: target.baseUrl,
        host,
        ok: false,
        error: 'missing username or password',
        wifiCapable: false,
        radioCount: 0,
        ssids: [],
      });
      continue;
    }
    const auth = resolveLuciAuthMode({ kind: target.kind, username: target.username });
    try {
      const client = new LuciClient({
        baseUrl: target.baseUrl,
        username: target.username,
        password: target.password,
        insecureTls: true,
        auth,
      });
      const ssids = await client.getWirelessSsids();
      const radios = new Set(ssids.map((s) => s.device));
      logger.info(
        { url: target.baseUrl, kind: target.kind, ssids: ssids.length, radios: radios.size },
        'LuCI wireless probe',
      );
      results.push({
        url: target.baseUrl,
        host,
        ok: true,
        wifiCapable: radios.size > 0,
        radioCount: radios.size,
        ssids,
      });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      logger.warn({ url: target.baseUrl, kind: target.kind, error: msg }, 'LuCI wireless probe failed');
      results.push({
        url: target.baseUrl,
        host,
        ok: false,
        error: msg,
        wifiCapable: false,
        radioCount: 0,
        ssids: [],
      });
    }
  }
  return results;
}

function safeHost(baseUrl: string): string {
  try {
    return new URL(baseUrl).hostname;
  } catch {
    return baseUrl;
  }
}
