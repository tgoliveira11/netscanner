import type { Logger } from '@netscanner/logger';
import { LuciClient, type LuciWifiNeighbor, type LuciWirelessSsid } from './luci-client.js';
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

/** Soft ceiling per AP so one hung Compal cannot stall topology/admin probes. */
const PER_TARGET_TIMEOUT_MS = 8_000;

export async function probeOpenWrtWifiNeighbors(
  targets: OpenWrtScrapeTarget[],
  logger: Logger,
): Promise<{ url: string; neighbors: LuciWifiNeighbor[] }[]> {
  const results: { url: string; neighbors: LuciWifiNeighbor[] }[] = [];
  for (const target of targets) {
    if (!target.username || !target.password) {
      results.push({ url: target.baseUrl, neighbors: [] });
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
      const neighbors = await client.scanWifiNeighbors();
      logger.info({ url: target.baseUrl, kind: target.kind, neighbors: neighbors.length }, 'AP Wi‑Fi neighbor scan');
      results.push({ url: target.baseUrl, neighbors });
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      logger.warn({ url: target.baseUrl, kind: target.kind, error: msg }, 'AP Wi‑Fi neighbor scan failed');
      results.push({ url: target.baseUrl, neighbors: [] });
    }
  }
  return results;
}

export async function probeOpenWrtWireless(
  targets: OpenWrtScrapeTarget[],
  logger: Logger,
): Promise<OpenWrtWirelessResult[]> {
  // Parallel with per-target timeout — sequential Compal ETIMEDOUT previously blocked /api/topology for minutes.
  return Promise.all(targets.map((target) => probeOneWirelessTarget(target, logger)));
}

async function probeOneWirelessTarget(
  target: OpenWrtScrapeTarget,
  logger: Logger,
): Promise<OpenWrtWirelessResult> {
  const host = safeHost(target.baseUrl);
  if (!target.username || !target.password) {
    return {
      url: target.baseUrl,
      host,
      ok: false,
      error: 'missing username or password',
      wifiCapable: false,
      radioCount: 0,
      ssids: [],
    };
  }

  const auth = resolveLuciAuthMode({ kind: target.kind, username: target.username });
  const work = (async (): Promise<OpenWrtWirelessResult> => {
    const client = new LuciClient({
      baseUrl: target.baseUrl,
      username: target.username!,
      password: target.password!,
      insecureTls: true,
      auth,
    });
    const ssids = await client.getWirelessSsids();
    const radios = new Set(ssids.map((s) => s.device));
    logger.info(
      { url: target.baseUrl, kind: target.kind, ssids: ssids.length, radios: radios.size },
      'LuCI wireless probe',
    );
    return {
      url: target.baseUrl,
      host,
      ok: true,
      wifiCapable: radios.size > 0,
      radioCount: radios.size,
      ssids,
    };
  })();

  try {
    return await Promise.race([
      work,
      sleep(PER_TARGET_TIMEOUT_MS).then(
        (): OpenWrtWirelessResult => ({
          url: target.baseUrl,
          host,
          ok: false,
          error: `timeout after ${PER_TARGET_TIMEOUT_MS}ms`,
          wifiCapable: false,
          radioCount: 0,
          ssids: [],
        }),
      ),
    ]);
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    logger.warn({ url: target.baseUrl, kind: target.kind, error: msg }, 'LuCI wireless probe failed');
    return {
      url: target.baseUrl,
      host,
      ok: false,
      error: msg,
      wifiCapable: false,
      radioCount: 0,
      ssids: [],
    };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function safeHost(baseUrl: string): string {
  try {
    return new URL(baseUrl).hostname;
  } catch {
    return baseUrl;
  }
}
