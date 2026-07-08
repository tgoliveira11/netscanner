import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { NetworkFingerprint } from '@netscanner/contracts';
import { detectPrimaryCidr, isIgnoredScanCidr, listLocalInterfaces, listScanCidrs } from './local-network.js';

const execFileAsync = promisify(execFile);

function normalizeMac(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const hex = raw.replace(/[^0-9a-f]/gi, '').toLowerCase();
  if (hex.length !== 12) return null;
  return hex.match(/.{2}/g)!.join(':');
}

/** Parse default gateway IPv4 from `netstat -rn` (macOS/Linux). */
export async function detectDefaultGatewayIp(): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync('netstat', ['-rn'], { timeout: 5000 });
    for (const line of stdout.split('\n')) {
      if (!/default|0\.0\.0\.0/.test(line)) continue;
      const parts = line.trim().split(/\s+/);
      const gw = parts.find((p) => /^\d+\.\d+\.\d+\.\d+$/.test(p));
      if (gw && gw !== '0.0.0.0') return gw;
    }
  } catch {
    /* ignore */
  }
  return null;
}

/** Resolve gateway L2 address via ARP table. */
export async function resolveGatewayMac(gatewayIp: string): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync('arp', ['-n', gatewayIp], { timeout: 5000 });
    const match = stdout.match(/\(([0-9a-f:]{17})\)/i) ?? stdout.match(/([0-9a-f]{2}(:[0-9a-f]{2}){5})/i);
    return normalizeMac(match?.[1] ?? null);
  } catch {
    return null;
  }
}

/** True when tunnel/VPN interfaces carry the default route or primary CIDR is an overlay. */
export function detectVpnActive(primaryCidr: string | null, gatewayIp: string | null): boolean {
  const ifaces = listLocalInterfaces();
  const tunnelDefault = ifaces.some(
    (i) => /^(utun|tun|wg|ppp)/i.test(i.name) && i.address === gatewayIp,
  );
  if (tunnelDefault) return true;
  if (primaryCidr && isIgnoredScanCidr(primaryCidr)) return true;
  return ifaces.some((i) => /^(utun|tun|wg)/i.test(i.name));
}

/** Read DNS servers from macOS scutil (best effort). */
export async function detectDnsServers(): Promise<string[]> {
  try {
    const { stdout } = await execFileAsync('scutil', ['--dns'], { timeout: 5000 });
    const servers = new Set<string>();
    for (const line of stdout.split('\n')) {
      const m = line.match(/nameserver\s*\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)/i);
      if (m?.[1]) servers.add(m[1]);
    }
    return [...servers];
  } catch {
    return [];
  }
}

/** Current Wi‑Fi SSID + nearby SSIDs (macOS). */
export async function detectWifiSsids(): Promise<string[]> {
  const ssids = new Set<string>();
  const airport =
    '/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport';

  try {
    const { stdout } = await execFileAsync('networksetup', ['-getairportnetwork', 'en0'], {
      timeout: 5000,
    });
    const cur = stdout.match(/:\s*(.+)$/);
    if (cur?.[1]?.trim()) ssids.add(cur[1].trim());
  } catch {
    /* ignore */
  }

  try {
    const { stdout } = await execFileAsync(airport, ['-s'], { timeout: 8000 });
    for (const line of stdout.split('\n').slice(1)) {
      const ssid = line.trim().split(/\s{2,}/)[0]?.trim();
      if (ssid && ssid !== 'SSID') ssids.add(ssid);
    }
  } catch {
    /* ignore */
  }

  return [...ssids].slice(0, 32);
}

export async function fetchPublicIp(): Promise<string | null> {
  try {
    const res = await fetch('https://api.ipify.org?format=json', { signal: AbortSignal.timeout(5000) });
    if (!res.ok) return null;
    const body = (await res.json()) as { ip?: string };
    return body.ip ?? null;
  } catch {
    return null;
  }
}

export async function fetchGeoForIp(ip: string): Promise<{
  lat: number | null;
  lon: number | null;
  label: string | null;
}> {
  try {
    const res = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=lat,lon,city,country`, {
      signal: AbortSignal.timeout(5000,
      ),
    });
    if (!res.ok) return { lat: null, lon: null, label: null };
    const body = (await res.json()) as { lat?: number; lon?: number; city?: string; country?: string };
    const label = [body.city, body.country].filter(Boolean).join(', ') || null;
    return { lat: body.lat ?? null, lon: body.lon ?? null, label };
  } catch {
    return { lat: null, lon: null, label: null };
  }
}

export interface CollectObservationOptions {
  extraCidrs?: string;
  routerId?: string | null;
  includeGeo?: boolean;
}

/** Snapshot of the currently attached network for site matching. */
export async function collectNetworkObservation(
  opts: CollectObservationOptions = {},
): Promise<NetworkFingerprint> {
  const primaryCidr = detectPrimaryCidr();
  const cidrs = listScanCidrs(opts.extraCidrs ?? '');
  const gatewayIp = await detectDefaultGatewayIp();
  const gatewayMac = gatewayIp ? await resolveGatewayMac(gatewayIp) : null;
  const dnsServers = await detectDnsServers();
  const ssids = await detectWifiSsids();
  const vpnDetected = detectVpnActive(primaryCidr, gatewayIp);

  let publicIp: string | null = null;
  let geoLat: number | null = null;
  let geoLon: number | null = null;
  let geoLabel: string | null = null;

  if (opts.includeGeo !== false && !vpnDetected) {
    publicIp = await fetchPublicIp();
    if (publicIp) {
      const geo = await fetchGeoForIp(publicIp);
      geoLat = geo.lat;
      geoLon = geo.lon;
      geoLabel = geo.label;
    }
  }

  return {
    gatewayIp,
    gatewayMac,
    cidrs,
    dnsServers,
    routerId: opts.routerId ?? null,
    publicIp,
    geoLat,
    geoLon,
    geoLabel,
    ssids,
    vpnDetected,
    collectedAt: new Date().toISOString(),
  };
}
