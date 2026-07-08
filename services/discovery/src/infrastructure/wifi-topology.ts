import type { Device } from '@netscanner/contracts';
import type { OpenWrtWirelessResult } from './openwrt-wireless-probe.js';

export interface WifiAssociation {
  mac: string;
  ssid: string;
  routerHost: string;
  signal?: number | null;
}

export function normalizeMac(mac: string | null | undefined): string | null {
  if (!mac) return null;
  const cleaned = mac.trim().toLowerCase().replace(/-/g, ':');
  return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(cleaned) ? cleaned : null;
}

/** Flatten wireless probe results into MAC → router + SSID associations. */
export function extractWifiAssociations(results: OpenWrtWirelessResult[]): WifiAssociation[] {
  const out: WifiAssociation[] = [];
  for (const router of results) {
    if (!router.ok) continue;
    for (const iface of router.ssids) {
      if (!iface.ssid) continue;
      for (const client of iface.clients ?? []) {
        const mac = normalizeMac(client.mac);
        if (!mac) continue;
        out.push({
          mac,
          ssid: iface.ssid,
          routerHost: router.host,
          signal: client.signal,
        });
      }
    }
  }
  return out;
}

/** Resolve inventory device id by MAC (case/colon insensitive). */
export function deviceIdByMac(devices: Device[], mac: string): string | null {
  const target = normalizeMac(mac);
  if (!target) return null;
  const hit = devices.find((d) => normalizeMac(d.mac) === target);
  return hit?.id ?? null;
}

/** Resolve router device id by probe host IP. */
export function routerDeviceIdByIp(devices: Device[], host: string): string | null {
  const hit = devices.find((d) => d.ip === host && d.deviceType === 'router');
  return hit?.id ?? null;
}
