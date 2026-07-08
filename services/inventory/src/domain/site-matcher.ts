import type {
  NetworkFingerprint,
  NetworkSite,
  SiteIntegrations,
  SiteMatchCandidate,
} from '@netscanner/contracts';
import {
  NetworkFingerprintSchema,
  SiteIntegrationsSchema,
} from '@netscanner/contracts';
import type { AppConfig } from '@netscanner/config';

/** Weights for site fingerprint matching (sum used for normalization). */
export interface SiteMatchWeights {
  gatewayMac: number;
  gatewayIp: number;
  cidrs: number;
  dns: number;
  routerId: number;
  publicIp: number;
  geo: number;
  ssids: number;
}

export function defaultMatchWeights(vpnDetected: boolean, config: AppConfig): SiteMatchWeights {
  if (vpnDetected && config.SITE_VPN_IGNORE_GEO) {
    return {
      gatewayMac: 35,
      gatewayIp: 25,
      cidrs: 20,
      dns: 5,
      routerId: 15,
      publicIp: 0,
      geo: 0,
      ssids: 10,
    };
  }
  return {
    gatewayMac: 30,
    gatewayIp: 20,
    cidrs: 15,
    dns: 5,
    routerId: 15,
    publicIp: 5,
    geo: 5,
    ssids: 10,
  };
}

function normMac(mac: string | null | undefined): string | null {
  if (!mac) return null;
  return mac.replace(/[^0-9a-f]/gi, '').toLowerCase();
}

function overlapRatio(a: string[], b: string[]): number {
  if (!a.length || !b.length) return 0;
  const setB = new Set(b);
  const hit = a.filter((x) => setB.has(x)).length;
  return hit / Math.max(a.length, b.length);
}

function geoDistanceKm(
  a: { lat: number; lon: number },
  b: { lat: number; lon: number },
): number {
  const R = 6371;
  const dLat = ((b.lat - a.lat) * Math.PI) / 180;
  const dLon = ((b.lon - a.lon) * Math.PI) / 180;
  const lat1 = (a.lat * Math.PI) / 180;
  const lat2 = (b.lat * Math.PI) / 180;
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

function scoreFingerprint(
  obs: NetworkFingerprint,
  stored: NetworkFingerprint,
  weights: SiteMatchWeights,
): number {
  let earned = 0;
  let total = 0;

  const add = (weight: number, score: number) => {
    if (weight <= 0) return;
    total += weight;
    earned += weight * score;
  };

  if (obs.gatewayMac && stored.gatewayMac) {
    add(
      weights.gatewayMac,
      normMac(obs.gatewayMac) === normMac(stored.gatewayMac) ? 1 : 0,
    );
  } else if (obs.gatewayIp && stored.gatewayIp) {
    add(weights.gatewayIp, obs.gatewayIp === stored.gatewayIp ? 1 : 0);
  }

  if (obs.cidrs.length && stored.cidrs.length) {
    add(weights.cidrs, overlapRatio(obs.cidrs, stored.cidrs));
  }

  if (obs.dnsServers.length && stored.dnsServers.length) {
    add(weights.dns, overlapRatio(obs.dnsServers, stored.dnsServers));
  }

  if (obs.routerId && stored.routerId) {
    add(weights.routerId, obs.routerId === stored.routerId ? 1 : 0);
  }

  if (weights.publicIp > 0 && obs.publicIp && stored.publicIp) {
    add(weights.publicIp, obs.publicIp === stored.publicIp ? 1 : 0);
  }

  if (
    weights.geo > 0 &&
    obs.geoLat != null &&
    obs.geoLon != null &&
    stored.geoLat != null &&
    stored.geoLon != null
  ) {
    const km = geoDistanceKm(
      { lat: obs.geoLat, lon: obs.geoLon },
      { lat: stored.geoLat, lon: stored.geoLon },
    );
    add(weights.geo, km <= 25 ? 1 : km <= 100 ? 0.5 : 0);
  }

  if (obs.ssids.length && stored.ssids.length) {
    add(weights.ssids, overlapRatio(obs.ssids, stored.ssids));
  }

  return total > 0 ? earned / total : 0;
}

export function mergeFingerprints(
  stored: NetworkFingerprint,
  obs: NetworkFingerprint,
): NetworkFingerprint {
  const union = (a: string[], b: string[]) => [...new Set([...a, ...b])];
  return NetworkFingerprintSchema.parse({
    gatewayIp: obs.gatewayIp ?? stored.gatewayIp ?? null,
    gatewayMac: obs.gatewayMac ?? stored.gatewayMac ?? null,
    cidrs: union(stored.cidrs, obs.cidrs),
    dnsServers: union(stored.dnsServers, obs.dnsServers),
    routerId: obs.routerId ?? stored.routerId ?? null,
    publicIp: obs.vpnDetected ? stored.publicIp : obs.publicIp ?? stored.publicIp ?? null,
    geoLat: obs.vpnDetected ? stored.geoLat : obs.geoLat ?? stored.geoLat ?? null,
    geoLon: obs.vpnDetected ? stored.geoLon : obs.geoLon ?? stored.geoLon ?? null,
    geoLabel: obs.vpnDetected ? stored.geoLabel : obs.geoLabel ?? stored.geoLabel ?? null,
    ssids: union(stored.ssids, obs.ssids),
    vpnDetected: obs.vpnDetected,
    collectedAt: obs.collectedAt ?? new Date().toISOString(),
  });
}

export function rankSiteMatches(
  obs: NetworkFingerprint,
  sites: NetworkSite[],
  config: AppConfig,
): SiteMatchCandidate[] {
  const weights = defaultMatchWeights(obs.vpnDetected, config);
  return sites
    .map((site) => ({
      site,
      score: scoreFingerprint(obs, site.fingerprint, weights),
    }))
    .sort((a, b) => b.score - a.score);
}

export function parseSiteIntegrations(raw: string): SiteIntegrations {
  try {
    return SiteIntegrationsSchema.parse(JSON.parse(raw || '{}'));
  } catch {
    return {};
  }
}

export function parseSiteFingerprint(raw: string): NetworkFingerprint {
  try {
    return NetworkFingerprintSchema.parse(JSON.parse(raw || '{}'));
  } catch {
    return NetworkFingerprintSchema.parse({});
  }
}
