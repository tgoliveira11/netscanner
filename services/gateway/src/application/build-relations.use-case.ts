import type { Device, Traffic } from '@netscanner/contracts';
import { analyzeDns } from '@netscanner/classification';

export interface RelationEdge {
  from: string;
  to: string;
  kind: 'traffic' | 'traffic-external' | 'dns';
  label: string;
  bytes?: number;
}

export interface RelationsResponse {
  edges: RelationEdge[];
  externalContacts: { deviceId: string; domain: string; vendor?: string }[];
  dnsLog: { at: string; deviceId: string; deviceLabel: string; message: string }[];
}

export interface BuildRelationsOptions {
  /** Optional passive store for per-IP DNS queries not yet enriched onto devices. */
  passiveDnsByIp?: (ip: string) => string[];
  dnsLog?: { at: string; deviceId: string; deviceLabel: string; message: string }[];
}

function isLocalDomain(domain: string): boolean {
  return /\.(local|lan|home|internal|arpa)$/i.test(domain);
}

function trafficPeers(device: Device): { ip: string; bytes: number }[] {
  const traffic = device.signals?.traffic as Traffic | undefined;
  return traffic?.topPeers ?? [];
}

function dnsQueriesFor(device: Device, passiveDnsByIp?: (ip: string) => string[]): string[] {
  const fromProfile = device.signals?.dnsProfile as
    | { topDomains?: { domain: string }[] }
    | undefined;
  const fromSignals = device.signals?.dnsRecentQueries;
  const fromPassive = passiveDnsByIp?.(device.ip) ?? [];
  const merged = new Set<string>();
  if (Array.isArray(fromSignals)) {
    for (const q of fromSignals) merged.add(String(q));
  }
  for (const q of fromPassive) merged.add(q);
  if (merged.size === 0 && fromProfile?.topDomains?.length) {
    for (const row of fromProfile.topDomains) merged.add(row.domain);
  }
  return [...merged];
}

function deviceLabel(device: Device): string {
  return device.label ?? device.hostname ?? device.ip;
}

function peerLabel(peerIp: string, byIp: Map<string, Device>): string {
  const known = byIp.get(peerIp);
  if (known) return deviceLabel(known);
  if (!/^(10\.|192\.168\.|172\.)/.test(peerIp)) return `${peerIp} (external)`;
  return peerIp;
}

/**
 * Build a who-talks-to-whom graph from per-device traffic peers and DNS activity.
 */
export function buildDeviceRelations(
  devices: Device[],
  options: BuildRelationsOptions = {},
): RelationsResponse {
  const byIp = new Map(devices.map((d) => [d.ip, d]));
  const edges: RelationEdge[] = [];
  const externalContacts: RelationsResponse['externalContacts'] = [];
  const seen = new Set<string>();

  for (const device of devices) {
    for (const peer of trafficPeers(device)) {
      const target = byIp.get(peer.ip);
      const isExternal = !target && !/^(10\.|192\.168\.|172\.)/.test(peer.ip);
      const key = `traffic:${device.id}:${peer.ip}`;
      if (seen.has(key)) continue;
      seen.add(key);
      edges.push({
        from: device.id,
        to: target?.id ?? peer.ip,
        kind: isExternal ? 'traffic-external' : 'traffic',
        label: `${deviceLabel(device)} → ${peerLabel(peer.ip, byIp)}`,
        bytes: peer.bytes,
      });
    }

    const queries = dnsQueriesFor(device, options.passiveDnsByIp);
    if (queries.length === 0) continue;
    const profile = analyzeDns(queries);
    for (const row of profile.topDomains) {
      if (isLocalDomain(row.domain)) continue;
      externalContacts.push({
        deviceId: device.id,
        domain: row.domain,
        vendor: row.vendor,
      });
      const key = `dns:${device.id}:${row.domain}`;
      if (seen.has(key)) continue;
      seen.add(key);
      edges.push({
        from: device.id,
        to: row.domain,
        kind: 'dns',
        label: `${deviceLabel(device)} → ${row.domain}`,
      });
    }
  }

  edges.sort((a, b) => (b.bytes ?? 0) - (a.bytes ?? 0));

  return { edges, externalContacts, dnsLog: options.dnsLog ?? [] };
}
