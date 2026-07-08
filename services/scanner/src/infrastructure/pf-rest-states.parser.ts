import type { TrafficSample } from '../domain/traffic-source.js';

const TOP_PEER_LIMIT = 12;

function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
}

/** Extract IPv4 from pfSense REST endpoint strings like `192.168.1.5:443`. */
export function ipFromPfEndpoint(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) return null;
  const v4 = trimmed.match(/^(\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$/);
  if (v4) return v4[1]!;
  return null;
}

export interface PfRestStateRow {
  source?: string;
  destination?: string;
  direction?: string;
  bytes_in?: number;
  bytes_out?: number;
  bytes_total?: number;
}

interface HostAcc {
  in: number;
  out: number;
  conns: number;
  peers: Map<string, number>;
}

/**
 * Aggregate `/api/v2/firewall/states` rows into per-LAN-host traffic samples.
 * Mirrors the LAN-centric view of `parsePfStates` (private host → remote peer).
 */
export function parseRestFirewallStates(rows: PfRestStateRow[]): TrafficSample[] {
  const acc = new Map<string, HostAcc>();

  const host = (ip: string): HostAcc => {
    const cur = acc.get(ip);
    if (cur) return cur;
    const created = { in: 0, out: 0, conns: 0, peers: new Map<string, number>() };
    acc.set(ip, created);
    return created;
  };

  const bumpPeer = (ip: string, peer: string | null, bytes: number) => {
    if (!peer || peer === ip || bytes <= 0) return;
    const row = host(ip);
    row.peers.set(peer, (row.peers.get(peer) ?? 0) + bytes);
  };

  const bump = (ip: string, inc: { in: number; out: number }) => {
    const row = host(ip);
    row.in += inc.in;
    row.out += inc.out;
    row.conns += 1;
  };

  for (const row of rows) {
    const src = ipFromPfEndpoint(String(row.source ?? ''));
    const dst = ipFromPfEndpoint(String(row.destination ?? ''));
    if (!src || !dst) continue;

    const bytesIn = Math.max(0, Number(row.bytes_in ?? 0));
    const bytesOut = Math.max(0, Number(row.bytes_out ?? 0));
    const total = Math.max(bytesIn + bytesOut, Number(row.bytes_total ?? 0));

    const srcPrivate = isPrivate(src);
    const dstPrivate = isPrivate(dst);
    if (!srcPrivate && !dstPrivate) continue;

    if (srcPrivate && !dstPrivate) {
      bump(src, { in: bytesIn, out: bytesOut });
      bumpPeer(src, dst, total);
      continue;
    }
    if (dstPrivate && !srcPrivate) {
      bump(dst, { in: bytesIn, out: bytesOut });
      bumpPeer(dst, src, total);
      continue;
    }
    // LAN ↔ LAN — attribute to source; peer still useful for Relations.
    bump(src, { in: bytesIn, out: bytesOut });
    bumpPeer(src, dst, total);
  }

  return [...acc.entries()].map(([ip, v]) => ({
    ip,
    bytesIn: v.in,
    bytesOut: v.out,
    connections: v.conns,
    topPeers: [...v.peers.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, TOP_PEER_LIMIT)
      .map(([peerIp, bytes]) => ({ ip: peerIp, bytes })),
  }));
}
