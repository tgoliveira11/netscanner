import type { TrafficSample } from '../domain/traffic-source.js';

const BYTES_RE = /([\d]+):([\d]+)\s+bytes/i;
const TOP_PEER_LIMIT = 12;

function isPrivate(ip: string): boolean {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
}

function ipsInSegment(segment: string): string[] {
  const cleaned = segment.replace(/\([^)]*\)/g, ' ');
  return cleaned.match(/\d{1,3}(?:\.\d{1,3}){3}/g) ?? [];
}

/** Parse pf state header into LAN-centric src/dst (private host → remote peer). */
export function parseStateEndpoints(line: string): { src: string | null; dst: string | null } {
  const pickPrivate = (segment: string): string | null => {
    const ips = ipsInSegment(segment);
    return ips.find(isPrivate) ?? ips[0] ?? null;
  };
  const pickRemote = (segment: string, local: string | null): string | null => {
    const ips = ipsInSegment(segment);
    const remote = ips.find((ip) => ip !== local && !isPrivate(ip));
    if (remote) return remote;
    return ips.find((ip) => ip !== local) ?? ips[0] ?? null;
  };

  if (line.includes('<-')) {
    const [left = '', right = ''] = line.split('<-');
    const local = pickPrivate(right) ?? pickPrivate(left);
    const remote = pickRemote(left, local) ?? pickRemote(right, local);
    return local && remote ? { src: local, dst: remote } : { src: null, dst: null };
  }
  if (line.includes('->')) {
    const [left = '', right = ''] = line.split('->');
    const local = pickPrivate(left) ?? pickPrivate(right);
    const remote = pickRemote(right, local) ?? pickRemote(left, local);
    return local && remote ? { src: local, dst: remote } : { src: null, dst: null };
  }
  return { src: null, dst: null };
}

interface HostAcc {
  in: number;
  out: number;
  conns: number;
  peers: Map<string, number>;
}

/**
 * Parse `pfctl -vvs state` output into per-device cumulative traffic + top peers.
 */
export function parsePfStates(output: string): TrafficSample[] {
  const acc = new Map<string, HostAcc>();
  const lines = output.split('\n');
  let srcIp: string | null = null;
  let dstIp: string | null = null;

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

  const bump = (ip: string, inc: { in: number; out: number; conn: boolean }) => {
    const row = host(ip);
    row.in += inc.in;
    row.out += inc.out;
    if (inc.conn) row.conns += 1;
  };

  for (const line of lines) {
    if (line.includes('->') || line.includes('<-')) {
      const endpoints = parseStateEndpoints(line);
      srcIp = endpoints.src;
      dstIp = endpoints.dst;
      continue;
    }
    const b = BYTES_RE.exec(line);
    if (b && srcIp && dstIp) {
      const outBytes = Number(b[1]);
      const inBytes = Number(b[2]);
      const total = outBytes + inBytes;
      if (isPrivate(srcIp)) {
        bump(srcIp, { out: outBytes, in: inBytes, conn: true });
        bumpPeer(srcIp, dstIp, total);
      }
      if (isPrivate(dstIp) && dstIp !== srcIp) {
        bump(dstIp, { out: inBytes, in: outBytes, conn: true });
        bumpPeer(dstIp, srcIp, total);
      }
      srcIp = null;
      dstIp = null;
    }
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
