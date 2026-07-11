/**
 * NetScanner mobile (Fase D) — Expo/RN shell.
 *
 * Stand-alone: limited LAN scan (ARP/ping/mDNS subset via native modules later).
 * With agents: mDNS/UDP discovery + aggregate inventory from multiple peers/cloud.
 */
export type DiscoveredAgent = {
  agentId: string;
  hostname: string;
  baseUrl: string;
  role: string;
};

export type AggregatedDevice = {
  siteId: string;
  agentId: string;
  mac: string;
  ip: string;
  hostname?: string;
};

/** Parse a PeerBeacon-like UDP/mDNS payload into a discovered agent. */
export function agentFromBeacon(
  beacon: {
    agentId: string;
    hostname: string;
    httpPort: number;
    role: string;
  },
  address: string,
): DiscoveredAgent {
  return {
    agentId: beacon.agentId,
    hostname: beacon.hostname,
    baseUrl: `http://${address}:${beacon.httpPort}`,
    role: beacon.role,
  };
}

/** Merge device lists from multiple agents (last-write-wins by mac+site). */
export function aggregateDevices(lists: AggregatedDevice[]): AggregatedDevice[] {
  const map = new Map<string, AggregatedDevice>();
  for (const d of lists) {
    map.set(`${d.siteId}:${d.mac.toLowerCase()}`, d);
  }
  return [...map.values()].sort((a, b) => (a.hostname || a.ip).localeCompare(b.hostname || b.ip));
}

/** Limited stand-alone scan placeholder (no root): returns empty until native probes land. */
export async function standaloneLimitedScan(_cidr?: string): Promise<AggregatedDevice[]> {
  return [];
}
