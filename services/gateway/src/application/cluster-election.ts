/**
 * Pure cluster leader election — portable agents yield to dedicated/prefer-leader
 * peers when present, and take inventory leadership when alone (e.g. Mac on another LAN).
 */

export type ElectionCandidate = {
  agentId: string;
  dedicated: boolean;
  preferLeader: boolean;
  elevated: boolean;
  uptimeSec: number;
  canInventory: boolean;
  canControl: boolean;
};

export function electionScore(p: {
  dedicated: boolean;
  preferLeader: boolean;
  elevated: boolean;
  uptimeSec: number;
  agentId: string;
}): number {
  let s = 0;
  if (p.dedicated) s += 1_000_000;
  if (p.preferLeader) s += 100_000;
  if (p.elevated) s += 10_000;
  s += Math.min(p.uptimeSec, 86_400);
  for (let i = 0; i < Math.min(8, p.agentId.length); i++) s += p.agentId.charCodeAt(i) % 7;
  return s;
}

/** True for dedicated appliances / prefer-leader boxes. */
export function isPreferredLeader(p: { dedicated: boolean; preferLeader: boolean }): boolean {
  return p.dedicated || p.preferLeader;
}

/**
 * Pick inventory + control leaders.
 * If any preferred (dedicated/preferLeader) candidate is in the pool, portable
 * agents are excluded from that race so a laptop helper never steals SoT at home,
 * but still wins when no preferred peer is reachable (other network / box offline).
 */
export function pickClusterLeaders(candidates: ElectionCandidate[]): {
  inventoryLeaderId: string | null;
  controlLeaderId: string | null;
} {
  const invPool = candidates.filter((c) => c.canInventory);
  const ctrlPool = candidates.filter((c) => c.canControl);

  const pick = (pool: ElectionCandidate[]): string | null => {
    if (!pool.length) return null;
    const preferred = pool.filter(isPreferredLeader);
    const use = preferred.length > 0 ? preferred : pool;
    return [...use].sort((a, b) => electionScore(b) - electionScore(a))[0]!.agentId;
  };

  return {
    inventoryLeaderId: pick(invPool.length ? invPool : candidates),
    // No fallback to inventory-only peers — control stays null until someone is eligible.
    controlLeaderId: pick(ctrlPool),
  };
}
