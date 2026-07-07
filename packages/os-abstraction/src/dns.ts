import { promises as dns } from 'node:dns';

const PTR_CACHE = new Map<string, { name: string | null; expiresAt: number }>();
const PTR_TTL_MS = 10 * 60_000;

function cacheGet(ip: string): string | null | undefined {
  const row = PTR_CACHE.get(ip);
  if (!row) return undefined;
  if (Date.now() > row.expiresAt) {
    PTR_CACHE.delete(ip);
    return undefined;
  }
  return row.name;
}

function cacheSet(ip: string, name: string | null): void {
  PTR_CACHE.set(ip, { name, expiresAt: Date.now() + PTR_TTL_MS });
}

/**
 * Reverse-resolve an IP to a hostname via the system resolver (PTR lookup).
 * Best-effort: returns null when the host has no PTR record.
 */
export async function reverseDns(ip: string): Promise<string | null> {
  const cached = cacheGet(ip);
  if (cached !== undefined) return cached;

  try {
    const names = await dns.reverse(ip);
    const name = names[0] ? names[0].replace(/\.$/, '') : null;
    cacheSet(ip, name);
    return name;
  } catch {
    cacheSet(ip, null);
    return null;
  }
}

/** Prefetch PTR records for many hosts (uses cache; runs with bounded concurrency). */
export async function batchReverseDns(ips: string[], concurrency = 32): Promise<Map<string, string | null>> {
  const out = new Map<string, string | null>();
  const todo = ips.filter((ip) => cacheGet(ip) === undefined);
  for (const ip of ips) {
    const cached = cacheGet(ip);
    if (cached !== undefined) out.set(ip, cached);
  }

  let idx = 0;
  const worker = async (): Promise<void> => {
    while (idx < todo.length) {
      const ip = todo[idx++]!;
      const name = await reverseDns(ip);
      out.set(ip, name);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, todo.length || 1) }, worker));
  return out;
}

export function clearReverseDnsCache(): void {
  PTR_CACHE.clear();
}
