import { promises as dns } from 'node:dns';

/**
 * Reverse-resolve an IP to a hostname via the system resolver (PTR lookup).
 * Best-effort: returns null when the host has no PTR record.
 */
export async function reverseDns(ip: string): Promise<string | null> {
  try {
    const names = await dns.reverse(ip);
    const name = names[0];
    return name ? name.replace(/\.$/, '') : null;
  } catch {
    return null;
  }
}
