import { MacAddress, isOk } from '@netscanner/kernel';
import type { RouterLease } from '../domain/router-lease-source.js';

/** Normalize pfSense REST or push rows into a RouterLease. */
export function normalizePfSenseLease(r: Record<string, unknown>): RouterLease | null {
  const ip = str(r['ip'] ?? r['address'] ?? r['ip_address'] ?? r['ipaddr']);
  const rawMac = str(r['mac'] ?? r['hwaddr'] ?? r['mac_address']);
  if (!ip && !rawMac) return null;

  let mac: string | null = null;
  if (rawMac) {
    const parsed = MacAddress.create(rawMac.replace(/-/g, ':'));
    mac = isOk(parsed) ? parsed.value.value : null;
  }

  const state = str(
    r['online_status'] ?? r['active_status'] ?? r['state'] ?? r['status'] ?? r['act'],
  );
  const online =
    r['online'] === true ||
    (state ? /online|active|bound/i.test(state) && !/offline/i.test(state) : true);

  return {
    ip: ip ?? '',
    mac,
    hostname: str(r['hostname'] ?? r['host'] ?? r['client_hostname']) ?? null,
    interface: str(r['if'] ?? r['interface'] ?? r['iface']) ?? null,
    description: str(r['descr'] ?? r['description']) ?? null,
    online,
  };
}

export function normalizePfSenseArpLease(r: {
  ip: string;
  mac?: string;
  interface?: string;
  hostname?: string;
}): RouterLease | null {
  if (!r.ip) return null;
  let mac: string | null = null;
  if (r.mac) {
    const parsed = MacAddress.create(r.mac.replace(/-/g, ':'));
    mac = isOk(parsed) ? parsed.value.value : null;
  }
  if (!mac) return null;
  return {
    ip: r.ip,
    mac,
    hostname: r.hostname ?? null,
    interface: r.interface ?? null,
    description: null,
    online: true,
  };
}

/** Merge DHCP leases with ARP; DHCP wins on conflict. */
export function mergePfSenseLeases(dhcp: RouterLease[], arp: RouterLease[]): RouterLease[] {
  const byKey = new Map<string, RouterLease>();
  for (const lease of arp) {
    const key = (lease.mac ?? lease.ip).toLowerCase();
    if (key) byKey.set(key, lease);
  }
  for (const lease of dhcp) {
    const key = (lease.mac ?? lease.ip).toLowerCase();
    if (!key) continue;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, lease);
      continue;
    }
    byKey.set(key, {
      ip: lease.ip || existing.ip,
      mac: lease.mac ?? existing.mac,
      hostname: lease.hostname ?? existing.hostname,
      interface: lease.interface ?? existing.interface,
      description: lease.description ?? existing.description,
      online: lease.online || existing.online,
    });
  }
  return [...byKey.values()];
}

function str(v: unknown): string | undefined {
  if (v == null) return undefined;
  const s = String(v).trim();
  return s.length ? s : undefined;
}
