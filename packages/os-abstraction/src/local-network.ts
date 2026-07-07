import { networkInterfaces } from 'node:os';
import { Cidr, isOk } from '@netscanner/kernel';

export interface LocalInterface {
  name: string;
  address: string;
  netmask: string;
  mac: string;
  cidr: string;
}

/** Convert a dotted netmask (255.255.255.0) to a prefix length (24). */
function netmaskToPrefix(netmask: string): number {
  return netmask
    .split('.')
    .map((o) => Number(o).toString(2).padStart(8, '0'))
    .join('')
    .split('')
    .filter((b) => b === '1').length;
}

/** Enumerate non-internal IPv4 interfaces with their derived CIDR networks. */
export function listLocalInterfaces(): LocalInterface[] {
  const result: LocalInterface[] = [];
  for (const [name, infos] of Object.entries(networkInterfaces())) {
    for (const info of infos ?? []) {
      if (info.family !== 'IPv4' || info.internal) continue;
      const prefix = netmaskToPrefix(info.netmask);
      const cidr = Cidr.create(`${info.address}/${prefix}`);
      if (!isOk(cidr)) continue;
      result.push({
        name,
        address: info.address,
        netmask: info.netmask,
        mac: info.mac,
        cidr: cidr.value.toString(),
      });
    }
  }
  return result;
}

/**
 * Pick the primary local subnet to scan: prefer a private /24-ish network on a
 * non-virtual interface. Falls back to the first available interface.
 */
export function detectPrimaryCidr(): string | null {
  const ifaces = listLocalInterfaces();
  if (ifaces.length === 0) return null;
  const preferred =
    ifaces.find(
      (i) => /^(en|eth|wl|wlan)/i.test(i.name) && !/(vmnet|docker|bridge|utun)/i.test(i.name),
    ) ?? ifaces[0]!;
  return preferred.cidr;
}

/** All CIDRs to scan: primary + other local interfaces + optional SCAN_CIDRS. */
export function listScanCidrs(extraCsv = process.env.SCAN_CIDRS ?? ''): string[] {
  const out = new Set<string>();
  const primary = detectPrimaryCidr();
  if (primary) out.add(primary);

  for (const iface of listLocalInterfaces()) {
    if (/(vmnet|docker|veth|utun|lo)/i.test(iface.name)) continue;
    out.add(iface.cidr);
  }

  for (const raw of extraCsv.split(',')) {
    const c = raw.trim();
    if (!c) continue;
    const parsed = Cidr.create(c);
    if (isOk(parsed)) out.add(parsed.value.toString());
  }

  return [...out];
}
