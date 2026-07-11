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
 * Interfaces unsuitable for local DHCP sniff (VM/containers/tunnels/loopback).
 * Bridge interfaces (e.g. bridge100 for Internet Sharing) are kept so we can
 * see DHCP on what the Mac actually receives on L2.
 */
export function isSniffableInterfaceName(name: string): boolean {
  if (/^lo\d*$/i.test(name)) return false;
  if (/(vmnet|docker|veth|utun)/i.test(name)) return false;
  return true;
}

/**
 * Unique local ifaces suitable for DHCP tcpdump fallback.
 * Note: routed VLANs without L2 on this host still need remote capture
 * (switch/gateway); this only covers what the machine can see locally.
 */
export function listSniffInterfaces(): LocalInterface[] {
  const byName = new Map<string, LocalInterface>();
  for (const iface of listLocalInterfaces()) {
    if (!isSniffableInterfaceName(iface.name)) continue;
    if (!byName.has(iface.name)) byName.set(iface.name, iface);
  }
  return [...byName.values()];
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

/**
 * Subnets we never auto-detect from local interfaces: common ISP handoff (.0),
 * Mac Internet Sharing, VPN overlays. Operators can still add them explicitly
 * via SCAN_CIDRS (e.g. 192.168.0.0/24 + 192.168.15.0/24 for dual-WAN CPE).
 */
export function isIgnoredScanCidr(cidr: string): boolean {
  const network = cidr.split('/')[0] ?? cidr;
  if (network.startsWith('192.168.0.')) return true;
  if (network.startsWith('192.168.64.')) return true; // Mac Internet Sharing
  if (network.startsWith('10.8.') || network.startsWith('10.14.')) return true;
  return false;
}

/** All CIDRs to scan: primary + other local interfaces + optional SCAN_CIDRS. */
export function listScanCidrs(extraCsv = process.env.SCAN_CIDRS ?? ''): string[] {
  const out = new Set<string>();
  const primary = detectPrimaryCidr();
  if (primary && !isIgnoredScanCidr(primary)) out.add(primary);

  for (const iface of listLocalInterfaces()) {
    if (/(vmnet|docker|veth|utun|lo|bridge)/i.test(iface.name)) continue;
    if (isIgnoredScanCidr(iface.cidr)) continue;
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
