import type { PfSenseGatewayRow, PfSenseInterfaceRow } from '@netscanner/discovery';

export interface PhysicalWanTarget {
  name: string;
  interface: string;
  hwif: string;
  srcip: string | null;
}

/** True for ISP WAN gateways — excludes VPN/tunnel monitor gateways. */
export function isPhysicalWanGateway(name: string): boolean {
  const n = name.toUpperCase();
  if (!n) return false;
  if (/VPN|OVPN|WIREGUARD|WG_|SURFSHARK|TUN_|GATEWAY.*SP|MIA|_UY|LB_/.test(n) && !/^WAN/.test(n)) return false;
  if (/^GW_/.test(n)) return false;
  return /^WAN_|^WAN$|WAN_DHCP|WAN.*DHCP|CLARO|VIVO|ISP/.test(n) || (n.includes('WAN') && !n.includes('VPN'));
}

/** Resolve pfSense WAN gateways to OS interface names (igc0, igc1) for per-link tests. */
export function listPhysicalWanTargets(
  gateways: PfSenseGatewayRow[],
  interfaces: PfSenseInterfaceRow[],
): PhysicalWanTarget[] {
  const hwifByOpt = new Map<string, string>();
  for (const iface of interfaces) {
    const name = iface.name?.toLowerCase();
    const hwif = iface.hwif?.trim();
    if (name && hwif) hwifByOpt.set(name, hwif);
  }

  const seen = new Set<string>();
  const out: PhysicalWanTarget[] = [];
  for (const gw of gateways) {
    const name = gw.name?.trim();
    if (!name || !isPhysicalWanGateway(name)) continue;
    if (seen.has(name)) continue;
    seen.add(name);
    const opt = gw.interface?.toLowerCase() ?? '';
    const hwif = (opt ? hwifByOpt.get(opt) : undefined) ?? gw.interface?.trim();
    if (!hwif) continue;
    out.push({
      name,
      interface: gw.interface ?? '',
      hwif,
      srcip: gw.srcip ?? null,
    });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}
