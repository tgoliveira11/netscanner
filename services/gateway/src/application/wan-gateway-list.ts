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

function looksLikeOsIface(name: string | null | undefined): boolean {
  if (!name) return false;
  return /^(igc|em|ix|igb|vtnet|eth|ena|re|hn)\d+/i.test(name.trim());
}

/** Resolve pfSense WAN gateways to OS interface names (igc0, igc1) for per-link tests. */
export function listPhysicalWanTargets(
  gateways: PfSenseGatewayRow[],
  interfaces: PfSenseInterfaceRow[],
): PhysicalWanTarget[] {
  const hwifByOpt = new Map<string, string>();
  const hwifBySrcip = new Map<string, { hwif: string; opt: string }>();
  for (const iface of interfaces) {
    const name = iface.name?.toLowerCase();
    const hwif = iface.hwif?.trim();
    if (name && hwif) hwifByOpt.set(name, hwif);
    if (iface.ipaddr && hwif) hwifBySrcip.set(iface.ipaddr, { hwif, opt: iface.name ?? '' });
  }

  const seenName = new Set<string>();
  const seenHwif = new Set<string>();
  const out: PhysicalWanTarget[] = [];
  for (const gw of gateways) {
    const name = gw.name?.trim();
    if (!name || !isPhysicalWanGateway(name)) continue;
    if (seenName.has(name)) continue;
    seenName.add(name);

    const opt = gw.interface?.toLowerCase() ?? '';
    const fromSrcip = gw.srcip ? hwifBySrcip.get(gw.srcip) : undefined;
    const hwif =
      (opt ? hwifByOpt.get(opt) : undefined) ??
      fromSrcip?.hwif ??
      (looksLikeOsIface(gw.interface) ? gw.interface!.trim() : undefined);
    if (!hwif) continue;
    // One speed sample per physical NIC (avoid duplicate WAN_* names on same link).
    if (seenHwif.has(hwif)) continue;
    seenHwif.add(hwif);

    out.push({
      name,
      interface: gw.interface || fromSrcip?.opt || '',
      hwif,
      srcip: gw.srcip ?? null,
    });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}
