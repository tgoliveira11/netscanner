import type {
  PfSenseDefaultGateway,
  PfSenseEgressSummary,
  PfSenseGatewayGroup,
  PfSenseGatewayGroupInsight,
  PfSenseGatewayRow,
  PfSenseInterfaceRow,
  PfSenseSystemStatus,
  PfSenseVpnClientRow,
} from '../domain/pfsense-telemetry.js';
import type { RouterLease } from '../domain/router-lease-source.js';
import { normalizePfSenseArpLease, normalizePfSenseLease } from './pfsense-lease-normalize.js';

export function normalizePfSenseArpRow(r: Record<string, unknown>): RouterLease | null {
  const ip = str(r['ip_address'] ?? r['ip'] ?? r['ipaddr']);
  const mac = str(r['mac_address'] ?? r['mac'] ?? r['hwaddr']);
  const hostname = str(r['hostname']);
  return normalizePfSenseArpLease({
    ip: ip ?? '',
    mac,
    interface: str(r['interface'] ?? r['if']),
    hostname: hostname && hostname !== '?' ? hostname : undefined,
  });
}

/**
 * Normalize a gateway status/config row.
 *
 * `/api/v2/status/gateways` exposes `srcip` (local WAN address used as the
 * probe source) but often omits the real next-hop. Never treat `srcip` as
 * `gateway` — that wrongly identifies the pfSense WAN NIC as the ISP CPE.
 * Prefer an explicit next-hop IP from `gateway` / `gatewayip` when present and
 * not the placeholder `dynamic`.
 */
export function normalizePfSenseGatewayRow(r: Record<string, unknown>): PfSenseGatewayRow {
  const delay = num(r['delay']);
  const loss = num(r['loss']);
  const rawGateway = str(r['gateway'] ?? r['gatewayip'] ?? r['gateway_ip']);
  const gateway = rawGateway && !/^dynamic$/i.test(rawGateway) ? rawGateway : null;
  const isDefaultRaw = r['isdefaultgw'] ?? r['is_default'] ?? r['default'];
  return {
    name: str(r['name']) ?? null,
    gateway,
    srcip: str(r['srcip'] ?? r['src_ip']) ?? null,
    monitor: str(r['monitor'] ?? r['monitorip']) ?? null,
    status: str(r['status']) ?? null,
    delay: delay ?? null,
    loss: loss ?? null,
    interface: str(r['interface'] ?? r['if']) ?? null,
    isDefault: isDefaultRaw === true || isDefaultRaw === 1 || isDefaultRaw === '1' || isDefaultRaw === 'true',
    description: str(r['descr'] ?? r['description']) ?? null,
  };
}

/** Parse `/api/v2/routing/gateway/default` — IPv4/IPv6 default gateway name or group. */
export function normalizePfSenseDefaultGateway(raw: Record<string, unknown> | null): PfSenseDefaultGateway | null {
  if (!raw) return null;
  const ipv4 = str(raw['defaultgw4'] ?? raw['ipv4'] ?? raw['default_ipv4'] ?? raw['gateway_ipv4']) ?? null;
  const ipv6 = str(raw['defaultgw6'] ?? raw['ipv6'] ?? raw['default_ipv6'] ?? raw['gateway_ipv6']) ?? null;
  if (!ipv4 && !ipv6) {
    const single = str(raw['gateway'] ?? raw['name']);
    if (single) return { ipv4: single, ipv6: null };
    return null;
  }
  return { ipv4, ipv6 };
}

/** Parse gateway group config rows from `/api/v2/routing/gateway_groups`. */
export function normalizePfSenseGatewayGroups(rows: Record<string, unknown>[]): PfSenseGatewayGroup[] {
  const out: PfSenseGatewayGroup[] = [];
  for (const row of rows) {
    const name = str(row['name']);
    if (!name) continue;
    const members: PfSenseGatewayGroup['members'] = [];
    const itemList = row['item'] ?? row['items'] ?? row['gateways'] ?? row['priorities'];
    if (Array.isArray(itemList)) {
      for (const item of itemList) {
        if (!item || typeof item !== 'object') continue;
        const rec = item as Record<string, unknown>;
        const gwName = str(rec['gateway'] ?? rec['name']);
        if (!gwName) continue;
        const tierRaw = rec['tier'] ?? rec['priority'];
        const tier = typeof tierRaw === 'number' ? tierRaw : Number(tierRaw);
        members.push({
          name: gwName,
          tier: Number.isFinite(tier) ? tier : 1,
          status: str(rec['status']) ?? null,
        });
      }
    }
    out.push({
      name,
      description: str(row['descr'] ?? row['description']) ?? null,
      members: members.sort((a, b) => a.tier - b.tier || a.name.localeCompare(b.name)),
    });
  }
  return out;
}

/** Overlay configured next-hop / interface from `/api/v2/routing/gateways` onto status rows. */
export function mergePfSenseGatewayRows(
  statusRows: PfSenseGatewayRow[],
  configRows: PfSenseGatewayRow[],
): PfSenseGatewayRow[] {
  if (configRows.length === 0) return statusRows;
  const byName = new Map(
    configRows
      .filter((r) => r.name)
      .map((r) => [r.name!.toLowerCase(), r] as const),
  );
  const mergedNames = new Set<string>();
  const out: PfSenseGatewayRow[] = statusRows.map((status) => {
    const cfg = status.name ? byName.get(status.name.toLowerCase()) : undefined;
    if (status.name) mergedNames.add(status.name.toLowerCase());
    if (!cfg) return status;
    return {
      ...status,
      gateway: status.gateway ?? cfg.gateway,
      interface: status.interface ?? cfg.interface,
      monitor: status.monitor ?? cfg.monitor,
    };
  });
  for (const cfg of configRows) {
    if (!cfg.name || mergedNames.has(cfg.name.toLowerCase())) continue;
    out.push(cfg);
  }
  return out;
}

export function normalizePfSenseInterfaceRow(r: Record<string, unknown>): PfSenseInterfaceRow {
  const vlan = r['vlan'] ?? r['vlanif'];
  return {
    name: str(r['name'] ?? r['if']) ?? null,
    descr: str(r['descr'] ?? r['description']) ?? null,
    ipaddr: str(r['ipaddr'] ?? r['ip']) ?? null,
    subnet: str(r['subnet']) ?? null,
    vlan: vlan != null ? String(vlan) : null,
    hwif: str(r['hwif'] ?? r['if']) ?? null,
    mac: str(r['macaddr'] ?? r['mac']) ?? null,
    status: str(r['status']) ?? null,
  };
}

/** Merge live monitor status from gateway status rows into group members. */
export function enrichGatewayGroupMembers(
  groups: PfSenseGatewayGroup[],
  gateways: PfSenseGatewayRow[],
): PfSenseGatewayGroup[] {
  const statusByName = new Map(
    gateways.filter((g) => g.name).map((g) => [g.name!.toLowerCase(), g.status] as const),
  );
  return groups.map((g) => ({
    ...g,
    members: g.members.map((m) => ({
      ...m,
      status: m.status ?? statusByName.get(m.name.toLowerCase()) ?? null,
    })),
  }));
}

/** Map OS iface (tun_wg2, ovpnc1) and pfSense opt name to gateway monitor name. */
export function buildHwifToGatewayMap(
  interfaces: PfSenseInterfaceRow[],
  gateways: PfSenseGatewayRow[],
): Map<string, string> {
  const optToHwif = new Map<string, string>();
  for (const iface of interfaces) {
    const name = iface.name?.toLowerCase();
    const hwif = iface.hwif?.toLowerCase();
    if (name && hwif) optToHwif.set(name, hwif);
  }
  const map = new Map<string, string>();
  for (const gw of gateways) {
    if (!gw.name || !gw.interface) continue;
    const hwif = optToHwif.get(gw.interface.toLowerCase());
    if (hwif) map.set(hwif, gw.name);
    map.set(gw.interface.toLowerCase(), gw.name);
  }
  return map;
}

/** Count firewall states per egress interface and map to gateway names when possible. */
export function summarizePfSenseEgress(
  states: Record<string, unknown>[],
  hwifToGateway: Map<string, string>,
): { egress: PfSenseEgressSummary[]; stateCount: number } {
  const counts = new Map<string, PfSenseEgressSummary>();
  for (const s of states) {
    const ifName = str(s['if'] ?? s['interface'] ?? s['iface'] ?? s['ifname']);
    if (!ifName) continue;
    const gw = hwifToGateway.get(ifName.toLowerCase()) ?? ifName;
    const cur = counts.get(gw) ?? { gateway: gw, interface: ifName, stateCount: 0, bytesOut: 0 };
    cur.stateCount += 1;
    cur.bytesOut += num(s['bytes'] ?? s['bytes_out'] ?? s['outbytes']) ?? 0;
    counts.set(gw, cur);
  }
  return {
    egress: [...counts.values()].sort((a, b) => b.stateCount - a.stateCount),
    stateCount: states.length,
  };
}

/** Preferred tier (failover) vs observed egress per gateway group. */
export function buildGatewayGroupInsights(
  groups: PfSenseGatewayGroup[],
  gateways: PfSenseGatewayRow[],
  egress: PfSenseEgressSummary[],
): PfSenseGatewayGroupInsight[] {
  const statusByName = new Map(
    gateways.filter((g) => g.name).map((g) => [g.name!.toLowerCase(), g.status] as const),
  );
  const egressByGw = new Map(egress.map((e) => [e.gateway.toLowerCase(), e.stateCount]));
  return groups.map((g) => {
    const tiers = [...new Set(g.members.map((m) => m.tier))].sort((a, b) => a - b);
    let preferredGateway: string | null = null;
    let preferredTier: number | null = null;
    for (const tier of tiers) {
      const online = g.members
        .filter((m) => m.tier === tier)
        .find((m) => {
          const st = (m.status ?? statusByName.get(m.name.toLowerCase()) ?? '').toLowerCase();
          return st.includes('online');
        });
      if (online) {
        preferredGateway = online.name;
        preferredTier = tier;
        break;
      }
    }
    let activeGateway: string | null = null;
    let activeStateCount = 0;
    for (const m of g.members) {
      const cnt = egressByGw.get(m.name.toLowerCase()) ?? 0;
      if (cnt > activeStateCount) {
        activeStateCount = cnt;
        activeGateway = m.name;
      }
    }
    return {
      group: g.name,
      description: g.description ?? null,
      preferredGateway,
      preferredTier,
      activeGateway: activeStateCount > 0 ? activeGateway : null,
      activeStateCount,
      members: g.members,
    };
  });
}

export function normalizePfSenseSystemStatus(
  raw: Record<string, unknown> | null,
  version: string | null,
  hostname: string | null,
): PfSenseSystemStatus | null {
  if (!raw && !version && !hostname) return null;
  const uptimeRaw = raw?.['uptime'];
  let uptime: string | null = null;
  if (typeof uptimeRaw === 'string') uptime = uptimeRaw;
  else if (uptimeRaw && typeof uptimeRaw === 'object') uptime = formatUptimeObject(uptimeRaw as Record<string, unknown>);
  else uptime = str(uptimeRaw) ?? null;
  return {
    platform: str(raw?.['platform'] ?? raw?.['cpu_type']) ?? null,
    uptime,
    version: version ?? str(raw?.['version'] ?? raw?.['product_version']) ?? null,
    hostname: hostname ?? str(raw?.['hostname']) ?? null,
    domain: str(raw?.['domain']) ?? null,
  };
}

export function normalizePfSenseOpenVpnClients(rows: Record<string, unknown>[]): PfSenseVpnClientRow[] {
  const out: PfSenseVpnClientRow[] = [];
  for (const r of rows) {
    const remoteHost = str(r['remote_host']);
    const remotePort = str(r['remote_port']);
    out.push({
      name: str(r['name'] ?? r['vpn_desc'] ?? r['description'] ?? r['common_name']) ?? 'OpenVPN',
      type: 'openvpn',
      status: str(r['status'] ?? r['state']) ?? null,
      virtualAddress: str(r['virtual_address'] ?? r['virtual_addr'] ?? r['local_host']) ?? null,
      remoteHost: remoteHost && remotePort ? `${remoteHost}:${remotePort}` : remoteHost ?? null,
      interface: str(r['interface'] ?? r['dev']) ?? null,
      enabled: r['disabled'] !== true && r['disabled'] !== 1,
    });
  }
  return out;
}

export function normalizePfSenseWireGuardTunnels(rows: Record<string, unknown>[]): PfSenseVpnClientRow[] {
  const out: PfSenseVpnClientRow[] = [];
  for (const r of rows) {
    const enabled = r['enabled'] === true || r['enabled'] === 1 || r['enabled'] === '1';
    out.push({
      name: str(r['descr'] ?? r['description'] ?? r['name']) ?? 'WireGuard',
      type: 'wireguard',
      status: enabled ? 'enabled' : 'disabled',
      virtualAddress: formatPfSenseAddresses(r['interface_addresses'] ?? r['addresses'] ?? r['tunneladdress']),
      remoteHost: str(r['endpoint'] ?? r['peer']) ?? null,
      interface: str(r['interface'] ?? r['if'] ?? r['name']) ?? null,
      enabled,
    });
  }
  return out;
}

/** pfSense REST often returns tunnel addresses as [{ address, mask }, …]. */
export function formatPfSenseAddresses(raw: unknown): string | null {
  if (raw == null) return null;
  if (typeof raw === 'string') {
    const s = raw.trim();
    return s.length ? s : null;
  }
  if (Array.isArray(raw)) {
    const parts = raw
      .map((item) => {
        if (typeof item === 'string') return item.trim();
        if (item && typeof item === 'object') {
          const rec = item as Record<string, unknown>;
          const addr = str(rec['address'] ?? rec['ipaddr'] ?? rec['ip']);
          if (!addr) return undefined;
          const mask = rec['mask'] ?? rec['subnet'] ?? rec['cidr'];
          if (mask != null && String(mask).length) return `${addr}/${mask}`;
          return addr;
        }
        return undefined;
      })
      .filter((s): s is string => Boolean(s));
    return parts.length ? parts.join(', ') : null;
  }
  if (typeof raw === 'object') {
    const rec = raw as Record<string, unknown>;
    const addr = str(rec['address'] ?? rec['ipaddr'] ?? rec['ip']);
    if (!addr) return null;
    const mask = rec['mask'] ?? rec['subnet'] ?? rec['cidr'];
    return mask != null && String(mask).length ? `${addr}/${mask}` : addr;
  }
  return str(raw) ?? null;
}

function formatUptimeObject(u: Record<string, unknown>): string | null {
  const parts: string[] = [];
  const days = num(u['days'] ?? u['day']);
  const hours = num(u['hours'] ?? u['hour']);
  const minutes = num(u['minutes'] ?? u['minute']);
  const seconds = num(u['seconds'] ?? u['second']);
  if (days) parts.push(`${days}d`);
  if (hours != null) parts.push(`${hours}h`);
  if (minutes != null) parts.push(`${minutes}m`);
  if (seconds != null && !days && !hours) parts.push(`${seconds}s`);
  return parts.length ? parts.join(' ') : null;
}

/** Map internal iface keys (e.g. opt4) to GUI labels (e.g. VLAN10). */
export function buildInterfaceLabelMap(rows: PfSenseInterfaceRow[]): Map<string, string> {
  const map = new Map<string, string>();
  for (const row of rows) {
    const name = row.name?.trim();
    const descr = row.descr?.trim();
    if (name && descr) map.set(name, descr);
    if (descr) map.set(descr, descr);
  }
  return map;
}

export function applyInterfaceLabels(
  leases: RouterLease[],
  labelMap: Map<string, string>,
): RouterLease[] {
  if (labelMap.size === 0) return leases;
  return leases.map((lease) => {
    if (!lease.interface) return lease;
    const label = labelMap.get(lease.interface) ?? lease.interface;
    return { ...lease, interface: label };
  });
}

export function enrichLeasesFromStaticMappings(
  leases: RouterLease[],
  staticRows: Record<string, unknown>[],
): RouterLease[] {
  if (staticRows.length === 0) return leases;
  const byMac = new Map<string, Record<string, unknown>>();
  for (const row of staticRows) {
    const mac = str(row['mac']);
    if (mac) byMac.set(mac.toLowerCase(), row);
  }
  return leases.map((lease) => {
    if (!lease.mac) return lease;
    const row = byMac.get(lease.mac.toLowerCase());
    if (!row) return lease;
    const parent = str(row['parent_id'] ?? row['interface']);
    return {
      ...lease,
      hostname: lease.hostname ?? str(row['hostname']) ?? null,
      description: lease.description ?? str(row['descr']) ?? null,
      interface: lease.interface ?? parent ?? null,
    };
  });
}

export function normalizePfSenseDhcpRows(rows: Record<string, unknown>[]): RouterLease[] {
  return rows.map((r) => normalizePfSenseLease(r)).filter((l): l is RouterLease => l !== null);
}

function str(v: unknown): string | undefined {
  if (v == null) return undefined;
  const s = String(v).trim();
  return s.length ? s : undefined;
}

function num(v: unknown): number | undefined {
  if (v == null || v === '') return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}
