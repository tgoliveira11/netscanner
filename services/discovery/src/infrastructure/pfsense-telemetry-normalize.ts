import type { PfSenseGatewayRow, PfSenseInterfaceRow } from '../domain/pfsense-telemetry.js';
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

export function normalizePfSenseGatewayRow(r: Record<string, unknown>): PfSenseGatewayRow {
  const delay = num(r['delay']);
  const loss = num(r['loss']);
  return {
    name: str(r['name']) ?? null,
    gateway: str(r['gateway'] ?? r['srcip']) ?? null,
    monitor: str(r['monitor'] ?? r['monitorip']) ?? null,
    status: str(r['status']) ?? null,
    delay: delay ?? null,
    loss: loss ?? null,
    interface: str(r['interface'] ?? r['if']) ?? null,
  };
}

export function normalizePfSenseInterfaceRow(r: Record<string, unknown>): PfSenseInterfaceRow {
  const vlan = r['vlan'] ?? r['vlanif'];
  return {
    name: str(r['name'] ?? r['if']) ?? null,
    descr: str(r['descr'] ?? r['description']) ?? null,
    ipaddr: str(r['ipaddr'] ?? r['ip']) ?? null,
    subnet: str(r['subnet']) ?? null,
    vlan: vlan != null ? String(vlan) : null,
    mac: str(r['macaddr'] ?? r['mac'] ?? r['hwif']) ?? null,
    status: str(r['status']) ?? null,
  };
}

/** Map internal iface keys (e.g. opt4) to GUI labels (e.g. LAN_MAIN). */
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
