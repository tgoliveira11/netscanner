import type { Device } from '@netscanner/contracts';

export interface InterfaceSignal {
  name?: string | null;
  descr?: string | null;
  ipaddr?: string | null;
  mac?: string | null;
}

export interface InfrastructureAliasInfo {
  ip: string;
  mac: string | null;
  interfaceLabel: string | null;
}

export interface CollapseInfrastructureOptions {
  /** Prefer this IP as the canonical record (e.g. from PFSENSE_URL / SNMP host). */
  preferredIp?: string | null;
}

export function normalizeMac(mac: string | null | undefined): string | null {
  if (!mac) return null;
  const hex = mac.toLowerCase().replace(/[^0-9a-f]/g, '');
  return hex.length === 12 ? hex : null;
}

function isPhysMac(mac: string | null | undefined): boolean {
  const n = normalizeMac(mac);
  return Boolean(n && /^[0-9a-f]{12}$/.test(n));
}

function asRows<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : [];
}

/**
 * Union of interface rows from router telemetry attached to inventory (pfSense
 * `pfsenseInterfaces` today; same shape works for other multi-homed gateways).
 */
export function collectInfrastructureInterfaces(devices: Device[]): InterfaceSignal[] {
  const byIp = new Map<string, InterfaceSignal>();
  for (const device of devices) {
    const ifaces = asRows<InterfaceSignal>(device.signals?.pfsenseInterfaces);
    for (const iface of ifaces) {
      if (!iface.ipaddr) continue;
      const prev = byIp.get(iface.ipaddr);
      if (!prev || (!prev.mac && iface.mac)) byIp.set(iface.ipaddr, iface);
    }
  }
  return [...byIp.values()];
}

/** True when this row is a NIC of a multi-homed router/firewall, not a leaf client. */
export function isInfrastructureInterface(
  device: Device,
  catalog: InterfaceSignal[],
): boolean {
  if (catalog.length === 0) return false;
  const mac = normalizeMac(device.mac);
  for (const iface of catalog) {
    if (iface.ipaddr && iface.ipaddr === device.ip) return true;
    if (mac && isPhysMac(iface.mac) && normalizeMac(iface.mac) === mac) return true;
  }
  return false;
}

/** pfSense / multi-homed gateway NIC — same check used by topology graph building. */
export function isPfSenseSelfNic(device: Device, allDevices?: Device[]): boolean {
  const catalog = allDevices
    ? collectInfrastructureInterfaces(allDevices)
    : collectInfrastructureInterfaces([device]);
  return isInfrastructureInterface(device, catalog);
}

function scoreCanonical(device: Device, preferredIp?: string | null): number {
  let score = 0;
  if (preferredIp && device.ip === preferredIp) score += 1000;
  if (device.deviceType === 'firewall') score += 100;
  if (device.signals?.pfsenseHostname) score += 50;
  const iface = String(device.signals?.pfsenseInterface ?? '');
  if (/MAIN/i.test(iface)) score += 30;
  if (device.mac) score += 10;
  const last = Number(device.ip.split('.').pop());
  if (!Number.isNaN(last)) score -= last;
  return score;
}

export function pickCanonicalInfrastructure(
  aliases: Device[],
  options: CollapseInfrastructureOptions = {},
): Device {
  return [...aliases].sort(
    (a, b) => scoreCanonical(b, options.preferredIp) - scoreCanonical(a, options.preferredIp),
  )[0]!;
}

function interfaceLabelFor(
  device: Device,
  catalog: InterfaceSignal[],
): string | null {
  const row = catalog.find((i) => i.ipaddr === device.ip);
  const fromCatalog = row?.descr ?? row?.name ?? null;
  if (fromCatalog) return fromCatalog;
  const lease = device.signals?.pfsenseInterface;
  return typeof lease === 'string' && lease ? lease : null;
}

/**
 * Collapse duplicate inventory rows for the same multi-homed appliance into one
 * canonical device. Secondary VLAN/WAN NICs are removed from the list; their IPs
 * are exposed on the canonical row via `signals.infrastructureIps` /
 * `signals.infrastructureAliases`.
 */
export function collapseInfrastructureAliases(
  devices: Device[],
  options: CollapseInfrastructureOptions = {},
): Device[] {
  const catalog = collectInfrastructureInterfaces(devices);
  if (catalog.length === 0) return devices;

  const aliasRows: Device[] = [];
  const other: Device[] = [];
  for (const device of devices) {
    if (isInfrastructureInterface(device, catalog)) aliasRows.push(device);
    else other.push(device);
  }
  if (aliasRows.length <= 1) return devices;

  const canonical = pickCanonicalInfrastructure(aliasRows, options);
  const aliasIps: InfrastructureAliasInfo[] = aliasRows
    .filter((d) => d.id !== canonical.id)
    .map((d) => ({
      ip: d.ip,
      mac: d.mac,
      interfaceLabel: interfaceLabelFor(d, catalog),
    }));
  const allIps = [...new Set(aliasRows.map((d) => d.ip))].sort();

  const enrichedCanonical: Device = {
    ...canonical,
    signals: {
      ...canonical.signals,
      infrastructureAliases: aliasIps,
      infrastructureIps: allIps,
    },
  };

  return [...other, enrichedCanonical];
}
