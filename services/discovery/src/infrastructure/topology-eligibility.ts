import type { ConnectionLookup, Device } from '@netscanner/contracts';
import { MacAddress, isOk } from '@netscanner/kernel';
import type { LocalInterface } from '@netscanner/os-abstraction';
import { normalizeMac } from './wifi-topology.js';

export interface TopologyEligibilityContext {
  localIfaces: LocalInterface[];
  managedRouterIps: Set<string>;
  gatewayId: string | null;
}

/** Device is an address on the machine running the agent (e.g. bridge100 / hotspot). */
export function isLocalScannerDevice(
  device: Pick<Device, 'ip' | 'mac'>,
  ifaces: LocalInterface[],
): boolean {
  const mac = normalizeMac(device.mac);
  for (const iface of ifaces) {
    if (iface.address === device.ip) return true;
    const ifaceMac = normalizeMac(iface.mac);
    if (mac && ifaceMac && mac === ifaceMac) return true;
  }
  return false;
}

export function hasRandomizedMac(mac: string | null | undefined): boolean {
  if (!mac) return false;
  const parsed = MacAddress.create(mac);
  return isOk(parsed) && parsed.value.isLocallyAdministered;
}

/**
 * Router may appear as a wired uplink only with positive evidence — not merely
 * because it sits on .1 of a scanned subnet.
 */
export function isWiredUplinkRouter(
  device: Device,
  ctx: TopologyEligibilityContext,
  snmp: ConnectionLookup | null,
): boolean {
  if (!ctx.gatewayId || device.id === ctx.gatewayId) return false;
  if (device.deviceType !== 'router') return false;
  if (isLocalScannerDevice(device, ctx.localIfaces)) return false;
  if (device.connectionType === 'wifi' || snmp?.type === 'wifi') return false;

  if (ctx.managedRouterIps.has(device.ip)) return true;
  if (snmp?.type === 'wired') return true;

  const signals = device.signals ?? {};
  if (typeof signals.pfsenseInterface === 'string' && signals.pfsenseInterface.trim()) return true;
  if (typeof signals.routerInterface === 'string' && signals.routerInterface.trim()) return true;

  if (device.connectionType === 'wired' && !hasRandomizedMac(device.mac)) return true;

  return false;
}

/** Wired leaf device — excludes WiFi, local host interfaces, and unknown attachment. */
export function isWiredEndpoint(
  device: Device,
  snmp: ConnectionLookup | null,
  localIfaces: LocalInterface[],
): boolean {
  if (device.deviceType === 'router') return false;
  if (isLocalScannerDevice(device, localIfaces)) return false;
  if (device.connectionType === 'wifi' || snmp?.type === 'wifi') return false;
  if (device.connectionType === 'wired' || snmp?.type === 'wired') return true;
  return false;
}
