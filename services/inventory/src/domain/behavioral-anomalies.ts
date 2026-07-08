import type { Device, DnsProfile } from '@netscanner/contracts';

export interface BehavioralAnomaly {
  code: string;
  severity: 'info' | 'low' | 'medium' | 'high';
  message: string;
}

export interface DeviceBaseline {
  openPorts: number[];
  externalDomains: string[];
  mac: string | null;
  vendor: string | null;
}

function readBaseline(signals: Record<string, unknown>): DeviceBaseline | null {
  const raw = signals.baseline;
  if (!raw || typeof raw !== 'object') return null;
  const b = raw as Record<string, unknown>;
  return {
    openPorts: Array.isArray(b.openPorts) ? b.openPorts.map(Number).filter(Number.isFinite) : [],
    externalDomains: Array.isArray(b.externalDomains) ? b.externalDomains.map(String) : [],
    mac: typeof b.mac === 'string' ? b.mac : null,
    vendor: typeof b.vendor === 'string' ? b.vendor : null,
  };
}

function externalDomainsFromDns(signals: Record<string, unknown>): string[] {
  const profile = signals.dnsProfile as DnsProfile | undefined;
  if (!profile?.topDomains?.length) return [];
  return profile.topDomains
    .map((d) => d.domain)
    .filter((d) => !/\.(local|lan|home|internal)$/i.test(d));
}

/** Compare a fresh device snapshot against its stored baseline. */
export function detectBehavioralAnomalies(
  previous: Device,
  next: Device,
): BehavioralAnomaly[] {
  const anomalies: BehavioralAnomaly[] = [];
  const baseline = readBaseline(previous.signals) ?? {
    openPorts: previous.services.filter((s) => s.state === 'open').map((s) => s.port),
    externalDomains: externalDomainsFromDns(previous.signals),
    mac: previous.mac,
    vendor: previous.vendor,
  };

  const prevPorts = new Set(baseline.openPorts);
  const newPorts = next.services
    .filter((s) => s.state === 'open')
    .map((s) => s.port)
    .filter((p) => !prevPorts.has(p));
  if (newPorts.length && baseline.openPorts.length > 0) {
    anomalies.push({
      code: 'NEW_OPEN_PORT',
      severity: newPorts.some((p) => [22, 23, 3389, 445].includes(p)) ? 'high' : 'medium',
      message: `New open port(s): ${newPorts.join(', ')}`,
    });
  }

  if (
    baseline.mac &&
    next.mac &&
    baseline.mac.toLowerCase() !== next.mac.toLowerCase()
  ) {
    anomalies.push({
      code: 'MAC_CHANGED',
      severity: 'high',
      message: `MAC changed: ${baseline.mac} → ${next.mac}`,
    });
  }

  if (
    baseline.vendor &&
    next.vendor &&
    baseline.vendor.toLowerCase() !== next.vendor.toLowerCase()
  ) {
    anomalies.push({
      code: 'VENDOR_CHANGED',
      severity: 'medium',
      message: `Vendor changed: ${baseline.vendor} → ${next.vendor}`,
    });
  }

  const knownExt = new Set(baseline.externalDomains);
  const currentExt = externalDomainsFromDns(next.signals);
  const newExt = currentExt.filter((d) => !knownExt.has(d));
  if (newExt.length && knownExt.size > 0) {
    anomalies.push({
      code: 'NEW_EXTERNAL_DEST',
      severity: 'low',
      message: `New external DNS destination(s): ${newExt.slice(0, 5).join(', ')}${newExt.length > 5 ? '…' : ''}`,
    });
  }

  if (previous.isOnline && !next.isOnline) {
    anomalies.push({
      code: 'DEVICE_OFFLINE',
      severity: 'info',
      message: 'Device went offline',
    });
  }

  return anomalies;
}

/** Rolling baseline persisted in device.signals for anomaly comparison. */
export function updateBaseline(device: Device): Record<string, unknown> {
  const baseline: DeviceBaseline = {
    openPorts: device.services.filter((s) => s.state === 'open').map((s) => s.port),
    externalDomains: externalDomainsFromDns(device.signals),
    mac: device.mac,
    vendor: device.vendor,
  };
  return { ...device.signals, baseline };
}
