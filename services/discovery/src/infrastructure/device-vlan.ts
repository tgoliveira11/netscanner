import type { Device } from '@netscanner/contracts';

export interface DeviceVlan {
  id: string;
  label: string;
}

/** pfSense/router interface name when known; otherwise /24 subnet from the device IP. */
export function resolveDeviceVlan(device: Pick<Device, 'ip' | 'signals'>): DeviceVlan {
  const signals = device.signals ?? {};
  const iface = signals.pfsenseInterface ?? signals.routerInterface;
  if (typeof iface === 'string' && iface.trim()) {
    const label = iface.trim();
    return { id: label, label };
  }

  const parts = device.ip.split('.');
  if (parts.length === 4) {
    const subnet = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    return { id: subnet, label: subnet };
  }

  return { id: 'unknown', label: 'Unknown' };
}
