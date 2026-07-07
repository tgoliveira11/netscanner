import type { Device } from '@netscanner/contracts';

/**
 * Computes human-readable changes between a stored device and a fresh snapshot.
 * Drives `device.changed` events and the per-device timeline. Pure function.
 */
export function diffDevice(previous: Device, next: Device): string[] {
  const changes: string[] = [];
  if (previous.ip !== next.ip) changes.push(`ip: ${previous.ip} → ${next.ip}`);
  if (previous.hostname !== next.hostname && next.hostname)
    changes.push(`hostname: ${previous.hostname ?? '∅'} → ${next.hostname}`);
  if (previous.deviceType !== next.deviceType)
    changes.push(`type: ${previous.deviceType} → ${next.deviceType}`);
  if (previous.vendor !== next.vendor && next.vendor)
    changes.push(`vendor: ${previous.vendor ?? '∅'} → ${next.vendor}`);

  const prevPorts = new Set(previous.services.map((s) => s.port));
  const newPorts = next.services.map((s) => s.port).filter((p) => !prevPorts.has(p));
  if (newPorts.length) changes.push(`new open ports: ${newPorts.join(', ')}`);

  if (!previous.isOnline && next.isOnline) changes.push('came online');
  return changes;
}
