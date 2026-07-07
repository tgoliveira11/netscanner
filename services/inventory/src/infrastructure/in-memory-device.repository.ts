import type { Device } from '@netscanner/contracts';
import type { DeviceFilter, IDeviceRepository } from '../domain/device-repository.js';

/**
 * Zero-dependency repository used for tests and for running without a database.
 * Implements the same port as the Prisma adapter (LSP), so callers are agnostic.
 */
export class InMemoryDeviceRepository implements IDeviceRepository {
  private readonly devices = new Map<string, Device>();

  async findByMac(mac: string): Promise<Device | null> {
    return [...this.devices.values()].find((d) => d.mac === mac) ?? null;
  }

  async findByIp(ip: string): Promise<Device | null> {
    return [...this.devices.values()].find((d) => d.ip === ip) ?? null;
  }

  async findById(id: string): Promise<Device | null> {
    return this.devices.get(id) ?? null;
  }

  async save(device: Device): Promise<void> {
    this.devices.set(device.id, device);
  }

  async list(filter?: DeviceFilter): Promise<Device[]> {
    let items = [...this.devices.values()];
    if (filter?.deviceType) items = items.filter((d) => d.deviceType === filter.deviceType);
    if (filter?.onlineOnly) items = items.filter((d) => d.isOnline);
    if (filter?.search) {
      const q = filter.search.toLowerCase();
      items = items.filter((d) =>
        [d.ip, d.mac, d.vendor, d.hostname, d.label].some((v) => v?.toLowerCase().includes(q)),
      );
    }
    return items.sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
  }

  async markOfflineExcept(onlineIds: string[]): Promise<string[]> {
    const keep = new Set(onlineIds);
    const changed: string[] = [];
    for (const device of this.devices.values()) {
      if (!keep.has(device.id) && device.isOnline) {
        this.devices.set(device.id, { ...device, isOnline: false });
        changed.push(device.id);
      }
    }
    return changed;
  }
}
