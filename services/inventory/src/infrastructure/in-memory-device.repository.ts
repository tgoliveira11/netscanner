import type { Device } from '@netscanner/contracts';
import type { DeviceFilter, IDeviceRepository, RouterScrapeCredential } from '../domain/device-repository.js';
import type { StoredDevice } from '../domain/device-public.js';

/**
 * Zero-dependency repository used for tests and for running without a database.
 * Implements the same port as the Prisma adapter (LSP), so callers are agnostic.
 */
export class InMemoryDeviceRepository implements IDeviceRepository {
  private readonly devices = new Map<string, StoredDevice>();

  async findByMac(mac: string): Promise<Device | null> {
    const found = [...this.devices.values()].find((d) => d.mac === mac);
    return found ? stripStored(found) : null;
  }

  async findByIp(ip: string): Promise<Device | null> {
    const found = [...this.devices.values()].find((d) => d.ip === ip);
    return found ? stripStored(found) : null;
  }

  async findById(id: string): Promise<Device | null> {
    const stored = this.devices.get(id);
    return stored ? stripStored(stored) : null;
  }

  async findStoredById(id: string): Promise<StoredDevice | null> {
    return this.devices.get(id) ?? null;
  }

  async save(device: Device | StoredDevice): Promise<void> {
    this.devices.set(device.id, device as StoredDevice);
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
    return items.sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true })).map(stripStored);
  }

  async listRouterScrapeCredentials(): Promise<RouterScrapeCredential[]> {
    return [...this.devices.values()]
      .filter((d) => d.routerScrapeUser && d.routerScrapePassword)
      .map((d) => ({
        ip: d.ip,
        deviceType: d.deviceType,
        brand: d.brand ?? null,
        routerScrapeUser: d.routerScrapeUser!,
        routerScrapePassword: d.routerScrapePassword!,
      }));
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

function stripStored(device: StoredDevice): Device {
  const { routerScrapePassword, ...rest } = device;
  return { ...rest, routerScrapePasswordSet: Boolean(routerScrapePassword) };
}
