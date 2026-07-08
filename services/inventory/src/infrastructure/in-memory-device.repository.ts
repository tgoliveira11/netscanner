import type { Device } from '@netscanner/contracts';
import type { DeviceFilter, IDeviceRepository, RouterScrapeCredential } from '../domain/device-repository.js';
import type { StoredDevice } from '../domain/device-public.js';

/**
 * Zero-dependency repository used for tests and for running without a database.
 * Implements the same port as the Prisma adapter (LSP), so callers are agnostic.
 */
export class InMemoryDeviceRepository implements IDeviceRepository {
  private readonly devices = new Map<string, StoredDevice & { siteId: string }>();

  async findByMac(siteId: string, mac: string): Promise<Device | null> {
    const found = [...this.devices.values()].find((d) => d.siteId === siteId && d.mac === mac);
    return found ? stripStored(found) : null;
  }

  async findByIp(siteId: string, ip: string): Promise<Device | null> {
    const found = [...this.devices.values()].find((d) => d.siteId === siteId && d.ip === ip);
    return found ? stripStored(found) : null;
  }

  async findById(id: string): Promise<Device | null> {
    const stored = this.devices.get(id);
    return stored ? stripStored(stored) : null;
  }

  async findStoredById(id: string): Promise<StoredDevice | null> {
    const stored = this.devices.get(id);
    if (!stored) return null;
    const { siteId: _s, ...rest } = stored;
    return rest;
  }

  async save(device: Device | StoredDevice, siteId: string): Promise<void> {
    this.devices.set(device.id, { ...(device as StoredDevice), siteId });
  }

  async list(filter?: DeviceFilter): Promise<Device[]> {
    let items = [...this.devices.values()];
    if (filter?.siteId) items = items.filter((d) => d.siteId === filter.siteId);
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

  async listRouterScrapeCredentials(siteId: string): Promise<RouterScrapeCredential[]> {
    return [...this.devices.values()]
      .filter(
        (d) =>
          d.siteId === siteId && d.routerScrapeUser && d.routerScrapePassword,
      )
      .map((d) => ({
        ip: d.ip,
        deviceType: d.deviceType,
        brand: d.brand ?? null,
        routerScrapeUser: d.routerScrapeUser!,
        routerScrapePassword: d.routerScrapePassword!,
      }));
  }

  async markOfflineExcept(onlineIds: string[], siteId: string): Promise<string[]> {
    const keep = new Set(onlineIds);
    const changed: string[] = [];
    for (const device of this.devices.values()) {
      if (device.siteId !== siteId) continue;
      if (!keep.has(device.id) && device.isOnline) {
        this.devices.set(device.id, { ...device, isOnline: false });
        changed.push(device.id);
      }
    }
    return changed;
  }

  async updatePresence(
    id: string,
    patch: { isOnline: boolean; latencyMs?: number | null },
  ): Promise<Device | null> {
    const stored = this.devices.get(id);
    if (!stored) return null;
    const next = {
      ...stored,
      isOnline: patch.isOnline,
      latencyMs: patch.latencyMs === undefined ? stored.latencyMs : patch.latencyMs,
      lastSeen: patch.isOnline ? new Date().toISOString() : stored.lastSeen,
    };
    this.devices.set(id, next);
    return stripStored(next);
  }
}

function stripStored(device: StoredDevice): Device {
  const { routerScrapePassword, ...rest } = device;
  return { ...rest, routerScrapePasswordSet: Boolean(routerScrapePassword) };
}
