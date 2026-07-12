import type { Device } from '@netscanner/contracts';
import type { StoredDevice } from './device-public.js';

export interface RouterScrapeCredential {
  ip: string;
  mac: string | null;
  deviceType: string;
  brand: string | null;
  hostname: string | null;
  isOnline?: boolean;
  /** Present when the operator saved panel credentials on the device. */
  routerScrapeUser: string | null;
  routerScrapePassword: string | null;
}

export interface DeviceFilter {
  siteId?: string;
  search?: string;
  deviceType?: string;
  onlineOnly?: boolean;
}

/**
 * Persistence port for devices (DIP + ISP). The application layer depends on
 * this interface only; the Prisma adapter is one interchangeable implementation
 * (an in-memory fake is used in tests).
 */
export interface IDeviceRepository {
  findByMac(siteId: string, mac: string): Promise<Device | null>;
  findByIp(siteId: string, ip: string): Promise<Device | null>;
  findById(id: string): Promise<Device | null>;
  findStoredById(id: string): Promise<StoredDevice | null>;
  save(device: Device | StoredDevice, siteId: string): Promise<void>;
  list(filter?: DeviceFilter): Promise<Device[]>;
  listRouterScrapeCredentials(siteId: string): Promise<RouterScrapeCredential[]>;
  /** Mark devices not in the provided id set as offline within a site; returns their ids. */
  markOfflineExcept(onlineIds: string[], siteId: string): Promise<string[]>;
  /** Lightweight online/offline update without a full scan enrichment. */
  updatePresence(
    id: string,
    patch: { isOnline: boolean; latencyMs?: number | null },
  ): Promise<Device | null>;
}
