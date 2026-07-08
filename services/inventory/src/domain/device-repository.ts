import type { Device } from '@netscanner/contracts';
import type { StoredDevice } from './device-public.js';

export interface RouterScrapeCredential {
  ip: string;
  deviceType: string;
  brand: string | null;
  routerScrapeUser: string;
  routerScrapePassword: string;
}

export interface DeviceFilter {
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
  findByMac(mac: string): Promise<Device | null>;
  findByIp(ip: string): Promise<Device | null>;
  findById(id: string): Promise<Device | null>;
  findStoredById(id: string): Promise<StoredDevice | null>;
  save(device: Device | StoredDevice): Promise<void>;
  list(filter?: DeviceFilter): Promise<Device[]>;
  listRouterScrapeCredentials(): Promise<RouterScrapeCredential[]>;
  /** Mark devices not in the provided id set as offline; returns their ids. */
  markOfflineExcept(onlineIds: string[]): Promise<string[]>;
  /** Lightweight online/offline update without a full scan enrichment. */
  updatePresence(
    id: string,
    patch: { isOnline: boolean; latencyMs?: number | null },
  ): Promise<Device | null>;
}
