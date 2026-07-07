import type { Device } from '@netscanner/contracts';

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
  save(device: Device): Promise<void>;
  list(filter?: DeviceFilter): Promise<Device[]>;
  /** Mark devices not in the provided id set as offline; returns their ids. */
  markOfflineExcept(onlineIds: string[]): Promise<string[]>;
}
