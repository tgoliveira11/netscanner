import type { PrismaClient } from '@prisma/client';
import type { Device } from '@netscanner/contracts';
import type { DeviceFilter, IDeviceRepository, RouterScrapeCredential } from '../domain/device-repository.js';
import type { StoredDevice } from '../domain/device-public.js';
import { DeviceMapper, type DeviceRow } from './device-mapper.js';

/**
 * SQLite/Postgres-backed repository (via Prisma). Persists the device inventory
 * so history, first/last-seen, and new-device detection survive restarts.
 */
export class PrismaDeviceRepository implements IDeviceRepository {
  constructor(private readonly prisma: PrismaClient) {}

  async findByMac(mac: string): Promise<Device | null> {
    const row = await this.prisma.deviceRecord.findUnique({ where: { mac } });
    return row ? DeviceMapper.toDomain(row as DeviceRow) : null;
  }

  async findByIp(ip: string): Promise<Device | null> {
    const row = await this.prisma.deviceRecord.findFirst({
      where: { ip },
      orderBy: { lastSeen: 'desc' },
    });
    return row ? DeviceMapper.toDomain(row as DeviceRow) : null;
  }

  async findById(id: string): Promise<Device | null> {
    const row = await this.prisma.deviceRecord.findUnique({ where: { id } });
    return row ? DeviceMapper.toDomain(row as DeviceRow) : null;
  }

  async findStoredById(id: string): Promise<StoredDevice | null> {
    const row = await this.prisma.deviceRecord.findUnique({ where: { id } });
    return row ? DeviceMapper.toStored(row as DeviceRow) : null;
  }

  async save(device: Device | StoredDevice): Promise<void> {
    const row = DeviceMapper.toRow(device);
    await this.prisma.deviceRecord.upsert({
      where: { id: row.id },
      create: row,
      update: row,
    });
  }

  async list(filter?: DeviceFilter): Promise<Device[]> {
    const rows = await this.prisma.deviceRecord.findMany({
      where: {
        deviceType: filter?.deviceType,
        isOnline: filter?.onlineOnly ? true : undefined,
        ...(filter?.search
          ? {
              OR: [
                { ip: { contains: filter.search } },
                { mac: { contains: filter.search } },
                { vendor: { contains: filter.search } },
                { hostname: { contains: filter.search } },
                { label: { contains: filter.search } },
              ],
            }
          : {}),
      },
      orderBy: { ip: 'asc' },
    });
    return rows.map((r) => DeviceMapper.toDomain(r as DeviceRow));
  }

  async listRouterScrapeCredentials(): Promise<RouterScrapeCredential[]> {
    const rows = await this.prisma.deviceRecord.findMany({
      where: { routerScrapeUser: { not: null }, routerScrapePassword: { not: null } },
      select: {
        ip: true,
        deviceType: true,
        brand: true,
        routerScrapeUser: true,
        routerScrapePassword: true,
      },
    });
    return rows
      .filter((r) => r.routerScrapeUser && r.routerScrapePassword)
      .map((r) => ({
        ip: r.ip,
        deviceType: r.deviceType,
        brand: r.brand,
        routerScrapeUser: r.routerScrapeUser!,
        routerScrapePassword: r.routerScrapePassword!,
      }));
  }

  async markOfflineExcept(onlineIds: string[]): Promise<string[]> {
    const stale = await this.prisma.deviceRecord.findMany({
      where: { id: { notIn: onlineIds }, isOnline: true },
      select: { id: true },
    });
    if (stale.length) {
      await this.prisma.deviceRecord.updateMany({
        where: { id: { in: stale.map((s) => s.id) } },
        data: { isOnline: false },
      });
    }
    return stale.map((s) => s.id);
  }

  async updatePresence(
    id: string,
    patch: { isOnline: boolean; latencyMs?: number | null },
  ): Promise<Device | null> {
    try {
      const row = await this.prisma.deviceRecord.update({
        where: { id },
        data: {
          isOnline: patch.isOnline,
          ...(patch.latencyMs !== undefined ? { latencyMs: patch.latencyMs } : {}),
          ...(patch.isOnline ? { lastSeen: new Date() } : {}),
        },
      });
      return DeviceMapper.toDomain(row as DeviceRow);
    } catch {
      return null;
    }
  }
}
