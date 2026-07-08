import { DeviceSchema, type Device, type OsGuess, type SecurityFlag, type ServiceInfo } from '@netscanner/contracts';
import type { StoredDevice } from '../domain/device-public.js';

/** Shape of a persisted row (matches the Prisma DeviceRecord model). */
export interface DeviceRow {
  id: string;
  siteId: string;
  ip: string;
  mac: string | null;
  vendor: string | null;
  brand: string | null;
  model: string | null;
  hostname: string | null;
  deviceType: string;
  classificationConfidence: number;
  connectionType: string;
  latencyMs: number | null;
  isOnline: boolean;
  label: string | null;
  notes: string | null;
  routerScrapeUser: string | null;
  routerScrapePassword: string | null;
  osJson: string | null;
  servicesJson: string;
  securityFlagsJson: string;
  signalsJson: string;
  firstSeen: Date;
  lastSeen: Date;
}

/** Maps between the domain Device and the flat persistence row (SRP). */
export const DeviceMapper = {
  toStored(row: DeviceRow): StoredDevice {
    return {
      ...DeviceMapper.toDomain(row),
      siteId: row.siteId,
      routerScrapePassword: row.routerScrapePassword,
    };
  },

  toDomain(row: DeviceRow): Device {
    return DeviceSchema.parse({
      id: row.id,
      ip: row.ip,
      mac: row.mac,
      vendor: row.vendor,
      brand: row.brand,
      model: row.model,
      hostname: row.hostname,
      deviceType: row.deviceType,
      classificationConfidence: row.classificationConfidence,
      os: row.osJson ? (JSON.parse(row.osJson) as OsGuess) : null,
      connectionType: row.connectionType,
      services: JSON.parse(row.servicesJson) as ServiceInfo[],
      latencyMs: row.latencyMs,
      isOnline: row.isOnline,
      securityFlags: JSON.parse(row.securityFlagsJson) as SecurityFlag[],
      label: row.label,
      notes: row.notes,
      routerScrapeUser: row.routerScrapeUser,
      routerScrapePasswordSet: Boolean(row.routerScrapePassword),
      firstSeen: row.firstSeen.toISOString(),
      lastSeen: row.lastSeen.toISOString(),
      signals: JSON.parse(row.signalsJson) as Record<string, unknown>,
    });
  },

  toRow(device: Device, siteId: string): DeviceRow {
    return {
      id: device.id,
      siteId,
      ip: device.ip,
      mac: device.mac,
      vendor: device.vendor,
      brand: device.brand ?? null,
      model: device.model ?? null,
      hostname: device.hostname,
      deviceType: device.deviceType,
      classificationConfidence: device.classificationConfidence,
      connectionType: device.connectionType,
      latencyMs: device.latencyMs,
      isOnline: device.isOnline,
      label: device.label,
      notes: device.notes,
      routerScrapeUser: (device as StoredDevice).routerScrapeUser ?? null,
      routerScrapePassword: (device as StoredDevice).routerScrapePassword ?? null,
      osJson: device.os ? JSON.stringify(device.os) : null,
      servicesJson: JSON.stringify(device.services),
      securityFlagsJson: JSON.stringify(device.securityFlags),
      signalsJson: JSON.stringify(device.signals),
      firstSeen: new Date(device.firstSeen),
      lastSeen: new Date(device.lastSeen),
    };
  },
};
