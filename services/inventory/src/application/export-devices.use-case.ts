import type { Device } from '@netscanner/contracts';
import type { IDeviceRepository } from '../domain/device-repository.js';

export type ExportFormat = 'json' | 'csv';

const CSV_HEADERS = [
  'ip',
  'mac',
  'brand',
  'model',
  'vendor',
  'hostname',
  'deviceType',
  'osFamily',
  'osVersion',
  'connectionType',
  'classificationConfidence',
  'isOnline',
  'firstSeen',
  'lastSeen',
  'label',
] as const;

function deviceToCsvRow(d: Device): string[] {
  return [
    d.ip,
    d.mac ?? '',
    d.brand ?? '',
    d.model ?? '',
    d.vendor ?? '',
    d.hostname ?? '',
    d.deviceType,
    d.os?.family ?? d.os?.name ?? '',
    d.os?.version ?? '',
    d.connectionType,
    String(d.classificationConfidence),
    String(d.isOnline),
    d.firstSeen,
    d.lastSeen,
    d.label ?? '',
  ];
}

function csvEscape(value: unknown): string {
  const str = value == null ? '' : String(value);
  return /[",\n]/.test(str) ? `"${str.replace(/"/g, '""')}"` : str;
}

/** Exports the inventory as JSON or CSV for reporting/backup. */
export class ExportDevicesUseCase {
  constructor(private readonly repo: IDeviceRepository) {}

  async execute(format: ExportFormat): Promise<{ body: string; contentType: string; filename: string }> {
    const devices = await this.repo.list();
    if (format === 'json') {
      return {
        body: JSON.stringify(devices, null, 2),
        contentType: 'application/json',
        filename: 'netscanner-devices.json',
      };
    }
    const header = CSV_HEADERS.join(',');
    const rows = devices.map((d) => deviceToCsvRow(d).map(csvEscape).join(','));
    return {
      body: [header, ...rows].join('\n'),
      contentType: 'text/csv',
      filename: 'netscanner-devices.csv',
    };
  }
}
