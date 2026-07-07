import { z } from 'zod';
import { DeviceSchema } from './device.js';
import { ScanSessionSchema } from './scan.js';

/** REST response envelopes shared by gateway and web client. */
export const DeviceListResponseSchema = z.object({
  devices: z.array(DeviceSchema),
  total: z.number(),
});
export type DeviceListResponse = z.infer<typeof DeviceListResponseSchema>;

export const ScanResponseSchema = z.object({
  scan: ScanSessionSchema,
});
export type ScanResponse = z.infer<typeof ScanResponseSchema>;

export const UpdateDeviceRequestSchema = z.object({
  label: z.string().max(120).nullable().optional(),
  notes: z.string().max(2000).nullable().optional(),
});
export type UpdateDeviceRequest = z.infer<typeof UpdateDeviceRequestSchema>;

export const ExportFormat = z.enum(['json', 'csv']);
export type ExportFormat = z.infer<typeof ExportFormat>;

export const HealthResponseSchema = z.object({
  status: z.literal('ok'),
  capabilities: z.object({
    nmap: z.boolean(),
    elevated: z.boolean(),
  }),
  version: z.string(),
});
export type HealthResponse = z.infer<typeof HealthResponseSchema>;
