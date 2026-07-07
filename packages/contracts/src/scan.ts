import { z } from 'zod';

export const ScanType = z.enum(['quick', 'standard', 'deep']);
export type ScanType = z.infer<typeof ScanType>;

export const ScanStatus = z.enum(['pending', 'discovering', 'fingerprinting', 'completed', 'failed']);
export type ScanStatus = z.infer<typeof ScanStatus>;

export const StartScanRequestSchema = z.object({
  /** Target subnet in CIDR. If omitted, the gateway auto-detects the primary subnet. */
  cidr: z.string().optional(),
  scanType: ScanType.default('standard'),
});
export type StartScanRequest = z.infer<typeof StartScanRequestSchema>;

export const ScanSessionSchema = z.object({
  id: z.string(),
  cidr: z.string(),
  scanType: ScanType,
  status: ScanStatus,
  hostsTotal: z.number(),
  hostsDiscovered: z.number(),
  devicesClassified: z.number(),
  startedAt: z.string(),
  finishedAt: z.string().nullable(),
  error: z.string().nullable(),
});
export type ScanSession = z.infer<typeof ScanSessionSchema>;

/** Raw output of the discovery stage before fingerprinting/classification. */
export interface DiscoveredHost {
  ip: string;
  mac: string | null;
  hostname: string | null;
  latencyMs: number | null;
  sources: string[]; // e.g. ['arp', 'ping', 'mdns']
  signals: Record<string, unknown>;
}
