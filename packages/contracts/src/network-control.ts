import { z } from 'zod';

export const NS_ALIAS_BLOCK = 'NS_BLOCK';
export const NS_ALIAS_PAUSED = 'NS_PAUSED';
export const NS_ALIAS_AUTOBLOCK = 'NS_AUTOBLOCK';

export const ControlTargetSchema = z.object({
  deviceId: z.string().optional(),
  ip: z.string().optional(),
  mac: z.string().optional(),
});
export type ControlTarget = z.infer<typeof ControlTargetSchema>;

export const BlockRequestSchema = ControlTargetSchema.extend({
  reason: z.string().max(200).optional(),
});
export type BlockRequest = z.infer<typeof BlockRequestSchema>;

export const PauseRequestSchema = ControlTargetSchema.extend({
  durationMs: z.coerce.number().min(60_000).max(86_400_000).default(3_600_000),
});
export type PauseRequest = z.infer<typeof PauseRequestSchema>;

export const DhcpReservationRequestSchema = z.object({
  mac: z.string(),
  ip: z.string(),
  hostname: z.string().optional(),
  interface: z.string().optional(),
  description: z.string().optional(),
});
export type DhcpReservationRequest = z.infer<typeof DhcpReservationRequestSchema>;

export const BandwidthLimitRequestSchema = ControlTargetSchema.extend({
  downMbps: z.coerce.number().min(0.1).max(1000),
  upMbps: z.coerce.number().min(0.1).max(1000),
});
export type BandwidthLimitRequest = z.infer<typeof BandwidthLimitRequestSchema>;

export const ParentalScheduleRequestSchema = z.object({
  name: z.string().min(1).max(80),
  deviceIds: z.array(z.string()).min(1),
  weekdays: z.array(z.number().min(0).max(6)),
  startTime: z.string().regex(/^\d{2}:\d{2}$/),
  endTime: z.string().regex(/^\d{2}:\d{2}$/),
  enabled: z.boolean().default(true),
});
export type ParentalScheduleRequest = z.infer<typeof ParentalScheduleRequestSchema>;

export const ControlStatusSchema = z.object({
  blocked: z.boolean(),
  paused: z.boolean(),
  pauseExpiresAt: z.string().nullable(),
  bandwidthLimited: z.boolean(),
  dhcpReserved: z.boolean(),
});
export type ControlStatus = z.infer<typeof ControlStatusSchema>;

export const ControlBootstrapSchema = z.object({
  ready: z.boolean(),
  aliases: z.record(z.string(), z.boolean()),
  limiters: z.record(z.string(), z.boolean()),
  schedules: z.number(),
  message: z.string().optional(),
});
export type ControlBootstrap = z.infer<typeof ControlBootstrapSchema>;

export const PolicyAuditEntrySchema = z.object({
  id: z.string(),
  action: z.string(),
  target: z.string(),
  detail: z.record(z.unknown()),
  actor: z.string(),
  createdAt: z.string(),
  undone: z.boolean(),
});
export type PolicyAuditEntry = z.infer<typeof PolicyAuditEntrySchema>;

export const ControlVerifyCheckSchema = z.object({
  id: z.string(),
  label: z.string(),
  status: z.enum(['pass', 'warn', 'fail', 'skip']),
  detail: z.string().optional(),
});
export type ControlVerifyCheck = z.infer<typeof ControlVerifyCheckSchema>;

export const ControlVerifyResultSchema = z.object({
  ok: z.boolean(),
  checks: z.array(ControlVerifyCheckSchema),
  ranAt: z.string(),
});
export type ControlVerifyResult = z.infer<typeof ControlVerifyResultSchema>;
