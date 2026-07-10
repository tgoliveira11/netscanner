import { z } from 'zod';

export const CompalSsidRowSchema = z.object({
  device: z.string(),
  ifname: z.string(),
  ssid: z.string(),
  up: z.boolean(),
  mode: z.string().optional(),
  channel: z.union([z.number(), z.string()]).optional(),
  disabled: z.boolean().optional(),
});
export type CompalSsidRow = z.infer<typeof CompalSsidRowSchema>;

export const CompalAdminDeviceSchema = z.object({
  url: z.string(),
  host: z.string(),
  ok: z.boolean(),
  error: z.string().optional(),
  meshEnabled: z.boolean().nullable(),
  ssids: z.array(z.string()),
  ssidRows: z.array(CompalSsidRowSchema),
  uptimeSec: z.number().optional(),
  uptimeLabel: z.string().optional(),
  localtime: z.string().optional(),
});
export type CompalAdminDevice = z.infer<typeof CompalAdminDeviceSchema>;

export const CompalStepSchema = z.object({
  level: z.enum(['info', 'warn', 'success', 'error']),
  message: z.string(),
  at: z.string(),
});
export type CompalStep = z.infer<typeof CompalStepSchema>;

export const CompalStreamEventSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('step'), level: CompalStepSchema.shape.level, message: z.string(), at: z.string() }),
  z.object({
    type: z.literal('done'),
    ok: z.boolean(),
    url: z.string(),
    meshEnabled: z.boolean().nullable().optional(),
    uptimeSec: z.number().optional(),
    message: z.string().optional(),
  }),
]);
export type CompalStreamEvent = z.infer<typeof CompalStreamEventSchema>;

export type CompalDoneEvent = Extract<CompalStreamEvent, { type: 'done' }>;

export const CompalAdminResponseSchema = z.object({
  configured: z.boolean(),
  devices: z.array(CompalAdminDeviceSchema),
});
export type CompalAdminResponse = z.infer<typeof CompalAdminResponseSchema>;

export const CompalMeshRequestSchema = z.object({
  baseUrl: z.string().url(),
  enabled: z.boolean(),
});
export type CompalMeshRequest = z.infer<typeof CompalMeshRequestSchema>;

export const CompalRebootRequestSchema = z.object({
  baseUrl: z.string().url(),
});
export type CompalRebootRequest = z.infer<typeof CompalRebootRequestSchema>;

export const CompalActionResponseSchema = z.object({
  ok: z.boolean(),
  url: z.string(),
  meshEnabled: z.boolean().nullable().optional(),
  message: z.string().optional(),
});
export type CompalActionResponse = z.infer<typeof CompalActionResponseSchema>;
