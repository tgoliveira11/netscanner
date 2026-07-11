import { z } from 'zod';

export const CpeAccessOpenRequestSchema = z.object({
  ip: z.string().min(1),
  username: z.string().min(1),
  password: z.string().min(1),
  label: z.string().optional(),
  port: z.number().int().positive().optional(),
  tls: z.boolean().optional(),
});
export type CpeAccessOpenRequest = z.infer<typeof CpeAccessOpenRequestSchema>;

export const CpeAccessSessionSchema = z.object({
  id: z.string(),
  ip: z.string(),
  port: z.number().int().positive(),
  tls: z.boolean(),
  label: z.string().nullable(),
  username: z.string(),
  /** How the agent reaches the CPE. */
  via: z.enum(['direct', 'pfsense-tunnel']),
  /** Browser path prefix (same-origin) ending with /. */
  proxyPath: z.string(),
  /** Absolute URL for convenience when UI knows the agent origin. */
  openUrl: z.string(),
  createdAt: z.string(),
  /** null = open until explicitly closed in Admin. */
  expiresAt: z.string().nullable(),
});
export type CpeAccessSession = z.infer<typeof CpeAccessSessionSchema>;

export const CpeAccessOpenResponseSchema = z.object({
  ok: z.boolean(),
  session: CpeAccessSessionSchema.optional(),
  error: z.string().optional(),
  hint: z.string().optional(),
});
export type CpeAccessOpenResponse = z.infer<typeof CpeAccessOpenResponseSchema>;

export const CpeAccessListResponseSchema = z.object({
  sessions: z.array(CpeAccessSessionSchema),
  pfsenseTunnelAvailable: z.boolean(),
});
export type CpeAccessListResponse = z.infer<typeof CpeAccessListResponseSchema>;
