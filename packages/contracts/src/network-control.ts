import { z } from 'zod';

export const NS_ALIAS_BLOCK = 'NS_BLOCK';
export const NS_ALIAS_PAUSED = 'NS_PAUSED';
export const NS_ALIAS_AUTOBLOCK = 'NS_AUTOBLOCK';
/** FQDN entries stored in a host alias (pfSense REST has no `url` type). */
export const NS_ALIAS_DNS_BLOCK = 'NS_DNS_BLOCK';
/** Host IPs subject to DNS block rules (source alias). */
export const NS_ALIAS_DNS_SRC = 'NS_DNS_SRC';
/** Network/host destinations to block (CIDR or IP, optional :port in audit only). */
export const NS_ALIAS_DEST_BLOCK = 'NS_DEST_BLOCK';
export const NS_ALIAS_DEST_SRC = 'NS_DEST_SRC';
/** Policy routing: device IP in exactly one route alias (floating pass + gateway on pfSense). */
export const NS_ALIAS_ROUTE_WAN = 'NS_ROUTE_WAN';
export const NS_ALIAS_ROUTE_LB = 'NS_ROUTE_LB';
export const NS_ALIAS_ROUTE_VPN = 'NS_ROUTE_VPN';

export const RouteProfileSchema = z.enum(['wan', 'lb', 'vpn', 'default']);
export type RouteProfile = z.infer<typeof RouteProfileSchema>;

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

export const DnsBlockRequestSchema = ControlTargetSchema.extend({
  domain: z.string().min(1).max(253).transform((d) => d.trim().toLowerCase().replace(/^\.+/, '')),
});
export type DnsBlockRequest = z.infer<typeof DnsBlockRequestSchema>;

export const DestBlockRequestSchema = ControlTargetSchema.extend({
  /** IPv4, CIDR, or host — optional :port stored in audit; pfSense rule may need manual port match. */
  destination: z.string().min(1).max(80),
});
export type DestBlockRequest = z.infer<typeof DestBlockRequestSchema>;

export const RoutePolicyRequestSchema = ControlTargetSchema.extend({
  /** pfSense gateway or gateway-group name; null clears policy routing. */
  gatewayName: z.string().max(80).nullable().optional(),
  /** Legacy shortcut — resolved to a gateway when gatewayName omitted. */
  profile: RouteProfileSchema.optional(),
}).refine((d) => d.gatewayName !== undefined || d.profile !== undefined, {
  message: 'gatewayName or profile required',
});
export type RoutePolicyRequest = z.infer<typeof RoutePolicyRequestSchema>;

export const RouteOptionSchema = z.object({
  name: z.string(),
  kind: z.enum(['wan', 'lb', 'vpn', 'group', 'other']),
  label: z.string(),
  online: z.boolean().optional(),
  description: z.string().nullable().optional(),
});
export type RouteOption = z.infer<typeof RouteOptionSchema>;

export const ControlStatusSchema = z.object({
  blocked: z.boolean(),
  paused: z.boolean(),
  pauseExpiresAt: z.string().nullable(),
  bandwidthLimited: z.boolean(),
  dhcpReserved: z.boolean(),
  dnsBlocked: z.boolean(),
  dnsBlockedDomains: z.array(z.string()),
  destBlocked: z.boolean(),
  destBlockedEntries: z.array(z.string()),
  egressRoute: RouteProfileSchema.nullable(),
  egressGateway: z.string().nullable(),
});
export type ControlStatus = z.infer<typeof ControlStatusSchema>;

/** pfSense host alias for policy routing to a specific gateway/group. */
export function routeAliasForGateway(gatewayName: string): string {
  const sanitized = gatewayName
    .replace(/[^A-Za-z0-9_]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_|_$/g, '');
  const body = (sanitized || 'GW').slice(0, 24);
  return `NS_RT_${body}`;
}

export function classifyGatewayKind(name: string): RouteOption['kind'] {
  const n = name.toUpperCase();
  if (n === 'LB_WAN' || n.startsWith('LB_')) return 'lb';
  if (/VPN|OVPN|WIREGUARD|WG_|SURFSHARK|SSVPN|TUN_/.test(n)) return 'vpn';
  if (/^WAN|WAN_DHCP|CLARO|VIVO|ISP/.test(n)) return 'wan';
  if (/FAILOVER|_GROUP/.test(n)) return 'group';
  return 'other';
}

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
