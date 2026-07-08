import { z } from 'zod';

export const TopologyEdgeKind = z.enum(['wifi', 'wired', 'unknown']);
export type TopologyEdgeKind = z.infer<typeof TopologyEdgeKind>;

export const TopologyEdgeSchema = z.object({
  from: z.string(),
  to: z.string(),
  kind: TopologyEdgeKind,
  ssid: z.string().optional(),
  label: z.string().optional(),
  vlan: z.string().optional(),
  vlanLabel: z.string().optional(),
});
export type TopologyEdge = z.infer<typeof TopologyEdgeSchema>;

export const TopologyVlanSchema = z.object({
  id: z.string(),
  label: z.string(),
});
export type TopologyVlan = z.infer<typeof TopologyVlanSchema>;

export const TopologyNodeRole = z.enum(['wan', 'gateway', 'wired-router', 'wifi-ap', 'endpoint']);
export type TopologyNodeRole = z.infer<typeof TopologyNodeRole>;

export const TopologyNodeSchema = z.object({
  id: z.string(),
  role: TopologyNodeRole,
  tier: z.number().int().min(0),
  wifiCapable: z.boolean().optional(),
});
export type TopologyNode = z.infer<typeof TopologyNodeSchema>;

export const TopologySsidSchema = z.object({
  routerId: z.string(),
  routerIp: z.string(),
  ssid: z.string(),
  up: z.boolean(),
  band: z.string().optional(),
  channel: z.union([z.number(), z.string()]).optional(),
  clientCount: z.number(),
});
export type TopologySsid = z.infer<typeof TopologySsidSchema>;

export const TopologyResponseSchema = z.object({
  gatewayId: z.string().nullable(),
  edges: z.array(TopologyEdgeSchema),
  ssids: z.array(TopologySsidSchema),
  vlans: z.array(TopologyVlanSchema).default([]),
  nodes: z.array(TopologyNodeSchema).default([]),
});
export type TopologyResponse = z.infer<typeof TopologyResponseSchema>;
