import { z } from 'zod';

/** Stable agent identity (persisted in NETSCANNER_HOME/agent.json). */
export const AgentIdSchema = z.string().uuid();
export type AgentId = z.infer<typeof AgentIdSchema>;

/**
 * Fine-grained cluster capabilities announced in peer beacons.
 * Leader leases tasks only to peers that advertise the required capability.
 */
export const AgentCapabilitySchema = z.enum([
  'inventory-scan',
  'passive-l2',
  'snmp-bridge',
  'wifi-rf',
  'speed-agent',
  'speed-wan',
  'diagnostics',
  'presence',
  'pfsense-control',
  'compal-control',
  'ui-host',
  'cloud-sync',
  'topology-builder',
  'traffic-relations',
  'ap-scrape',
  'fingerprint-cloud',
  'camera-iot-probe',
  'site-probe',
  'elevated',
]);
export type AgentCapability = z.infer<typeof AgentCapabilitySchema>;

export const ClusterRoleSchema = z.enum(['leader', 'worker', 'ui-only']);
export type ClusterRole = z.infer<typeof ClusterRoleSchema>;

export const AgentProfileSchema = z.enum(['full', 'scan-only', 'ui-only']);
export type AgentProfile = z.infer<typeof AgentProfileSchema>;

const AgentCapabilitiesFieldsSchema = z.object({
  inventoryScan: z.boolean().default(false),
  passiveL2: z.boolean().default(false),
  snmpBridge: z.boolean().default(false),
  wifiRf: z.boolean().default(false),
  speedAgent: z.boolean().default(false),
  speedWan: z.boolean().default(false),
  diagnostics: z.boolean().default(false),
  presence: z.boolean().default(false),
  pfsenseControl: z.boolean().default(false),
  compalControl: z.boolean().default(false),
  uiHost: z.boolean().default(false),
  cloudSync: z.boolean().default(false),
  topologyBuilder: z.boolean().default(false),
  trafficRelations: z.boolean().default(false),
  apScrape: z.boolean().default(false),
  fingerprintCloud: z.boolean().default(false),
  cameraIotProbe: z.boolean().default(false),
  siteProbe: z.boolean().default(false),
  elevated: z.boolean().default(false),
  /** @deprecated Prefer inventoryScan — kept for mixed-version beacons. */
  scan: z.boolean().default(false),
  /** @deprecated Prefer wifiRf. */
  wifi: z.boolean().default(false),
  /** @deprecated Prefer inventoryScan + topologyBuilder (SoT eligibility). */
  inventory: z.boolean().default(false),
});

/** Map legacy coarse beacon flags onto fine-grained capabilities. */
export function normalizeAgentCapabilities(
  raw: Record<string, unknown> | null | undefined,
): z.infer<typeof AgentCapabilitiesFieldsSchema> {
  const base = AgentCapabilitiesFieldsSchema.parse(raw ?? {});
  const inventoryScan = base.inventoryScan || base.scan || base.inventory;
  const wifiRf = base.wifiRf || base.wifi;
  return {
    ...base,
    inventoryScan,
    wifiRf,
    // Keep legacy mirrors in sync when emitting/reading mixed clusters.
    scan: inventoryScan || base.scan,
    wifi: wifiRf || base.wifi,
    inventory: base.inventory || inventoryScan || base.topologyBuilder,
  };
}

export const AgentCapabilitiesSchema = z.preprocess(
  (val) => {
    if (!val || typeof val !== 'object') return val;
    return normalizeAgentCapabilities(val as Record<string, unknown>);
  },
  AgentCapabilitiesFieldsSchema,
);
export type AgentCapabilities = z.infer<typeof AgentCapabilitiesFieldsSchema>;

const CAPABILITY_FIELD: Record<AgentCapability, keyof AgentCapabilities> = {
  'inventory-scan': 'inventoryScan',
  'passive-l2': 'passiveL2',
  'snmp-bridge': 'snmpBridge',
  'wifi-rf': 'wifiRf',
  'speed-agent': 'speedAgent',
  'speed-wan': 'speedWan',
  diagnostics: 'diagnostics',
  presence: 'presence',
  'pfsense-control': 'pfsenseControl',
  'compal-control': 'compalControl',
  'ui-host': 'uiHost',
  'cloud-sync': 'cloudSync',
  'topology-builder': 'topologyBuilder',
  'traffic-relations': 'trafficRelations',
  'ap-scrape': 'apScrape',
  'fingerprint-cloud': 'fingerprintCloud',
  'camera-iot-probe': 'cameraIotProbe',
  'site-probe': 'siteProbe',
  elevated: 'elevated',
};

export function peerHasCapability(caps: AgentCapabilities, capability: AgentCapability): boolean {
  return Boolean(caps[CAPABILITY_FIELD[capability]]);
}

export function listEnabledCapabilities(caps: AgentCapabilities): AgentCapability[] {
  return (Object.keys(CAPABILITY_FIELD) as AgentCapability[]).filter((c) =>
    peerHasCapability(caps, c),
  );
}

export function canHoldInventory(caps: AgentCapabilities, profile?: AgentProfile): boolean {
  if (profile === 'ui-only') return false;
  return (
    caps.inventory ||
    caps.inventoryScan ||
    caps.topologyBuilder ||
    caps.presence ||
    profile === 'full'
  );
}

export function canHoldControl(caps: AgentCapabilities): boolean {
  return caps.pfsenseControl || caps.compalControl;
}

export const AgentIdentitySchema = z.object({
  id: AgentIdSchema,
  hostname: z.string(),
  preferLeader: z.boolean().default(false),
  dedicated: z.boolean().default(false),
  profile: AgentProfileSchema.default('full'),
  createdAt: z.string(),
  updatedAt: z.string(),
});
export type AgentIdentity = z.infer<typeof AgentIdentitySchema>;

export const PeerBeaconSchema = z.object({
  v: z.literal(1),
  agentId: AgentIdSchema,
  hostname: z.string(),
  httpPort: z.number().int().positive(),
  httpHost: z.string().optional(),
  role: ClusterRoleSchema,
  term: z.number().int().nonnegative(),
  preferLeader: z.boolean(),
  dedicated: z.boolean(),
  profile: AgentProfileSchema,
  capabilities: AgentCapabilitiesSchema,
  inventoryLeaderId: AgentIdSchema.nullable(),
  controlLeaderId: AgentIdSchema.nullable(),
  startedAt: z.string(),
  uptimeSec: z.number().nonnegative(),
});
export type PeerBeacon = z.infer<typeof PeerBeaconSchema>;

export const ClusterPeerSchema = PeerBeaconSchema.extend({
  address: z.string(),
  lastSeenAt: z.string(),
  stale: z.boolean().default(false),
});
export type ClusterPeer = z.infer<typeof ClusterPeerSchema>;

export const ClusterStatusSchema = z.object({
  self: PeerBeaconSchema,
  role: ClusterRoleSchema,
  term: z.number().int().nonnegative(),
  isInventoryLeader: z.boolean(),
  isControlLeader: z.boolean(),
  inventoryLeaderId: AgentIdSchema.nullable(),
  controlLeaderId: AgentIdSchema.nullable(),
  peers: z.array(ClusterPeerSchema),
  beaconPort: z.number().int().positive(),
  mdnsName: z.string().nullable(),
});
export type ClusterStatus = z.infer<typeof ClusterStatusSchema>;

export const TaskLeaseTypeSchema = z.enum([
  'scan-cidr',
  'wifi-analyze',
  'enrich',
  'speed-agent',
  'speed-wan',
  'passive-capture',
  'diagnostics',
  'snmp-bridge',
  'ap-scrape',
  'camera-iot-probe',
  'site-probe',
  'presence-poll',
]);
export type TaskLeaseType = z.infer<typeof TaskLeaseTypeSchema>;

/** Capability a peer must advertise to accept a leased task. */
export const TASK_REQUIRED_CAPABILITY: Record<TaskLeaseType, AgentCapability> = {
  'scan-cidr': 'inventory-scan',
  'wifi-analyze': 'wifi-rf',
  enrich: 'fingerprint-cloud',
  'speed-agent': 'speed-agent',
  'speed-wan': 'speed-wan',
  'passive-capture': 'passive-l2',
  diagnostics: 'diagnostics',
  'snmp-bridge': 'snmp-bridge',
  'ap-scrape': 'ap-scrape',
  'camera-iot-probe': 'camera-iot-probe',
  'site-probe': 'site-probe',
  'presence-poll': 'presence',
};

export function requiredCapabilityForTask(type: TaskLeaseType): AgentCapability {
  return TASK_REQUIRED_CAPABILITY[type];
}

export function peerCanRunTask(caps: AgentCapabilities, type: TaskLeaseType): boolean {
  return peerHasCapability(caps, requiredCapabilityForTask(type));
}

export const TaskLeaseSchema = z.object({
  id: z.string().uuid(),
  type: TaskLeaseTypeSchema,
  siteId: z.string().optional(),
  payload: z.record(z.string(), z.unknown()),
  assignedTo: AgentIdSchema,
  leasedAt: z.string(),
  expiresAt: z.string(),
});
export type TaskLease = z.infer<typeof TaskLeaseSchema>;

/** Split a list of CIDRs across N workers (round-robin). */
export function shardCidrs(cidrs: string[], workerCount: number): string[][] {
  const n = Math.max(1, workerCount);
  const shards: string[][] = Array.from({ length: n }, () => []);
  cidrs.forEach((cidr, i) => {
    shards[i % n]!.push(cidr);
  });
  return shards;
}

export const InventoryEventSchema = z.object({
  id: z.string(),
  siteId: z.string(),
  type: z.enum([
    'device.upsert',
    'device.remove',
    'topology.snapshot',
    'speed-test',
    'policy.observed',
    'audit',
    'snapshot',
  ]),
  at: z.string(),
  agentId: AgentIdSchema,
  payload: z.record(z.string(), z.unknown()),
});
export type InventoryEvent = z.infer<typeof InventoryEventSchema>;

export const CloudRemoteCommandSchema = z.object({
  id: z.string().uuid(),
  siteId: z.string(),
  type: z.enum(['scan', 'block', 'unblock', 'pause', 'route', 'bandwidth']),
  payload: z.record(z.string(), z.unknown()),
  createdAt: z.string(),
});
export type CloudRemoteCommand = z.infer<typeof CloudRemoteCommandSchema>;

export const MDNS_SERVICE_TYPE = '_netscanner._tcp';
export const DEFAULT_BEACON_PORT = 4010;
export const DEFAULT_MDNS_HOSTNAME = 'netscanner';
