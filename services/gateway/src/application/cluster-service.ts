import type { AppConfig } from '@netscanner/config';
import type { Logger } from '@netscanner/logger';
import type {
  AgentCapabilities,
  AgentIdentity,
  ClusterPeer,
  ClusterRole,
  ClusterStatus,
  PeerBeacon,
} from '@netscanner/contracts';
import {
  canHoldControl,
  canHoldInventory,
  DEFAULT_MDNS_HOSTNAME,
  normalizeAgentCapabilities,
} from '@netscanner/contracts';
import type { ScanCapabilities } from '@netscanner/os-abstraction';
import { PeerBeaconTransport } from '../infrastructure/peer-beacon.js';
import { MdnsAdvertiser } from '../infrastructure/mdns-advertiser.js';
import { pickClusterLeaders } from './cluster-election.js';

const STALE_MS = 8_000;
const ELECTION_MS = 3_000;

function resolveCapabilities(
  identity: AgentIdentity,
  scanCaps: ScanCapabilities,
  config: AppConfig,
): AgentCapabilities {
  const uiOnly = identity.profile === 'ui-only' || config.UI_ONLY;
  const scanOnly = identity.profile === 'scan-only';
  const workerOk = !uiOnly;
  const leaderish = !uiOnly && !scanOnly;
  const elevated = workerOk && scanCaps.elevated;
  const pfsenseControl =
    leaderish && config.PFSENSE_CONTROL_ENABLED && config.CLUSTER_CONTROL_ELIGIBLE;
  const compalControl = leaderish && config.CLUSTER_CONTROL_ELIGIBLE;
  const inventoryScan = workerOk;
  // CoreWLAN / system_profiler only work on macOS; Linux leaders scrape APs instead.
  const wifiRf = workerOk && process.platform === 'darwin';
  const topologyBuilder = leaderish;
  const presence = leaderish;

  return normalizeAgentCapabilities({
    inventoryScan,
    passiveL2: elevated,
    snmpBridge: workerOk,
    wifiRf,
    speedAgent: workerOk,
    speedWan: pfsenseControl,
    diagnostics: workerOk,
    presence,
    pfsenseControl,
    compalControl,
    uiHost: !scanOnly,
    cloudSync: config.CLOUD_SYNC_ENABLED && Boolean(config.CLOUD_SYNC_URL),
    topologyBuilder,
    trafficRelations: pfsenseControl,
    apScrape: leaderish,
    fingerprintCloud: workerOk,
    cameraIotProbe: workerOk,
    siteProbe: workerOk,
    elevated,
    // Legacy mirrors for mixed-version beacons
    scan: inventoryScan,
    wifi: wifiRf,
    inventory: leaderish || inventoryScan,
  });
}

/** LAN cluster: beacon, election, control/inventory leadership. */
export class ClusterService {
  private readonly peers = new Map<string, ClusterPeer>();
  private readonly startedAt = new Date();
  private term = 0;
  private role: ClusterRole = 'leader';
  private inventoryLeaderId: string | null = null;
  private controlLeaderId: string | null = null;
  private beacon: PeerBeaconTransport | null = null;
  private electionTimer: ReturnType<typeof setInterval> | null = null;
  private mdnsName: string | null = null;
  private readonly capabilities: AgentCapabilities;
  private readonly mdns: MdnsAdvertiser;

  constructor(
    private readonly config: AppConfig,
    private readonly logger: Logger,
    private readonly identity: AgentIdentity,
    scanCaps: ScanCapabilities,
  ) {
    this.capabilities = resolveCapabilities(identity, scanCaps, config);
    this.mdns = new MdnsAdvertiser(logger);
    if (identity.profile === 'ui-only' || config.UI_ONLY) this.role = 'ui-only';
  }

  start(): void {
    if (!this.config.CLUSTER_ENABLED) {
      this.role = this.identity.profile === 'ui-only' || this.config.UI_ONLY ? 'ui-only' : 'leader';
      this.inventoryLeaderId = this.identity.id;
      this.controlLeaderId = this.canControl() ? this.identity.id : null;
      this.refreshMdns();
      this.logger.info({ role: this.role }, 'cluster disabled — acting as solo agent');
      return;
    }

    this.beacon = new PeerBeaconTransport(
      this.config.CLUSTER_BEACON_PORT,
      this.logger,
      (beacon, address) => this.handleBeacon(beacon, address),
      this.config.CLUSTER_PEER_HOSTS,
    );
    this.beacon.start(() => this.buildSelfBeacon());
    this.electionTimer = setInterval(() => this.runElection(), ELECTION_MS);
    this.runElection();
    this.refreshMdns();
    this.logger.info(
      { agentId: this.identity.id, profile: this.identity.profile },
      'cluster service started',
    );
  }

  stop(): void {
    this.beacon?.stop();
    this.beacon = null;
    if (this.electionTimer) clearInterval(this.electionTimer);
    this.electionTimer = null;
    this.mdns.stop();
    this.mdnsName = null;
  }

  status(): ClusterStatus {
    this.pruneStale();
    return {
      self: this.buildSelfBeacon(),
      role: this.role,
      term: this.term,
      isInventoryLeader: this.inventoryLeaderId === this.identity.id,
      isControlLeader: this.controlLeaderId === this.identity.id,
      inventoryLeaderId: this.inventoryLeaderId,
      controlLeaderId: this.controlLeaderId,
      peers: [...this.peers.values()].sort((a, b) => a.hostname.localeCompare(b.hostname)),
      beaconPort: this.config.CLUSTER_BEACON_PORT,
      mdnsName: this.mdnsName,
    };
  }

  isControlLeader(): boolean {
    if (!this.config.CLUSTER_ENABLED) return this.canControl();
    return this.controlLeaderId === this.identity.id;
  }

  isInventoryLeader(): boolean {
    if (!this.config.CLUSTER_ENABLED) return this.identity.profile !== 'ui-only';
    return this.inventoryLeaderId === this.identity.id;
  }

  /** HTTP base URL of the inventory leader for UI redirect (null if self or unknown). */
  inventoryLeaderBaseUrl(): string | null {
    if (this.isInventoryLeader()) return null;
    const id = this.inventoryLeaderId;
    if (!id) return null;
    const peer = this.peers.get(id);
    if (!peer) return null;
    const host = peer.httpHost || peer.address;
    if (this.config.MDNS_ENABLED) return `http://${host}`;
    return `http://${host}:${peer.httpPort}`;
  }

  /** Upstream for reverse-proxy (always includes the beacon HTTP port). */
  inventoryLeaderProxyUrl(): string | null {
    if (this.isInventoryLeader()) return null;
    const id = this.inventoryLeaderId;
    if (!id) return null;
    const peer = this.peers.get(id);
    if (!peer) return null;
    const host = peer.httpHost || peer.address;
    return `http://${host}:${peer.httpPort}`;
  }

  /** Live peers that can run a local Wi‑Fi RF scan (typically macOS helpers). */
  listWifiRfPeers(): ClusterPeer[] {
    const out: ClusterPeer[] = [];
    for (const peer of this.peers.values()) {
      if (peer.stale) continue;
      if (!peer.capabilities.wifiRf && !peer.capabilities.wifi) continue;
      out.push(peer);
    }
    return out;
  }

  peerBaseUrl(peer: ClusterPeer): string {
    const host = peer.httpHost || peer.address;
    return `http://${host}:${peer.httpPort}`;
  }

  setMdnsName(name: string | null): void {
    this.mdnsName = name;
  }

  private canControl(): boolean {
    return canHoldControl(this.capabilities);
  }

  private buildSelfBeacon(): PeerBeacon {
    const uptimeSec = Math.floor((Date.now() - this.startedAt.getTime()) / 1000);
    const advertise = this.config.CLUSTER_ADVERTISE_HOST?.trim();
    return {
      v: 1,
      agentId: this.identity.id,
      hostname: this.identity.hostname,
      httpPort: this.config.GATEWAY_PORT,
      ...(advertise ? { httpHost: advertise } : {}),
      role: this.role,
      term: this.term,
      preferLeader: this.identity.preferLeader,
      dedicated: this.identity.dedicated,
      profile: this.identity.profile,
      capabilities: this.capabilities,
      inventoryLeaderId: this.inventoryLeaderId,
      controlLeaderId: this.controlLeaderId,
      startedAt: this.startedAt.toISOString(),
      uptimeSec,
    };
  }

  private handleBeacon(beacon: PeerBeacon, address: string): void {
    if (beacon.agentId === this.identity.id) return;
    const now = new Date().toISOString();
    this.peers.set(beacon.agentId, {
      ...beacon,
      address,
      lastSeenAt: now,
      stale: false,
    });
  }

  private pruneStale(): void {
    const cutoff = Date.now() - STALE_MS;
    for (const [id, peer] of this.peers) {
      const seen = Date.parse(peer.lastSeenAt);
      if (Number.isNaN(seen) || seen < cutoff) {
        peer.stale = true;
        if (seen < cutoff - STALE_MS) this.peers.delete(id);
      }
    }
  }

  private runElection(): void {
    this.pruneStale();
    const candidates: Array<{
      agentId: string;
      dedicated: boolean;
      preferLeader: boolean;
      elevated: boolean;
      uptimeSec: number;
      canInventory: boolean;
      canControl: boolean;
    }> = [
      {
        agentId: this.identity.id,
        dedicated: this.identity.dedicated,
        preferLeader: this.identity.preferLeader,
        elevated: this.capabilities.elevated,
        uptimeSec: Math.floor((Date.now() - this.startedAt.getTime()) / 1000),
        canInventory: canHoldInventory(this.capabilities, this.identity.profile),
        canControl: this.canControl(),
      },
    ];

    for (const peer of this.peers.values()) {
      if (peer.stale) continue;
      candidates.push({
        agentId: peer.agentId,
        dedicated: peer.dedicated,
        preferLeader: peer.preferLeader,
        elevated: peer.capabilities.elevated,
        uptimeSec: peer.uptimeSec,
        canInventory: canHoldInventory(peer.capabilities, peer.profile),
        canControl: canHoldControl(peer.capabilities),
      });
    }

    // Portable helpers (!dedicated && !preferLeader) yield whenever a preferred
    // peer is reachable; alone they win and run full inventory/UI SoT.
    const { inventoryLeaderId: nextInventory, controlLeaderId: nextControl } =
      pickClusterLeaders(candidates);

    const changed =
      nextInventory !== this.inventoryLeaderId || nextControl !== this.controlLeaderId;
    this.inventoryLeaderId = nextInventory;
    this.controlLeaderId = nextControl;

    if (this.identity.profile === 'ui-only' || this.config.UI_ONLY) {
      this.role = 'ui-only';
    } else if (nextInventory === this.identity.id) {
      this.role = 'leader';
    } else {
      this.role = 'worker';
    }

    if (changed) {
      this.term += 1;
      this.logger.info(
        {
          term: this.term,
          role: this.role,
          inventoryLeaderId: this.inventoryLeaderId,
          controlLeaderId: this.controlLeaderId,
          peerCount: this.peers.size,
        },
        'cluster election updated',
      );
    }
    // Refresh every election tick so helpers pick up the leader IP once the peer beacon arrives
    // (first tick often runs before any peers are known).
    this.refreshMdns();
  }

  /** Preferred appliance peer that should own inventory (home box). */
  private hasPreferredInventoryPeer(): boolean {
    for (const peer of this.peers.values()) {
      if (peer.stale) continue;
      if (!peer.dedicated && !peer.preferLeader) continue;
      if (!canHoldInventory(peer.capabilities, peer.profile)) continue;
      return true;
    }
    return false;
  }

  private refreshMdns(): void {
    if (!this.config.MDNS_ENABLED) {
      this.mdns.stop();
      this.mdnsName = null;
      return;
    }
    if (!this.capabilities.uiHost) {
      this.mdns.stop();
      this.mdnsName = null;
      return;
    }

    const host = this.config.MDNS_HOSTNAME || DEFAULT_MDNS_HOSTNAME;
    this.mdnsName = `${host}.local`;

    // Portable agent still elected leader while a preferred peer is alive (race):
    // don't announce — wait until we yield. When alone on another LAN, we *do* announce.
    if (
      this.isInventoryLeader() &&
      !this.identity.dedicated &&
      !this.identity.preferLeader &&
      this.hasPreferredInventoryPeer()
    ) {
      this.mdns.stop();
      return;
    }

    // Leader: SoT UI. Worker: local A record + reverse-proxy to leader.
    const advertise = this.config.CLUSTER_ADVERTISE_HOST?.trim();
    this.mdns.start({
      hostname: host,
      port: 80,
      ...(advertise && /^\d+\.\d+\.\d+\.\d+$/.test(advertise) ? { ipv4: advertise } : {}),
    });
  }
}
