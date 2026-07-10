import { v4 as uuid } from 'uuid';
import type { AppConfig } from '@netscanner/config';
import type {
  BandwidthLimitRequest,
  ControlBootstrap,
  ControlStatus,
  ControlVerifyResult,
  DhcpReservationRequest,
  ParentalScheduleRequest,
  PolicyAuditEntry,
  RouteOption,
  RouteProfile,
} from '@netscanner/contracts';
import {
  NS_ALIAS_AUTOBLOCK,
  NS_ALIAS_BLOCK,
  NS_ALIAS_DNS_BLOCK,
  NS_ALIAS_DNS_SRC,
  NS_ALIAS_DEST_BLOCK,
  NS_ALIAS_DEST_SRC,
  NS_ALIAS_PAUSED,
  classifyGatewayKind,
  routeAliasForGateway,
} from '@netscanner/contracts';
import type { PfSenseRestControlAdapter } from '@netscanner/discovery';
import type { PfSenseTelemetry } from '@netscanner/discovery';
import { resolvePfSenseTelemetry } from '@netscanner/discovery';
import type { IRouterLeaseSource } from '@netscanner/discovery';
import type { Logger } from '@netscanner/logger';
import type { IDevicePolicyRepository, IDeviceRepository, IPolicyAuditRepository } from '@netscanner/inventory';

export interface PauseRow {
  id: string;
  deviceId: string | null;
  ip: string;
  mac: string | null;
  expiresAt: Date;
}

export interface ParentalRow {
  id: string;
  name: string;
  deviceIds: string[];
  weekdays: number[];
  startTime: string;
  endTime: string;
  enabled: boolean;
  pfsenseScheduleId: string | null;
}

function profileFromGateway(gatewayName: string): Exclude<RouteProfile, 'default'> | null {
  const kind = classifyGatewayKind(gatewayName);
  if (kind === 'wan') return 'wan';
  if (kind === 'lb') return 'lb';
  if (kind === 'vpn') return 'vpn';
  return null;
}

export class NetworkControlService {
  private readonly pauses = new Map<string, PauseRow>();
  private readonly parental: ParentalRow[] = [];
  private readonly bandwidth = new Map<string, { downMbps: number; upMbps: number }>();
  private readonly dnsBlocks = new Map<string, Set<string>>();
  private readonly destBlocks = new Map<string, Set<string>>();
  /** deviceId → pfSense gateway/group name */
  private readonly routes = new Map<string, string>();
  private expiryTimer: ReturnType<typeof setInterval> | null = null;
  private hydrated = false;

  constructor(
    private readonly adapter: PfSenseRestControlAdapter | null,
    private readonly repo: IDeviceRepository,
    private readonly audit: IPolicyAuditRepository,
    private readonly policies: IDevicePolicyRepository,
    private readonly config: AppConfig,
    private readonly logger: Logger,
    private readonly getSiteId: () => string,
    private readonly leaseSource?: IRouterLeaseSource | null,
  ) {}

  start(): void {
    this.expiryTimer = setInterval(() => void this.expirePauses(), 30_000);
    void this.hydrateFromDb();
  }

  stop(): void {
    if (this.expiryTimer) clearInterval(this.expiryTimer);
  }

  enabled(): boolean {
    return Boolean(this.adapter && this.config.PFSENSE_CONTROL_ENABLED);
  }

  async bootstrap(): Promise<ControlBootstrap> {
    if (!this.adapter) throw new Error('pfSense control not configured');
    const result = await this.adapter.bootstrap();
    await this.audit.append({
      action: 'bootstrap',
      target: 'pfsense',
      detail: result,
      actor: 'local',
      undone: false,
    });
    await this.reapplyAliasesToPfSense();
    return result;
  }

  async status(deviceId: string): Promise<ControlStatus> {
    await this.ensureHydrated();
    const device = await this.repo.findById(deviceId);
    if (!device) throw new Error('device not found');
    const addr = device.ip;
    const blocked = this.adapter
      ? (await this.adapter.listAliasAddresses(NS_ALIAS_BLOCK)).includes(addr)
      : false;
    const pausedAlias = this.adapter
      ? (await this.adapter.listAliasAddresses(NS_ALIAS_PAUSED)).includes(addr)
      : false;
    const pause = [...this.pauses.values()].find((p) => p.ip === addr || p.deviceId === deviceId);
    const dnsDomains = [...(this.dnsBlocks.get(deviceId) ?? [])];
    const destEntries = [...(this.destBlocks.get(deviceId) ?? [])];
    const gateway = this.routes.get(deviceId) ?? null;
    const profile = gateway ? profileFromGateway(gateway) : null;
    return {
      blocked,
      paused: pausedAlias || Boolean(pause),
      pauseExpiresAt: pause?.expiresAt.toISOString() ?? null,
      bandwidthLimited: this.bandwidth.has(deviceId),
      dhcpReserved: false,
      dnsBlocked: dnsDomains.length > 0,
      dnsBlockedDomains: dnsDomains,
      destBlocked: destEntries.length > 0,
      destBlockedEntries: destEntries,
      egressRoute: profile,
      egressGateway: gateway,
    };
  }

  listRouteOptions(): RouteOption[] {
    const telemetry = resolvePfSenseTelemetry(this.leaseSource ?? undefined);
    return buildRouteOptions(telemetry);
  }

  async block(deviceId: string | undefined, ip: string | undefined, mac: string | undefined, reason?: string): Promise<PolicyAuditEntry> {
    const target = await this.resolveTarget(deviceId, ip, mac);
    if (!this.adapter) throw new Error('pfSense control not configured');
    await this.adapter.addToAlias(NS_ALIAS_BLOCK, target.ip);
    return this.audit.append({
      action: 'block',
      target: target.ip,
      detail: { deviceId: target.deviceId, reason },
      actor: 'local',
      undone: false,
    });
  }

  async unblock(deviceId: string | undefined, ip: string | undefined, mac: string | undefined): Promise<PolicyAuditEntry> {
    const target = await this.resolveTarget(deviceId, ip, mac);
    if (!this.adapter) throw new Error('pfSense control not configured');
    await this.adapter.removeFromAlias(NS_ALIAS_BLOCK, target.ip);
    return this.audit.append({
      action: 'unblock',
      target: target.ip,
      detail: { deviceId: target.deviceId },
      actor: 'local',
      undone: false,
    });
  }

  async blockDns(
    deviceId: string | undefined,
    ip: string | undefined,
    mac: string | undefined,
    domain: string,
  ): Promise<PolicyAuditEntry> {
    await this.ensureHydrated();
    const target = await this.resolveTarget(deviceId, ip, mac);
    if (!target.deviceId) throw new Error('deviceId required for DNS block');
    if (!this.adapter) throw new Error('pfSense control not configured');
    await this.adapter.ensureDnsDestRules().catch((e) => {
      this.logger.warn({ error: e instanceof Error ? e.message : e }, 'DNS rule ensure failed');
    });
    const set = this.dnsBlocks.get(target.deviceId) ?? new Set<string>();
    set.add(domain);
    this.dnsBlocks.set(target.deviceId, set);
    await this.policies.setValues(target.deviceId, this.getSiteId(), 'dns', [...set]);
    await this.syncDnsAliases();
    return this.audit.append({
      action: 'dns_block',
      target: target.ip,
      detail: { deviceId: target.deviceId, domain },
      actor: 'local',
      undone: false,
    });
  }

  async unblockDns(
    deviceId: string | undefined,
    ip: string | undefined,
    mac: string | undefined,
    domain: string,
  ): Promise<PolicyAuditEntry> {
    await this.ensureHydrated();
    const target = await this.resolveTarget(deviceId, ip, mac);
    if (!target.deviceId) throw new Error('deviceId required for DNS unblock');
    if (!this.adapter) throw new Error('pfSense control not configured');
    const set = this.dnsBlocks.get(target.deviceId);
    set?.delete(domain);
    if (set?.size === 0) this.dnsBlocks.delete(target.deviceId);
    await this.policies.setValues(target.deviceId, this.getSiteId(), 'dns', [...(set ?? [])]);
    await this.syncDnsAliases();
    return this.audit.append({
      action: 'dns_unblock',
      target: target.ip,
      detail: { deviceId: target.deviceId, domain },
      actor: 'local',
      undone: false,
    });
  }

  async blockDest(
    deviceId: string | undefined,
    ip: string | undefined,
    mac: string | undefined,
    destination: string,
  ): Promise<PolicyAuditEntry> {
    await this.ensureHydrated();
    const target = await this.resolveTarget(deviceId, ip, mac);
    if (!target.deviceId) throw new Error('deviceId required for destination block');
    if (!this.adapter) throw new Error('pfSense control not configured');
    await this.adapter.ensureDnsDestRules().catch((e) => {
      this.logger.warn({ error: e instanceof Error ? e.message : e }, 'dest rule ensure failed');
    });
    const set = this.destBlocks.get(target.deviceId) ?? new Set<string>();
    set.add(destination);
    this.destBlocks.set(target.deviceId, set);
    await this.policies.setValues(target.deviceId, this.getSiteId(), 'dest', [...set]);
    await this.syncDestAliases();
    return this.audit.append({
      action: 'dest_block',
      target: target.ip,
      detail: { deviceId: target.deviceId, destination },
      actor: 'local',
      undone: false,
    });
  }

  async unblockDest(
    deviceId: string | undefined,
    ip: string | undefined,
    mac: string | undefined,
    destination: string,
  ): Promise<PolicyAuditEntry> {
    await this.ensureHydrated();
    const target = await this.resolveTarget(deviceId, ip, mac);
    if (!target.deviceId) throw new Error('deviceId required for destination unblock');
    if (!this.adapter) throw new Error('pfSense control not configured');
    const set = this.destBlocks.get(target.deviceId);
    set?.delete(destination);
    if (set?.size === 0) this.destBlocks.delete(target.deviceId);
    await this.policies.setValues(target.deviceId, this.getSiteId(), 'dest', [...(set ?? [])]);
    await this.syncDestAliases();
    return this.audit.append({
      action: 'dest_unblock',
      target: target.ip,
      detail: { deviceId: target.deviceId, destination },
      actor: 'local',
      undone: false,
    });
  }

  async setRoute(
    deviceId: string | undefined,
    ip: string | undefined,
    mac: string | undefined,
    opts: { gatewayName?: string | null; profile?: RouteProfile },
  ): Promise<PolicyAuditEntry> {
    await this.ensureHydrated();
    const target = await this.resolveTarget(deviceId, ip, mac);
    if (!target.deviceId) throw new Error('deviceId required for route policy');
    if (!this.adapter) throw new Error('pfSense control not configured');

    let gatewayName: string | null = null;
    if (opts.gatewayName !== undefined) {
      gatewayName = opts.gatewayName;
    } else if (opts.profile === 'default') {
      gatewayName = null;
    } else if (opts.profile) {
      gatewayName = this.resolveProfileGateway(opts.profile);
    }

    const prev = this.routes.get(target.deviceId);
    if (prev) {
      const prevAlias = routeAliasForGateway(prev);
      await this.adapter.removeFromAlias(prevAlias, target.ip).catch(() => undefined);
    }

    if (!gatewayName) {
      this.routes.delete(target.deviceId);
      await this.policies.setRoute(target.deviceId, this.getSiteId(), null);
    } else {
      const alias = await this.adapter.ensureRouteGateway(gatewayName);
      this.routes.set(target.deviceId, gatewayName);
      await this.policies.setRoute(target.deviceId, this.getSiteId(), gatewayName);
      await this.adapter.addToAlias(alias, target.ip);
    }

    return this.audit.append({
      action: 'route_policy',
      target: target.ip,
      detail: {
        deviceId: target.deviceId,
        gatewayName,
        profile: gatewayName ? profileFromGateway(gatewayName) : 'default',
      },
      actor: 'local',
      undone: false,
    });
  }

  async pause(deviceId: string | undefined, ip: string | undefined, mac: string | undefined, durationMs: number): Promise<PolicyAuditEntry> {
    const target = await this.resolveTarget(deviceId, ip, mac);
    if (!this.adapter) throw new Error('pfSense control not configured');
    await this.adapter.addToAlias(NS_ALIAS_PAUSED, target.ip);
    const row: PauseRow = {
      id: uuid(),
      deviceId: target.deviceId ?? null,
      ip: target.ip,
      mac: target.mac ?? null,
      expiresAt: new Date(Date.now() + durationMs),
    };
    this.pauses.set(row.id, row);
    return this.audit.append({
      action: 'pause',
      target: target.ip,
      detail: { deviceId: target.deviceId, durationMs, expiresAt: row.expiresAt.toISOString() },
      actor: 'local',
      undone: false,
    });
  }

  async autoblockDevice(deviceId: string, vlan?: string | null): Promise<void> {
    if (!this.config.AUTOBLOCK_ENABLED) return;
    const vlans = this.config.AUTOBLOCK_VLANS.split(',').map((s) => s.trim()).filter(Boolean);
    if (vlans.length && vlan && !vlans.includes(vlan)) return;
    const device = await this.repo.findById(deviceId);
    if (!device || !this.adapter) return;
    await this.adapter.addToAlias(NS_ALIAS_AUTOBLOCK, device.ip);
    await this.audit.append({
      action: 'autoblock',
      target: device.ip,
      detail: { deviceId, vlan },
      actor: 'system',
      undone: false,
    });
    this.logger.warn({ ip: device.ip, vlan }, 'autoblocked new device');
  }

  async createDhcpReservation(req: DhcpReservationRequest): Promise<PolicyAuditEntry> {
    if (!this.adapter) throw new Error('pfSense control not configured');
    const created = await this.adapter.createDhcpReservation(req);
    return this.audit.append({
      action: 'dhcp_reserve',
      target: req.ip,
      detail: { ...req, pfsenseId: created.id },
      actor: 'local',
      undone: false,
    });
  }

  async setBandwidth(req: BandwidthLimitRequest): Promise<PolicyAuditEntry> {
    const target = await this.resolveTarget(req.deviceId, req.ip, req.mac);
    this.bandwidth.set(target.deviceId ?? target.ip, { downMbps: req.downMbps, upMbps: req.upMbps });
    if (this.adapter) {
      await this.adapter.addToAlias('NS_LIMIT', target.ip).catch(() => undefined);
    }
    return this.audit.append({
      action: 'bandwidth_limit',
      target: target.ip,
      detail: { downMbps: req.downMbps, upMbps: req.upMbps },
      actor: 'local',
      undone: false,
    });
  }

  async createParentalSchedule(req: ParentalScheduleRequest): Promise<ParentalRow> {
    let pfsenseScheduleId: string | null = null;
    if (this.adapter) {
      const created = await this.adapter.createSchedule(req.name, req.weekdays, req.startTime, req.endTime);
      pfsenseScheduleId = created.id != null ? String(created.id) : req.name;
    }
    const row: ParentalRow = {
      id: uuid(),
      name: req.name,
      deviceIds: req.deviceIds,
      weekdays: req.weekdays,
      startTime: req.startTime,
      endTime: req.endTime,
      enabled: req.enabled,
      pfsenseScheduleId,
    };
    this.parental.push(row);
    await this.audit.append({
      action: 'parental_schedule',
      target: req.name,
      detail: req as unknown as Record<string, unknown>,
      actor: 'local',
      undone: false,
    });
    return row;
  }

  listParentalSchedules(): ParentalRow[] {
    return [...this.parental];
  }

  listAudit(limit?: number): Promise<PolicyAuditEntry[]> {
    return this.audit.list(limit);
  }

  checkBootstrap(): Promise<ControlBootstrap> {
    if (!this.adapter) {
      return Promise.resolve({
        ready: false,
        aliases: {},
        limiters: {},
        schedules: 0,
        message: 'Set PFSENSE_URL, PFSENSE_API_KEY, PFSENSE_CONTROL_ENABLED=true',
      });
    }
    return this.adapter.checkBootstrap().catch((error) => {
      const msg = error instanceof Error ? error.message : String(error);
      this.logger.warn({ error: msg }, 'pfSense bootstrap check failed');
      return {
        ready: false,
        aliases: {},
        limiters: {},
        schedules: 0,
        message: `pfSense unreachable (${msg})`,
      };
    });
  }

  verify(): Promise<ControlVerifyResult> {
    if (!this.adapter) {
      return Promise.resolve({
        ok: false,
        ranAt: new Date().toISOString(),
        checks: [
          {
            id: 'control',
            label: 'pfSense control',
            status: 'fail',
            detail: 'Set PFSENSE_URL, PFSENSE_API_KEY, PFSENSE_CONTROL_ENABLED=true',
          },
        ],
      });
    }
    if (!this.enabled()) {
      return Promise.resolve({
        ok: false,
        ranAt: new Date().toISOString(),
        checks: [
          {
            id: 'control',
            label: 'pfSense control enabled',
            status: 'fail',
            detail: 'PFSENSE_CONTROL_ENABLED is false',
          },
        ],
      });
    }
    return this.adapter
      .verify()
      .then(async (result) => {
        await this.audit.append({
          action: 'verify',
          target: 'pfsense',
          detail: { ok: result.ok, checks: result.checks.length },
          actor: 'local',
          undone: false,
        });
        return result;
      })
      .catch((error) => {
        const msg = error instanceof Error ? error.message : String(error);
        this.logger.warn({ error: msg }, 'pfSense verify failed');
        return {
          ok: false,
          ranAt: new Date().toISOString(),
          checks: [
            {
              id: 'api',
              label: 'pfSense API reachable',
              status: 'fail' as const,
              detail: msg,
            },
          ],
        };
      });
  }

  private resolveProfileGateway(profile: Exclude<RouteProfile, 'default'>): string {
    const options = this.listRouteOptions();
    const match = options.find((o) => o.kind === profile);
    if (match) return match.name;
    if (profile === 'wan') return 'WAN_DHCP';
    if (profile === 'lb') return 'LB_WAN';
    return 'SSVPN_Failover';
  }

  private async ensureHydrated(): Promise<void> {
    if (!this.hydrated) await this.hydrateFromDb();
  }

  private async hydrateFromDb(): Promise<void> {
    try {
      const rows = await this.policies.list();
      this.dnsBlocks.clear();
      this.destBlocks.clear();
      this.routes.clear();
      for (const row of rows) {
        if (row.kind === 'route') {
          this.routes.set(row.deviceId, row.value);
        } else if (row.kind === 'dns') {
          const set = this.dnsBlocks.get(row.deviceId) ?? new Set<string>();
          set.add(row.value);
          this.dnsBlocks.set(row.deviceId, set);
        } else if (row.kind === 'dest') {
          const set = this.destBlocks.get(row.deviceId) ?? new Set<string>();
          set.add(row.value);
          this.destBlocks.set(row.deviceId, set);
        }
      }
      this.hydrated = true;
      this.logger.info(
        {
          routes: this.routes.size,
          dnsDevices: this.dnsBlocks.size,
          destDevices: this.destBlocks.size,
        },
        'device policies hydrated from DB',
      );
      if (this.adapter && this.enabled()) {
        await this.reapplyAliasesToPfSense();
      }
    } catch (error) {
      this.logger.warn(
        { error: error instanceof Error ? error.message : error },
        'failed to hydrate device policies',
      );
      this.hydrated = true;
    }
  }

  private async reapplyAliasesToPfSense(): Promise<void> {
    if (!this.adapter) return;
    await this.adapter.ensureDnsDestRules().catch((e) => {
      this.logger.warn({ error: e instanceof Error ? e.message : e }, 'ensure DNS/dest rules failed');
    });
    await this.syncDnsAliases();
    await this.syncDestAliases();
    for (const [deviceId, gateway] of this.routes) {
      const device = await this.repo.findById(deviceId);
      if (!device) continue;
      try {
        const alias = await this.adapter.ensureRouteGateway(gateway);
        await this.adapter.addToAlias(alias, device.ip);
      } catch (error) {
        this.logger.warn(
          { deviceId, gateway, error: error instanceof Error ? error.message : error },
          'failed to reapply route policy',
        );
      }
    }
  }

  private async expirePauses(): Promise<void> {
    if (!this.adapter) return;
    const now = Date.now();
    for (const [id, row] of this.pauses) {
      if (row.expiresAt.getTime() > now) continue;
      await this.adapter.removeFromAlias(NS_ALIAS_PAUSED, row.ip).catch(() => undefined);
      this.pauses.delete(id);
      await this.audit.append({
        action: 'pause_expired',
        target: row.ip,
        detail: { deviceId: row.deviceId },
        actor: 'system',
        undone: false,
      });
    }
  }

  private async resolveTarget(
    deviceId?: string,
    ip?: string,
    mac?: string,
  ): Promise<{ deviceId?: string; ip: string; mac?: string | null }> {
    const siteId = this.getSiteId();
    if (deviceId) {
      const d = await this.repo.findById(deviceId);
      if (!d) throw new Error('device not found');
      return { deviceId, ip: d.ip, mac: d.mac };
    }
    if (ip) return { ip, mac: mac ?? null };
    if (mac) {
      const d = await this.repo.findByMac(siteId, mac);
      if (!d) throw new Error('device not found for mac');
      return { deviceId: d.id, ip: d.ip, mac: d.mac };
    }
    throw new Error('deviceId, ip, or mac required');
  }

  private async syncDnsAliases(): Promise<void> {
    if (!this.adapter) return;
    const allDomains = new Set<string>();
    const srcIps = new Set<string>();
    for (const [deviceId, domains] of this.dnsBlocks) {
      if (!domains.size) continue;
      const d = await this.repo.findById(deviceId);
      if (!d) continue;
      srcIps.add(d.ip);
      for (const dom of domains) allDomains.add(dom);
    }
    await this.adapter.setAliasAddresses(NS_ALIAS_DNS_BLOCK, [...allDomains]);
    await this.adapter.setAliasAddresses(NS_ALIAS_DNS_SRC, [...srcIps]);
  }

  private async syncDestAliases(): Promise<void> {
    if (!this.adapter) return;
    const allDests = new Set<string>();
    const srcIps = new Set<string>();
    for (const [deviceId, entries] of this.destBlocks) {
      if (!entries.size) continue;
      const d = await this.repo.findById(deviceId);
      if (!d) continue;
      srcIps.add(d.ip);
      for (const entry of entries) {
        const host = entry.split(':')[0] ?? entry;
        allDests.add(host);
      }
    }
    await this.adapter.setAliasAddresses(NS_ALIAS_DEST_BLOCK, [...allDests]);
    await this.adapter.setAliasAddresses(NS_ALIAS_DEST_SRC, [...srcIps]);
  }
}

export function buildRouteOptions(telemetry: PfSenseTelemetry | null): RouteOption[] {
  if (!telemetry) {
    return [
      { name: 'WAN_DHCP', kind: 'wan', label: 'WAN_DHCP', description: null },
      { name: 'LB_WAN', kind: 'lb', label: 'LB_WAN (load balance)', description: null },
      { name: 'SSVPN_Failover', kind: 'vpn', label: 'SSVPN_Failover', description: null },
    ];
  }
  const seen = new Set<string>();
  const out: RouteOption[] = [];
  const push = (name: string, kind: RouteOption['kind'], label: string, description: string | null, online?: boolean) => {
    if (!name || seen.has(name)) return;
    seen.add(name);
    out.push({ name, kind, label, description, online });
  };

  for (const g of telemetry.gatewayGroups) {
    const kind = classifyGatewayKind(g.name);
    push(g.name, kind === 'other' ? 'group' : kind, g.name, g.description ?? null);
  }
  for (const gw of telemetry.gateways) {
    const name = gw.name?.trim();
    if (!name) continue;
    const kind = classifyGatewayKind(name);
    const online = (gw.status ?? '').toLowerCase().includes('online');
    push(name, kind, name, gw.description ?? null, online);
  }
  return out.sort((a, b) => {
    const order = { wan: 0, lb: 1, vpn: 2, group: 3, other: 4 };
    return order[a.kind] - order[b.kind] || a.name.localeCompare(b.name);
  });
}
