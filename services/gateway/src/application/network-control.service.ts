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
} from '@netscanner/contracts';
import { NS_ALIAS_AUTOBLOCK, NS_ALIAS_BLOCK, NS_ALIAS_PAUSED } from '@netscanner/contracts';
import type { PfSenseRestControlAdapter } from '@netscanner/discovery';
import type { Logger } from '@netscanner/logger';
import type { IDeviceRepository } from '@netscanner/inventory';
import type { IPolicyAuditRepository } from '@netscanner/inventory';

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

export class NetworkControlService {
  private readonly pauses = new Map<string, PauseRow>();
  private readonly parental: ParentalRow[] = [];
  private readonly bandwidth = new Map<string, { downMbps: number; upMbps: number }>();
  private expiryTimer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly adapter: PfSenseRestControlAdapter | null,
    private readonly repo: IDeviceRepository,
    private readonly audit: IPolicyAuditRepository,
    private readonly config: AppConfig,
    private readonly logger: Logger,
    private readonly getSiteId: () => string,
  ) {}

  start(): void {
    this.expiryTimer = setInterval(() => void this.expirePauses(), 30_000);
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
    return result;
  }

  async status(deviceId: string): Promise<ControlStatus> {
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
    return {
      blocked,
      paused: pausedAlias || Boolean(pause),
      pauseExpiresAt: pause?.expiresAt.toISOString() ?? null,
      bandwidthLimited: this.bandwidth.has(deviceId),
      dhcpReserved: false,
    };
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
      await this.adapter.addToAlias('NS_LIMIT', target.ip).catch(() => {
        /* limiter alias may not exist until manual rule wiring */
      });
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
    return this.adapter.checkBootstrap();
  }

  async verify(): Promise<ControlVerifyResult> {
    if (!this.adapter) {
      return {
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
      };
    }
    if (!this.enabled()) {
      return {
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
      };
    }
    const result = await this.adapter.verify();
    await this.audit.append({
      action: 'verify',
      target: 'pfsense',
      detail: { ok: result.ok, checks: result.checks.length },
      actor: 'local',
      undone: false,
    });
    return result;
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
}
