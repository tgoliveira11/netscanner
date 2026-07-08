import { currentPlatform, type ICommandRunner } from '@netscanner/os-abstraction';
import type { AppConfig } from '@netscanner/config';
import type { Device, IEventPublisher } from '@netscanner/contracts';
import type { Logger } from '@netscanner/logger';
import type { IDeviceRepository } from '@netscanner/inventory';
import type { IRouterLeaseSource } from '@netscanner/discovery';
import type { ITrafficSource, TrafficMonitor } from '@netscanner/scanner';
import { trafficSuggestsAlive } from '@netscanner/scanner';
import type { ScanSessionStore } from './scan-session.js';

const LATENCY_RE = /time[=<]\s*([\d.]+)\s*ms/i;

export interface PresenceMonitorDeps {
  config: AppConfig;
  logger: Logger;
  runner: ICommandRunner;
  repo: IDeviceRepository;
  events: IEventPublisher;
  sessions: ScanSessionStore;
  leaseSource?: IRouterLeaseSource;
  trafficMonitor?: TrafficMonitor;
  trafficSource?: ITrafficSource;
  getSiteId: () => string;
  needsSiteConfirmation?: () => boolean;
  refreshSite?: () => Promise<void>;
}

function pingArgs(host: string, timeoutMs: number): string[] {
  const seconds = Math.max(1, Math.round(timeoutMs / 1000));
  switch (currentPlatform()) {
    case 'darwin':
      return ['-c', '1', '-t', String(seconds), host];
    case 'win32':
      return ['-n', '1', '-w', String(timeoutMs), host];
    default:
      return ['-c', '1', '-W', String(seconds), host];
  }
}

async function pingHost(
  runner: ICommandRunner,
  ip: string,
  timeoutMs: number,
): Promise<{ alive: boolean; latencyMs: number | null }> {
  const res = await runner.run('ping', pingArgs(ip, timeoutMs), { timeoutMs: timeoutMs + 500 });
  if (res.code !== 0) return { alive: false, latencyMs: null };
  const match = LATENCY_RE.exec(res.stdout);
  return { alive: true, latencyMs: match ? Number(match[1]) : null };
}

/**
 * Lightweight ICMP presence loop — updates online/offline without a full scan.
 * Emits `device.online` / `device.offline` within seconds of state changes.
 */
export class PresenceMonitor {
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;
  private readonly missCounts = new Map<string, number>();

  constructor(private readonly deps: PresenceMonitorDeps) {}

  start(): void {
    if (!this.deps.config.PRESENCE_POLL_ENABLED) return;
    const ms = this.deps.config.PRESENCE_POLL_INTERVAL_MS;
    this.timer = setInterval(() => void this.poll(), ms);
    setTimeout(() => void this.poll(), 4_000);
    this.deps.logger.info({ intervalMs: ms }, 'presence monitor started');
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.missCounts.clear();
  }

  reconfigure(): void {
    this.stop();
    this.start();
  }

  async poll(): Promise<void> {
    if (this.running || this.deps.sessions.activeScan()) return;
    this.running = true;
    try {
      const devices = await this.deps.repo.list({ siteId: this.deps.getSiteId() });
      if (!devices.length) return;

      const leaseOnline = await this.leaseOnlineByIp();
      if (this.deps.trafficSource && this.deps.trafficMonitor) {
        try {
          await this.deps.trafficMonitor.refresh(this.deps.trafficSource);
        } catch {
          /* traffic hint is optional */
        }
      }
      const timeoutMs = this.deps.config.PRESENCE_PING_TIMEOUT_MS;
      const concurrency = Math.min(this.deps.config.PRESENCE_PING_CONCURRENCY, devices.length);
      const offlineAfter = Math.max(1, this.deps.config.PRESENCE_OFFLINE_AFTER_MISSES);

      let idx = 0;
      const workers = Array.from({ length: concurrency }, async () => {
        while (idx < devices.length) {
          const device = devices[idx++]!;
          await this.checkDevice(device, leaseOnline, timeoutMs, offlineAfter);
        }
      });
      await Promise.all(workers);
    } catch (error) {
      this.deps.logger.warn(
        { error: error instanceof Error ? error.message : error },
        'presence poll failed',
      );
    } finally {
      this.running = false;
    }
  }

  private async leaseOnlineByIp(): Promise<Map<string, boolean>> {
    const map = new Map<string, boolean>();
    if (!this.deps.leaseSource) return map;
    try {
      const leases = await this.deps.leaseSource.getLeases();
      for (const lease of leases) {
        if (lease.ip) map.set(lease.ip, lease.online);
      }
    } catch {
      /* leases are a hint, not required */
    }
    return map;
  }

  private async checkDevice(
    device: Device,
    leaseOnline: Map<string, boolean>,
    timeoutMs: number,
    offlineAfter: number,
  ): Promise<void> {
    const leaseHint = leaseOnline.get(device.ip);
    let alive: boolean;
    let latencyMs: number | null = null;

    // Lease "online" is a reliable positive hint; "offline" from DHCP is often stale — confirm with ping.
    if (leaseHint === true) {
      alive = true;
    } else {
      const ping = await pingHost(this.deps.runner, device.ip, timeoutMs);
      alive = ping.alive;
      latencyMs = ping.latencyMs;
      if (!alive) {
        const traffic =
          this.deps.trafficMonitor?.get(device.ip) ??
          (device.signals?.traffic as import('@netscanner/contracts').Traffic | undefined);
        if (trafficSuggestsAlive(traffic)) alive = true;
      }
    }

    if (alive) {
      this.missCounts.set(device.id, 0);
      if (!device.isOnline) {
        const updated = await this.deps.repo.updatePresence(device.id, {
          isOnline: true,
          latencyMs,
        });
        if (updated) {
          this.deps.events.emit({ type: 'device.online', payload: { device: updated } });
        }
      } else if (latencyMs != null && device.latencyMs !== latencyMs) {
        const updated = await this.deps.repo.updatePresence(device.id, {
          isOnline: true,
          latencyMs,
        });
        if (updated) {
          this.deps.events.emit({ type: 'device.classified', payload: { scanId: 'presence', device: updated } });
        }
      }
      return;
    }

    const misses = (this.missCounts.get(device.id) ?? 0) + 1;
    this.missCounts.set(device.id, misses);
    if (!device.isOnline || misses < offlineAfter) return;

    const updated = await this.deps.repo.updatePresence(device.id, { isOnline: false });
    if (updated) {
      this.deps.events.emit({ type: 'device.offline', payload: { deviceId: device.id, device: updated } });
    }
  }
}
