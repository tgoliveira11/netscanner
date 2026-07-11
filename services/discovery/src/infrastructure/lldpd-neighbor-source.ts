import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';

export interface LldpdNeighborSourceOptions {
  store: IPassiveSignalStore;
  logger: Logger;
  runner: ICommandRunner;
  intervalMs?: number;
}

const KEY_RE = /^lldp\.([^.]+)\.(.+)=(.*)$/;

/** Parse `lldpctl -f keyvalue` into per-interface neighbor maps. */
export function parseLldpctlKeyvalue(output: string): Array<{
  iface: string;
  systemName?: string;
  chassis?: string;
  portId?: string;
  mgmtIp?: string;
  mac?: string;
}> {
  const byIface = new Map<string, Record<string, string>>();
  for (const line of output.split('\n')) {
    const m = KEY_RE.exec(line.trim());
    if (!m) continue;
    const iface = m[1]!;
    const key = m[2]!;
    const val = m[3] ?? '';
    const row = byIface.get(iface) ?? {};
    row[key] = val;
    byIface.set(iface, row);
  }
  const out: Array<{
    iface: string;
    systemName?: string;
    chassis?: string;
    portId?: string;
    mgmtIp?: string;
    mac?: string;
  }> = [];
  for (const [iface, row] of byIface) {
    const systemName = row['chassis.name'] || row['chassis.descr'];
    const chassis = row['chassis.mac'] || row['chassis.id'];
    const portId = row['port.ifname'] || row['port.id'] || row['port.descr'];
    const mgmtIp = row['chassis.mgmt-ip'] || row['chassis.mgmt_ip'];
    const mac = (row['chassis.mac'] || '').toLowerCase() || undefined;
    if (!systemName && !chassis && !mgmtIp) continue;
    out.push({ iface, systemName, chassis, portId, mgmtIp, mac });
  }
  return out;
}

/**
 * Poll lldpd neighbors via `lldpctl -f keyvalue`. Prefer this when lldpd is
 * installed; tcpdump LLDP remains as fallback when lldpctl is absent.
 */
export class LldpdNeighborSource {
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly opts: LldpdNeighborSourceOptions) {}

  async start(): Promise<void> {
    if (this.timer) return;
    const has = await this.opts.runner.which('lldpctl');
    if (!has) {
      this.opts.logger.info('lldpctl not installed — lldpd neighbor source skipped');
      return;
    }
    void this.poll();
    this.timer = setInterval(() => void this.poll(), this.opts.intervalMs ?? 90_000);
    this.opts.logger.info({ intervalMs: this.opts.intervalMs ?? 90_000 }, 'lldpd neighbor source started');
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  /** True when this source is actively polling (lldpctl present). */
  get active(): boolean {
    return this.timer != null;
  }

  private async poll(): Promise<void> {
    const res = await this.opts.runner.run('lldpctl', ['-f', 'keyvalue'], { timeoutMs: 8_000 });
    if (!res.stdout) return;
    for (const n of parseLldpctlKeyvalue(res.stdout)) {
      const mac = n.mac;
      const signals: Record<string, unknown> = {
        lldpPassive: true,
        lldpViaLldpd: true,
      };
      if (n.systemName) signals['lldpSystemName'] = n.systemName;
      if (n.chassis) signals['lldpChassis'] = n.chassis;
      if (n.portId) signals['lldpPortId'] = n.portId;
      if (n.mgmtIp) signals['lldpMgmtIp'] = n.mgmtIp;

      void this.opts.store.ingest({
        ip: n.mgmtIp ?? (mac ? `lldp:${mac}` : `lldp:${n.iface}`),
        mac: mac ?? null,
        hostname: n.systemName,
        source: 'lldpd',
        signals,
      });
    }
  }
}
