import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';

const LLDP_RE = /([0-9a-f]{2}(:[0-9a-f]{2}){5})/gi;
const SYS_NAME_RE = /System Name TLV \(\d+\), length \d+: (.+)/i;
const CHASSIS_RE = /Chassis ID TLV \(\d+\), length \d+: (.+)/i;

/**
 * Brief LLDP capture via tcpdump (needs root + tcpdump on PATH). Parses stdout
 * for neighbor MACs and system names; feeds the passive signal store.
 */
export class LldpPassiveListener {
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly runner: ICommandRunner,
    private readonly store: IPassiveSignalStore,
    private readonly logger: Logger,
    private readonly iface: string,
    private readonly intervalMs = 300_000,
  ) {}

  start(): void {
    if (this.timer) return;
    void this.capture();
    this.timer = setInterval(() => void this.capture(), this.intervalMs);
    this.logger.info({ iface: this.iface, intervalMs: this.intervalMs }, 'LLDP passive listener started');
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  private async capture(): Promise<void> {
    const hasTcpdump = await this.runner.which('tcpdump');
    if (!hasTcpdump) return;

    const res = await this.runner.run(
      'tcpdump',
      ['-i', this.iface, '-nn', '-e', '-l', '-c', '80', 'ether proto 0x88cc'],
      { timeoutMs: 20_000 },
    );
    if (!res.stdout) return;

    let lastMac: string | null = null;
    for (const line of res.stdout.split('\n')) {
      const sys = SYS_NAME_RE.exec(line)?.[1]?.trim();
      const chassis = CHASSIS_RE.exec(line)?.[1]?.trim();
      const macs = [...line.matchAll(LLDP_RE)].map((m) => m[1]!.toLowerCase());
      if (macs.length) lastMac = macs[0]!;
      if (!lastMac) continue;

      const signals: Record<string, unknown> = { lldpPassive: true };
      if (sys) signals['lldpSystemName'] = sys;
      if (chassis) signals['lldpChassis'] = chassis;

      if (Object.keys(signals).length <= 1) continue;
      void this.store.ingest({
        ip: `lldp:${lastMac}`,
        mac: lastMac,
        hostname: sys ?? undefined,
        source: 'lldp-passive',
        signals,
      });
    }
  }
}
