import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { IHostProbe, ProbeContext, RawHostSignal } from '../domain/host-probe.js';

export interface MasscanProbeOptions {
  enabled: boolean;
  rate: number;
  /** Use masscan when host count exceeds this threshold. */
  minHosts?: number;
}

/**
 * Fast SYN sweep for large subnets when masscan is installed.
 * Emits live IPs; MAC resolution still comes from ARP after ping follow-up.
 */
export class MasscanProbe implements IHostProbe {
  readonly name = 'masscan';
  readonly phase = 'sweep' as const;

  constructor(
    private readonly runner: ICommandRunner,
    private readonly options: MasscanProbeOptions,
  ) {}

  async run(ctx: ProbeContext, emit: (signal: RawHostSignal) => void): Promise<void> {
    if (!this.options.enabled) return;
    const hostCount = [...ctx.cidr.hosts()].length;
    if (hostCount < (this.options.minHosts ?? 512)) return;
    if (!(await this.runner.which('masscan'))) return;

    const res = await this.runner.run(
      'masscan',
      [
        ctx.cidr.toString(),
        '-p',
        '22,80,443,445,8080',
        '--rate',
        String(this.options.rate),
        '-oL',
        '-',
        '--exclude',
        '255.255.255.255',
      ],
      { timeoutMs: Math.min(120_000, ctx.timeoutMs * hostCount) },
    );
    if (!res.stdout) return;

    for (const line of res.stdout.split('\n')) {
      const m = /^open\s+tcp\s+\d+\s+(\d+\.\d+\.\d+\.\d+)/.exec(line.trim());
      if (m) emit({ ip: m[1], source: 'masscan' });
    }
  }
}
