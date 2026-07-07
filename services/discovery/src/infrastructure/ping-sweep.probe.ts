import { currentPlatform, type ICommandRunner } from '@netscanner/os-abstraction';
import type { IHostProbe, ProbeContext, RawHostSignal } from '../domain/host-probe.js';
import { mapPool } from './concurrency.js';

const LATENCY_RE = /time[=<]\s*([\d.]+)\s*ms/i;

/**
 * Active ICMP liveness sweep. Uses the system `ping` (no raw sockets → no root)
 * with platform-specific flags, bounded by a worker pool for efficiency. Side
 * effect: populates the OS ARP cache so ArpTableProbe can resolve MACs.
 */
export class PingSweepProbe implements IHostProbe {
  readonly name = 'ping';
  readonly phase = 'sweep' as const;

  constructor(private readonly runner: ICommandRunner) {}

  private buildArgs(host: string, timeoutMs: number): string[] {
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

  async run(ctx: ProbeContext, emit: (signal: RawHostSignal) => void): Promise<void> {
    const hosts = [...ctx.cidr.hosts()].map((h) => h.value);
    await mapPool(
      hosts,
      ctx.concurrency,
      async (host) => {
        if (ctx.signal.aborted) return;
        const res = await this.runner.run('ping', this.buildArgs(host, ctx.timeoutMs), {
          timeoutMs: ctx.timeoutMs + 500,
        });
        if (res.code !== 0) return; // no reply → treat as down
        const match = LATENCY_RE.exec(res.stdout);
        emit({
          ip: host,
          source: this.name,
          latencyMs: match ? Number(match[1]) : undefined,
        });
      },
      ctx.signal,
    );
  }
}
