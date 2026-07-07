import { spawn, type ChildProcess } from 'node:child_process';
import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';

const IGMP_JOIN_RE = /(\d+\.\d+\.\d+\.\d+) > 224\.0\.0\.\d+: igmp v[23] report ([\d.]+)/i;
const MULTICAST_LABELS: Record<string, string> = {
  '224.0.0.22': 'igmp',
  '239.255.255.250': 'ssdp-multicast',
  '224.0.0.251': 'mdns-multicast',
};

/** IGMP/multicast joins — Chromecast, TVs, streaming sticks. */
export class IgmpPassiveListener {
  private proc: ChildProcess | null = null;

  constructor(
    private readonly store: IPassiveSignalStore,
    private readonly logger: Logger,
    private readonly iface: string,
  ) {}

  start(): void {
    if (this.proc) return;
    this.proc = spawn('tcpdump', ['-i', this.iface, '-nn', '-l', 'igmp'], {
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    this.proc.stdout?.on('data', (chunk: Buffer) => {
      for (const line of chunk.toString().split('\n')) this.parseLine(line);
    });
    this.proc.on('exit', () => {
      this.proc = null;
    });
    this.logger.info({ iface: this.iface }, 'IGMP passive listener started');
  }

  stop(): void {
    this.proc?.kill('SIGTERM');
    this.proc = null;
  }

  private parseLine(line: string): void {
    const m = IGMP_JOIN_RE.exec(line);
    if (!m) return;
    const ip = m[1]!;
    const group = m[2]!;
    const label = MULTICAST_LABELS[group] ?? `multicast:${group}`;
    void this.store.ingest({
      ip,
      source: 'igmp-passive',
      signals: {
        igmpGroups: [group],
        igmpInterest: label,
        igmpPassive: true,
      },
    });
  }
}
