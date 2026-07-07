import { spawn, type ChildProcess } from 'node:child_process';
import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';

const LLDP_RE = /([0-9a-f]{2}(:[0-9a-f]{2}){5})/gi;
const SYS_NAME_RE = /System Name TLV \(\d+\), length \d+: (.+)/i;
const CHASSIS_RE = /Chassis ID TLV \(\d+\), length \d+: (.+)/i;

export interface LldpPassiveOptions {
  runner: ICommandRunner;
  store: IPassiveSignalStore;
  logger: Logger;
  iface: string;
  /** Continuous tcpdump stream vs periodic burst capture. */
  stream?: boolean;
  intervalMs?: number;
}

/**
 * LLDP capture via tcpdump. Stream mode keeps tcpdump running; burst mode
 * samples periodically (legacy behaviour).
 */
export class LldpPassiveListener {
  private timer: ReturnType<typeof setInterval> | null = null;
  private proc: ChildProcess | null = null;

  constructor(private readonly opts: LldpPassiveOptions) {}

  start(): void {
    if (this.opts.stream) {
      void this.startStream();
      return;
    }
    if (this.timer) return;
    void this.captureBurst();
    this.timer = setInterval(() => void this.captureBurst(), this.opts.intervalMs ?? 300_000);
    this.opts.logger.info(
      { iface: this.opts.iface, mode: 'burst', intervalMs: this.opts.intervalMs ?? 300_000 },
      'LLDP passive listener started',
    );
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    this.proc?.kill('SIGTERM');
    this.proc = null;
  }

  private async startStream(): Promise<void> {
    if (this.proc) return;
    const hasTcpdump = await this.opts.runner.which('tcpdump');
    if (!hasTcpdump) return;

    this.proc = spawn(
      'tcpdump',
      ['-i', this.opts.iface, '-nn', '-e', '-l', '-U', 'ether proto 0x88cc'],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    );
    this.proc.stdout?.on('data', (chunk: Buffer) => {
      for (const line of chunk.toString().split('\n')) this.parseLine(line);
    });
    this.proc.on('exit', () => {
      this.proc = null;
    });
    this.opts.logger.info({ iface: this.opts.iface, mode: 'stream' }, 'LLDP passive listener started');
  }

  private async captureBurst(): Promise<void> {
    const hasTcpdump = await this.opts.runner.which('tcpdump');
    if (!hasTcpdump) return;

    const res = await this.opts.runner.run(
      'tcpdump',
      ['-i', this.opts.iface, '-nn', '-e', '-l', '-c', '80', 'ether proto 0x88cc'],
      { timeoutMs: 20_000 },
    );
    if (!res.stdout) return;
    for (const line of res.stdout.split('\n')) this.parseLine(line);
  }

  private parseLine(line: string): void {
    const sys = SYS_NAME_RE.exec(line)?.[1]?.trim();
    const chassis = CHASSIS_RE.exec(line)?.[1]?.trim();
    const macs = [...line.matchAll(LLDP_RE)].map((m) => m[1]!.toLowerCase());
    const lastMac = macs[0];
    if (!lastMac) return;

    const signals: Record<string, unknown> = { lldpPassive: true };
    if (sys) signals['lldpSystemName'] = sys;
    if (chassis) signals['lldpChassis'] = chassis;
    if (Object.keys(signals).length <= 1) return;

    void this.opts.store.ingest({
      ip: `lldp:${lastMac}`,
      mac: lastMac,
      hostname: sys ?? undefined,
      source: 'lldp-passive',
      signals,
    });
  }
}
