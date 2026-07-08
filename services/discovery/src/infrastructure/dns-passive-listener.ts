import { spawn, type ChildProcess } from 'node:child_process';
import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';
import { parseDnsTcpdumpLine } from './dns-tcpdump-line.js';

/**
 * Passive DNS observer via tcpdump :53.
 * Records recent query names as signals only — never promotes them to device hostname
 * (browsers on the agent host would otherwise flip hostname every few seconds).
 */
export class DnsPassiveListener {
  private proc: ChildProcess | null = null;

  constructor(
    private readonly store: IPassiveSignalStore,
    private readonly logger: Logger,
    private readonly iface: string,
  ) {}

  start(): void {
    if (this.proc) return;
    this.proc = spawn('tcpdump', ['-i', this.iface, '-nn', '-l', 'port', '53'], {
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    this.proc.stdout?.on('data', (chunk: Buffer) => {
      for (const line of chunk.toString().split('\n')) this.parseLine(line);
    });
    this.proc.on('exit', () => {
      this.proc = null;
    });
    this.logger.info({ iface: this.iface }, 'DNS passive listener started');
  }

  stop(): void {
    this.proc?.kill('SIGTERM');
    this.proc = null;
  }

  private parseLine(line: string): void {
    const parsed = parseDnsTcpdumpLine(line);
    if (!parsed) return;

    void this.store.ingest({
      ip: parsed.clientIp,
      source: 'dns-passive',
      signals: {
        dnsRecentQueries: [parsed.query],
        dnsPassive: true,
      },
    });
  }
}
