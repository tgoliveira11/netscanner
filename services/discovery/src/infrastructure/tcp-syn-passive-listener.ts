import { spawn, type ChildProcess } from 'node:child_process';
import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';
import { parseTcpSynLine, traitsToSignal } from '../domain/p0f-fingerprint.js';

/**
 * Passive TCP SYN stack fingerprinting (p0f-style) via tcpdump.
 * Observes outbound SYNs from LAN hosts → OS hints without active nmap.
 */
export class TcpSynPassiveListener {
  private proc: ChildProcess | null = null;

  constructor(
    private readonly store: IPassiveSignalStore,
    private readonly logger: Logger,
    private readonly iface: string,
  ) {}

  start(): void {
    if (this.proc) return;
    this.proc = spawn(
      'tcpdump',
      [
        '-i',
        this.iface,
        '-nn',
        '-l',
        '-v',
        'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack = 0',
      ],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    );
    this.proc.stdout?.on('data', (chunk: Buffer) => {
      for (const line of chunk.toString().split('\n')) this.parseLine(line);
    });
    this.proc.on('exit', () => {
      this.proc = null;
    });
    this.logger.info({ iface: this.iface }, 'TCP SYN passive (p0f-style) listener started');
  }

  stop(): void {
    this.proc?.kill('SIGTERM');
    this.proc = null;
  }

  private parseLine(line: string): void {
    const parsed = parseTcpSynLine(line);
    if (!parsed) return;
    void this.store.ingest({
      ip: parsed.ip,
      source: 'p0f-passive',
      signals: traitsToSignal(parsed.traits),
    });
  }
}
