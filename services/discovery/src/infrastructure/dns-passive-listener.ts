import { spawn, type ChildProcess } from 'node:child_process';
import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';

const QUERY_RE = /(\d+\.\d+\.\d+\.\d+)\.\d+ > (\d+\.\d+\.\d+\.\d+)\.\d+:.*\? ([\w.-]+)\./;

/** Domains queried in normal browsing — not a device hostname. */
const DNS_NOISE_RE =
  /(?:^|\.)((google|gstatic|googleusercontent|googleapis|gvt\d|1e100|apple|icloud|apple-dns|mzstatic|cursor|brave|github|githubusercontent|linkedin|licdn|cloudflare|amazonaws|akamai|fastly|fbcdn|microsoft|office|live|azure|doubleclick|googlesyndication|google-analytics|fonts)\.(com|net|org|io|sh|ai))$/i;

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
    const q = QUERY_RE.exec(line);
    if (!q) return;

    const clientIp = q[1]!;
    const query = q[3]!.replace(/\.$/, '').toLowerCase();
    if (query.length < 2 || /^(localhost|local)$/i.test(query)) return;
    if (DNS_NOISE_RE.test(query)) return;

    void this.store.ingest({
      ip: clientIp,
      source: 'dns-passive',
      signals: {
        dnsRecentQueries: [query],
        dnsPassive: true,
      },
    });
  }
}
