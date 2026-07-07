import { spawn, type ChildProcess } from 'node:child_process';
import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';

const MAC_RE = /([0-9a-f]{2}(:[0-9a-f]{2}){5})/i;
const DUID_RE = /duid ([0-9a-f:]+)/i;
const HOSTNAME_RE = /hostname "([^"]+)"/i;

/** DHCPv6 and IPv6 router advertisements — MAC/DUID/hostname hints. */
export class Dhcpv6PassiveListener {
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
      ['-i', this.iface, '-nn', '-l', 'udp port 546 or icmp6[icmp6type]=134 or icmp6[icmp6type]=133'],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    );
    this.proc.stdout?.on('data', (chunk: Buffer) => {
      for (const line of chunk.toString().split('\n')) this.parseLine(line);
    });
    this.proc.on('exit', () => {
      this.proc = null;
    });
    this.logger.info({ iface: this.iface }, 'DHCPv6/RA passive listener started');
  }

  stop(): void {
    this.proc?.kill('SIGTERM');
    this.proc = null;
  }

  private parseLine(line: string): void {
    const mac = MAC_RE.exec(line)?.[1]?.toLowerCase();
    const duid = DUID_RE.exec(line)?.[1];
    const hostname = HOSTNAME_RE.exec(line)?.[1];
    const ipv6 = /(([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4})/i.exec(line)?.[1];

    if (!mac && !ipv6) return;
    const signals: Record<string, unknown> = { ipv6Passive: true };
    if (duid) signals['ipv6Duid'] = duid;
    if (/router advertisement/i.test(line)) signals['ipv6Ra'] = true;
    if (/dhcp6/i.test(line)) signals['dhcpv6'] = true;

    void this.store.ingest({
      ip: ipv6 ? `ipv6:${ipv6}` : mac ? `ipv6:${mac}` : 'ipv6:unknown',
      mac: mac ?? undefined,
      hostname: hostname ?? undefined,
      source: 'dhcpv6-passive',
      signals,
    });
  }
}
