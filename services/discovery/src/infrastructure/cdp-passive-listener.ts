import { spawn, type ChildProcess } from 'node:child_process';
import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';

const MAC_RE = /([0-9a-f]{2}(:[0-9a-f]{2}){5})/gi;
const DEVICE_ID_RE = /Device ID: (.+)/i;
const PLATFORM_RE = /Platform: (.+?),/i;

/**
 * Cisco CDP passive capture (LLDP's Cisco cousin).
 * Filters ethertype 0x2000; parses device-id / platform when tcpdump -v exposes them.
 */
export class CdpPassiveListener {
  private proc: ChildProcess | null = null;

  constructor(
    private readonly store: IPassiveSignalStore,
    private readonly logger: Logger,
    private readonly iface: string,
  ) {}

  start(): void {
    if (this.proc) return;
    this.proc = spawn('tcpdump', ['-i', this.iface, '-nn', '-e', '-l', '-v', 'ether proto 0x2000'], {
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    this.proc.stdout?.on('data', (chunk: Buffer) => {
      for (const line of chunk.toString().split('\n')) this.parseLine(line);
    });
    this.proc.on('exit', () => {
      this.proc = null;
    });
    this.logger.info({ iface: this.iface }, 'CDP passive listener started');
  }

  stop(): void {
    this.proc?.kill('SIGTERM');
    this.proc = null;
  }

  private parseLine(line: string): void {
    const deviceId = DEVICE_ID_RE.exec(line)?.[1]?.trim();
    const platform = PLATFORM_RE.exec(line)?.[1]?.trim();
    const macs = [...line.matchAll(MAC_RE)].map((m) => m[1]!.toLowerCase());
    const mac = macs[0];
    if (!mac && !deviceId) return;

    const signals: Record<string, unknown> = { cdpPassive: true };
    if (deviceId) signals.cdpDeviceId = deviceId;
    if (platform) signals.cdpPlatform = platform;

    void this.store.ingest({
      ip: mac ? `cdp:${mac}` : `cdp:${deviceId ?? 'unknown'}`,
      mac: mac ?? undefined,
      hostname: deviceId ?? undefined,
      source: 'cdp-passive',
      signals,
    });
  }
}
