import { spawn, type ChildProcess } from 'node:child_process';
import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';

export interface NetdiscoverPassiveListenerOptions {
  store: IPassiveSignalStore;
  logger: Logger;
  runner: ICommandRunner;
  iface: string;
}

/**
 * Parse a netdiscover passive output line.
 * Typical: ` 192.168.1.10   00:11:22:33:44:55    1      60  Vendor Name`
 */
export function parseNetdiscoverLine(line: string): {
  ip: string;
  mac: string;
  vendor?: string;
} | null {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith('IP') || trimmed.startsWith('---') || trimmed.startsWith('Currently')) {
    return null;
  }
  const m =
    /^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})(?:\s+\d+\s+\d+\s+(.*))?$/i.exec(
      trimmed,
    );
  if (!m) return null;
  const vendor = m[3]?.trim();
  return {
    ip: m[1]!,
    mac: m[2]!.toLowerCase(),
    vendor: vendor && vendor !== '' ? vendor : undefined,
  };
}

/**
 * Continuous passive ARP via `netdiscover -p`. Feeds quiet hosts into the
 * passive store so enrichment/onUpdated can upsert stubs.
 */
export class NetdiscoverPassiveListener {
  private proc: ChildProcess | null = null;

  constructor(private readonly opts: NetdiscoverPassiveListenerOptions) {}

  async start(): Promise<void> {
    if (this.proc) return;
    const has = await this.opts.runner.which('netdiscover');
    if (!has) {
      this.opts.logger.info('netdiscover not installed — passive ARP skipped');
      return;
    }
    this.proc = spawn('netdiscover', ['-p', '-i', this.opts.iface], {
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    this.proc.stdout?.on('data', (chunk: Buffer) => {
      for (const line of chunk.toString().split('\n')) this.ingestLine(line);
    });
    this.proc.on('exit', () => {
      this.proc = null;
    });
    this.opts.logger.info({ iface: this.opts.iface }, 'netdiscover passive listener started');
  }

  stop(): void {
    this.proc?.kill('SIGTERM');
    this.proc = null;
  }

  private ingestLine(line: string): void {
    const parsed = parseNetdiscoverLine(line);
    if (!parsed) return;
    const signals: Record<string, unknown> = { arpPassive: true, netdiscover: true };
    if (parsed.vendor) signals['arpVendor'] = parsed.vendor;

    void this.opts.store.ingest({
      ip: parsed.ip,
      mac: parsed.mac,
      source: 'netdiscover',
      signals,
    });
  }
}
