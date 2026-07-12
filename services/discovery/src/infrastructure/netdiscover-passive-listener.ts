import { spawn, type ChildProcess } from 'node:child_process';
import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';

export interface NetdiscoverPassiveListenerOptions {
  store: IPassiveSignalStore;
  logger: Logger;
  runner: ICommandRunner;
  iface: string;
  /** Min interval between store.ingest calls for the same MAC (ms). */
  ingestCooldownMs?: number;
}

/**
 * Parse a netdiscover parseable-mode line (`-L`/`-P`).
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
 * Parse `tcpdump -nn -l -e arp` lines into IP/MAC pairs.
 * - Request who-has X tell Y → learn Y at ethernet src MAC
 * - Reply X is-at MAC → learn X at MAC
 */
export function parseTcpdumpArpLine(line: string): { ip: string; mac: string } | null {
  const reply =
    /Reply\s+(\d{1,3}(?:\.\d{1,3}){3})\s+is-at\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})/i.exec(line);
  if (reply) {
    return { ip: reply[1]!, mac: reply[2]!.toLowerCase() };
  }

  const req =
    /([0-9a-f]{2}(?::[0-9a-f]{2}){5})\s+>\s+\S+,\s+ethertype ARP[\s\S]*?Request who-has\s+\d{1,3}(?:\.\d{1,3}){3}\s+tell\s+(\d{1,3}(?:\.\d{1,3}){3})/i.exec(
      line,
    );
  if (req) {
    return { ip: req[2]!, mac: req[1]!.toLowerCase() };
  }

  // Fallback without -e: "Request who-has X tell Y" (no MAC — skip)
  return null;
}

/**
 * Continuous passive ARP observation.
 *
 * IMPORTANT: never run `netdiscover -p` in interactive mode — it redraws the
 * full screen to stdout and can emit 100MB+/s, pegging CPU and starving the
 * gateway event loop (background scans stuck in `discovering`).
 *
 * We use `tcpdump -e arp` instead (line-oriented, cheap). Optional one-shot
 * `netdiscover -L -N` remains available for parseable vendor enrichment.
 */
export class NetdiscoverPassiveListener {
  private proc: ChildProcess | null = null;
  private readonly lastIngest = new Map<string, number>();
  private readonly cooldownMs: number;

  constructor(private readonly opts: NetdiscoverPassiveListenerOptions) {
    this.cooldownMs = opts.ingestCooldownMs ?? 60_000;
  }

  async start(): Promise<void> {
    if (this.proc) return;
    const hasTcpdump = await this.opts.runner.which('tcpdump');
    if (!hasTcpdump) {
      this.opts.logger.info('tcpdump not installed — passive ARP skipped');
      return;
    }
    // Line-buffered ARP with ethernet headers so Requests carry a src MAC.
    this.proc = spawn('tcpdump', ['-i', this.opts.iface, '-nn', '-l', '-e', 'arp'], {
      stdio: ['ignore', 'pipe', 'ignore'],
    });
    let buf = '';
    this.proc.stdout?.on('data', (chunk: Buffer) => {
      buf += chunk.toString();
      const parts = buf.split('\n');
      buf = parts.pop() ?? '';
      for (const line of parts) this.ingestTcpdumpLine(line);
    });
    this.proc.on('exit', (code, signal) => {
      this.proc = null;
      if (code && code !== 0) {
        this.opts.logger.warn(
          { iface: this.opts.iface, code, signal },
          'ARP tcpdump exited',
        );
      }
    });
    this.opts.logger.info(
      { iface: this.opts.iface, mode: 'tcpdump-arp' },
      'ARP passive listener started (tcpdump; not interactive netdiscover)',
    );
  }

  stop(): void {
    this.proc?.kill('SIGTERM');
    this.proc = null;
  }

  private ingestTcpdumpLine(line: string): void {
    const parsed = parseTcpdumpArpLine(line);
    if (!parsed) return;
    this.ingest(parsed.ip, parsed.mac);
  }

  /** Visible for tests — applies cooldown then store.ingest. */
  ingest(ip: string, mac: string, vendor?: string): void {
    const now = Date.now();
    const prev = this.lastIngest.get(mac) ?? 0;
    if (now - prev < this.cooldownMs) return;
    this.lastIngest.set(mac, now);
    // Bound map growth on long uptimes with many transient MACs.
    if (this.lastIngest.size > 5_000) {
      const cutoff = now - this.cooldownMs;
      for (const [k, ts] of this.lastIngest) {
        if (ts < cutoff) this.lastIngest.delete(k);
      }
    }

    const signals: Record<string, unknown> = { arpPassive: true, netdiscover: true };
    if (vendor) signals['arpVendor'] = vendor;

    void this.opts.store.ingest({
      ip,
      mac,
      source: 'netdiscover',
      signals,
    });
  }
}
