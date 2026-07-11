import { spawn, type ChildProcess } from 'node:child_process';
import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';

export interface TsharkDeepListenerOptions {
  store: IPassiveSignalStore;
  logger: Logger;
  runner: ICommandRunner;
  iface: string;
}

const IP_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
const MAC_RE = /\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/i;

/**
 * Parse a single tshark `-T fields` line (tab-separated):
 * frame.protocols, ip.src, eth.src, tls.handshake.extensions_server_name,
 * http.host, dhcp.option.vendor_class_id, dhcp.option.parameter_request_list
 */
export function parseTsharkDeepLine(line: string): {
  ip?: string;
  mac?: string;
  tlsSni?: string;
  httpHost?: string;
  dhcpVendorClass?: string;
  dhcpParamList?: string;
} | null {
  const cols = line.split('\t').map((c) => c.trim());
  if (cols.length < 3) return null;
  const ip = cols[1] && IP_RE.test(cols[1]) ? cols[1] : undefined;
  const mac = cols[2] && MAC_RE.test(cols[2]) ? cols[2].toLowerCase() : undefined;
  const tlsSni = cols[3] || undefined;
  const httpHost = cols[4] || undefined;
  const dhcpVendorClass = cols[5] || undefined;
  const dhcpParamList = cols[6] || undefined;
  if (!tlsSni && !httpHost && !dhcpVendorClass && !dhcpParamList) return null;
  if (!ip && !mac) return null;
  return { ip, mac, tlsSni, httpHost, dhcpVendorClass, dhcpParamList };
}

/**
 * Deep passive capture via tshark: TLS SNI, HTTP Host, DHCP vendor class / PRL.
 * Complements Bonjour/SSDP/DNS listeners — does not replace them.
 */
export class TsharkDeepListener {
  private proc: ChildProcess | null = null;

  constructor(private readonly opts: TsharkDeepListenerOptions) {}

  async start(): Promise<void> {
    if (this.proc) return;
    const has = await this.opts.runner.which('tshark');
    if (!has) {
      this.opts.logger.info('tshark not installed — deep capture skipped');
      return;
    }
    this.proc = spawn(
      'tshark',
      [
        '-i',
        this.opts.iface,
        '-l',
        '-n',
        '-T',
        'fields',
        '-e',
        'frame.protocols',
        '-e',
        'ip.src',
        '-e',
        'eth.src',
        '-e',
        'tls.handshake.extensions_server_name',
        '-e',
        'http.host',
        '-e',
        'dhcp.option.vendor_class_id',
        '-e',
        'dhcp.option.parameter_request_list',
        '-Y',
        'tls.handshake.extensions_server_name or http.host or dhcp.option.vendor_class_id',
      ],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    );
    this.proc.stdout?.on('data', (chunk: Buffer) => {
      for (const line of chunk.toString().split('\n')) this.ingestLine(line);
    });
    this.proc.on('exit', () => {
      this.proc = null;
    });
    this.opts.logger.info({ iface: this.opts.iface }, 'tshark deep listener started');
  }

  stop(): void {
    this.proc?.kill('SIGTERM');
    this.proc = null;
  }

  private ingestLine(line: string): void {
    const parsed = parseTsharkDeepLine(line);
    if (!parsed) return;
    const signals: Record<string, unknown> = { tsharkDeep: true };
    if (parsed.tlsSni) signals['tlsSniRecent'] = [parsed.tlsSni];
    if (parsed.httpHost) signals['httpHostRecent'] = [parsed.httpHost];
    if (parsed.dhcpVendorClass) signals['dhcpVendorClass'] = parsed.dhcpVendorClass;
    if (parsed.dhcpParamList) signals['dhcpParamList'] = parsed.dhcpParamList;

    void this.opts.store.ingest({
      ip: parsed.ip ?? (parsed.mac ? `tshark:${parsed.mac}` : 'tshark:unknown'),
      mac: parsed.mac,
      source: 'tshark-deep',
      signals,
    });
  }
}
