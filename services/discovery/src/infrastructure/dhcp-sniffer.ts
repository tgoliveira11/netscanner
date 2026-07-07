import { createSocket, type Socket } from 'node:dgram';
import { spawn, type ChildProcess } from 'node:child_process';
import type { Logger } from '@netscanner/logger';
import {
  parseDhcpPacket,
  type DhcpFingerprint,
  type IDhcpFingerprintSource,
} from '../domain/dhcp-fingerprint.js';
import {
  dhcpPayloadFromTcpdumpHex,
  isTcpdumpHexLine,
  isTcpdumpPacketHeader,
} from './dhcp-tcpdump-parser.js';

export interface DhcpSnifferOptions {
  /** Interface for tcpdump fallback when UDP :67 is busy (e.g. macOS Internet Sharing). */
  iface?: string;
  /** Persist each capture (SQLite, etc.). */
  persist?: (fp: DhcpFingerprint) => Promise<void>;
  /** Load prior captures on startup. */
  hydrate?: () => Promise<DhcpFingerprint[]>;
  /** Sync hook for background enrichment (keep fast). */
  onCaptured?: (fp: DhcpFingerprint) => void;
}

/**
 * Passive DHCP fingerprint sniffer. Prefers binding UDP :67; when that port is
 * taken (macOS Internet Sharing, another DHCP server), falls back to tcpdump on
 * the LAN interface — still fully passive, never transmits.
 */
export class DhcpSniffer implements IDhcpFingerprintSource {
  private socket: Socket | null = null;
  private tcpdumpProc: ChildProcess | null = null;
  private captureMode: 'udp' | 'tcpdump' | null = null;
  private readonly cache = new Map<string, DhcpFingerprint>();
  private readonly capturedHandlers = new Set<(fp: DhcpFingerprint) => void>();

  constructor(
    private readonly logger: Logger,
    private readonly options: DhcpSnifferOptions = {},
  ) {}

  async start(): Promise<void> {
    if (this.options.hydrate) {
      try {
        const prior = await this.options.hydrate();
        for (const fp of prior) this.cache.set(fp.mac.toLowerCase(), fp);
        if (prior.length) {
          this.logger.info({ count: prior.length }, 'DHCP fingerprints restored from storage');
        }
      } catch (error) {
        this.logger.warn(
          { error: error instanceof Error ? error.message : error },
          'failed to hydrate DHCP fingerprints',
        );
      }
    }

    if (await this.tryUdpBind()) return;

    const iface = this.options.iface ?? 'en0';
    if (this.startTcpdump(iface)) return;

    this.logger.warn('DHCP sniffer unavailable (UDP :67 busy and tcpdump failed to start)');
  }

  private tryUdpBind(): Promise<boolean> {
    return new Promise((resolve) => {
      const socket = createSocket({ type: 'udp4', reuseAddr: true });
      let settled = false;
      const finish = (ok: boolean) => {
        if (settled) return;
        settled = true;
        resolve(ok);
      };

      socket.on('message', (msg) => void this.ingest(msg));
      socket.on('error', (err) => {
        try {
          socket.close();
        } catch {
          /* ignore */
        }
        this.logger.warn({ err: err.message }, 'UDP :67 unavailable, trying tcpdump fallback');
        finish(false);
      });
      socket.bind(67, () => {
        try {
          socket.setBroadcast(true);
        } catch {
          /* ignore */
        }
        this.socket = socket;
        this.captureMode = 'udp';
        this.logger.info('DHCP fingerprint sniffer listening on UDP :67');
        finish(true);
      });
    });
  }

  private startTcpdump(iface: string): boolean {
    try {
      const proc = spawn(
        'tcpdump',
        ['-i', iface, '-n', '-l', '-s', '512', '-xx', 'udp', 'port', '67'],
        { stdio: ['ignore', 'pipe', 'pipe'] },
      );
      this.tcpdumpProc = proc;
      this.captureMode = 'tcpdump';

      let hexLines: string[] = [];
      const flush = () => {
        if (!hexLines.length) return;
        const payload = dhcpPayloadFromTcpdumpHex(hexLines);
        hexLines = [];
        if (payload) void this.ingest(payload);
      };

      proc.stdout?.setEncoding('utf8');
      proc.stdout?.on('data', (chunk: string) => {
        for (const line of chunk.split('\n')) {
          if (!line.trim()) continue;
          if (isTcpdumpPacketHeader(line)) {
            flush();
            continue;
          }
          if (isTcpdumpHexLine(line)) hexLines.push(line);
        }
      });

      proc.stderr?.on('data', (chunk: Buffer) => {
        const msg = chunk.toString('utf8').trim();
        if (msg && !msg.includes('listening on')) {
          this.logger.debug({ stderr: msg }, 'tcpdump dhcp');
        }
      });

      proc.on('exit', (code, signal) => {
        flush();
        if (this.tcpdumpProc === proc) {
          this.tcpdumpProc = null;
          if (this.captureMode === 'tcpdump') this.captureMode = null;
        }
        if (code !== 0 && code !== null) {
          this.logger.warn({ code, signal }, 'DHCP tcpdump exited');
        }
      });

      this.logger.info({ iface }, 'DHCP fingerprint sniffer listening via tcpdump');
      return true;
    } catch (error) {
      this.logger.warn(
        { error: error instanceof Error ? error.message : error },
        'failed to start DHCP tcpdump fallback',
      );
      return false;
    }
  }

  private async ingest(msg: Buffer): Promise<void> {
    const parsed = parseDhcpPacket(msg);
    if (!parsed) return;
    if (![1, 3, 8].includes(parsed.messageType)) return;

    const mac = parsed.mac.toLowerCase();
    const prev = this.cache.get(mac);
    const fp: DhcpFingerprint = {
      mac: parsed.mac,
      fingerprint: parsed.fingerprint,
      vendorClass: parsed.vendorClass,
      hostname: parsed.hostname,
    };
    const changed =
      !prev ||
      prev.fingerprint !== fp.fingerprint ||
      prev.vendorClass !== fp.vendorClass ||
      prev.hostname !== fp.hostname;

    this.cache.set(mac, fp);
    this.logger.debug({ mac: fp.mac, fingerprint: fp.fingerprint }, 'DHCP fingerprint captured');

    if (!changed) return;

    if (this.options.persist) {
      try {
        await this.options.persist(fp);
      } catch (error) {
        this.logger.warn(
          { mac: fp.mac, error: error instanceof Error ? error.message : error },
          'failed to persist DHCP fingerprint',
        );
      }
    }

    this.options.onCaptured?.(fp);
    for (const handler of this.capturedHandlers) {
      try {
        handler(fp);
      } catch {
        /* listener must not break capture */
      }
    }
  }

  get(mac: string): DhcpFingerprint | undefined {
    return this.cache.get(mac.toLowerCase());
  }

  list(): DhcpFingerprint[] {
    return [...this.cache.values()];
  }

  size(): number {
    return this.cache.size;
  }

  isListening(): boolean {
    return this.captureMode !== null;
  }

  mode(): 'udp' | 'tcpdump' | null {
    return this.captureMode;
  }

  onCaptured(handler: (fp: DhcpFingerprint) => void): () => void {
    this.capturedHandlers.add(handler);
    return () => this.capturedHandlers.delete(handler);
  }

  stop(): void {
    try {
      this.socket?.close();
    } catch {
      /* ignore */
    }
    this.socket = null;
    if (this.tcpdumpProc) {
      try {
        this.tcpdumpProc.kill('SIGTERM');
      } catch {
        /* ignore */
      }
      this.tcpdumpProc = null;
    }
    this.captureMode = null;
  }
}
