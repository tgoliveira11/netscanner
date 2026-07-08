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
  /**
   * Preferred list of interfaces for tcpdump fallback. Use `['any']` (or include
   * `any` among several) for a single `tcpdump -i any` process on macOS/Linux.
   */
  ifaces?: string[];
  /** @deprecated Prefer `ifaces`. Single interface for tcpdump fallback. */
  iface?: string;
  /** Persist each capture (SQLite, etc.). */
  persist?: (fp: DhcpFingerprint) => Promise<void>;
  /** Load prior captures on startup. */
  hydrate?: () => Promise<DhcpFingerprint[]>;
  /** Sync hook for background enrichment (keep fast). */
  onCaptured?: (fp: DhcpFingerprint) => void;
}

/** Resolve effective tcpdump iface list from options. */
export function resolveDhcpSniffIfaces(options: Pick<DhcpSnifferOptions, 'ifaces' | 'iface'>): string[] {
  if (options.ifaces?.length) {
    return [...new Set(options.ifaces.map((i) => i.trim()).filter(Boolean))];
  }
  if (options.iface?.trim()) return [options.iface.trim()];
  return ['en0'];
}

/**
 * Passive DHCP fingerprint sniffer. Prefers binding UDP :67; when that port is
 * taken (macOS Internet Sharing, another DHCP server), falls back to tcpdump on
 * local interfaces — still fully passive, never transmits.
 *
 * Routed VLANs without L2 on this host are invisible here; use RemoteDhcpSniffer
 * on the switch/gateway bridge for those.
 */
export class DhcpSniffer implements IDhcpFingerprintSource {
  private socket: Socket | null = null;
  private tcpdumpProcs: ChildProcess[] = [];
  private captureMode: 'udp' | 'tcpdump' | null = null;
  private listeningIfaces: string[] = [];
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

    const ifaces = resolveDhcpSniffIfaces(this.options);
    if (this.startTcpdumpFallback(ifaces)) return;

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
        this.listeningIfaces = ['udp:67'];
        this.logger.info('DHCP fingerprint sniffer listening on UDP :67');
        finish(true);
      });
    });
  }

  private startTcpdumpFallback(ifaces: string[]): boolean {
    const useAny = ifaces.includes('any') || ifaces.length > 1;
    const targets = useAny ? ['any'] : ifaces;
    let started = 0;
    for (const iface of targets) {
      if (this.spawnTcpdump(iface)) started += 1;
    }
    if (started === 0) return false;
    this.captureMode = 'tcpdump';
    this.listeningIfaces = [...targets];
    this.logger.info(
      { ifaces: this.listeningIfaces, requested: ifaces },
      'DHCP fingerprint sniffer listening via tcpdump',
    );
    return true;
  }

  private spawnTcpdump(iface: string): boolean {
    try {
      const proc = spawn(
        'tcpdump',
        ['-i', iface, '-n', '-l', '-s', '512', '-xx', 'udp', 'port', '67'],
        { stdio: ['ignore', 'pipe', 'pipe'] },
      );
      this.tcpdumpProcs.push(proc);

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
          this.logger.debug({ iface, stderr: msg }, 'tcpdump dhcp');
        }
      });

      proc.on('exit', (code, signal) => {
        flush();
        this.tcpdumpProcs = this.tcpdumpProcs.filter((p) => p !== proc);
        if (this.tcpdumpProcs.length === 0 && this.captureMode === 'tcpdump') {
          this.captureMode = null;
          this.listeningIfaces = [];
        }
        if (code !== 0 && code !== null) {
          this.logger.warn({ iface, code, signal }, 'DHCP tcpdump exited');
        }
      });

      return true;
    } catch (error) {
      this.logger.warn(
        { iface, error: error instanceof Error ? error.message : error },
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

  /** Interfaces currently used for capture (udp:67 or tcpdump ifaces). */
  sniffIfaces(): string[] {
    return [...this.listeningIfaces];
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
    for (const proc of this.tcpdumpProcs) {
      try {
        proc.kill('SIGTERM');
      } catch {
        /* ignore */
      }
    }
    this.tcpdumpProcs = [];
    this.captureMode = null;
    this.listeningIfaces = [];
  }
}
