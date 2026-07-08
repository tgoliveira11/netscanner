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

export interface RemoteDhcpSnifferOptions {
  host: string;
  username?: string;
  /** Never logged. Prefer key-based auth when possible. */
  password?: string;
  /** Bridge / capture iface on the remote host (default br-lan). */
  remoteIface?: string;
  persist?: (fp: DhcpFingerprint) => Promise<void>;
  hydrate?: () => Promise<DhcpFingerprint[]>;
  onCaptured?: (fp: DhcpFingerprint) => void;
}

/**
 * Stream DHCP DISCOVER/REQUEST fingerprints via SSH + tcpdump on a remote
 * OpenWrt DSA switch (typically `br-lan`), which can see guest/iot/main VLANs
 * that a Mac on a single access VLAN cannot.
 */
export class RemoteDhcpSniffer implements IDhcpFingerprintSource {
  private proc: ChildProcess | null = null;
  private listening = false;
  private readonly cache = new Map<string, DhcpFingerprint>();
  private readonly capturedHandlers = new Set<(fp: DhcpFingerprint) => void>();
  private readonly remoteIface: string;
  private readonly username: string;

  constructor(
    private readonly logger: Logger,
    private readonly options: RemoteDhcpSnifferOptions,
  ) {
    this.remoteIface = options.remoteIface?.trim() || 'br-lan';
    this.username = options.username?.trim() || 'root';
  }

  async start(): Promise<void> {
    if (this.options.hydrate) {
      try {
        const prior = await this.options.hydrate();
        for (const fp of prior) this.cache.set(fp.mac.toLowerCase(), fp);
        if (prior.length) {
          this.logger.info(
            { count: prior.length },
            'DHCP fingerprints restored from storage (remote)',
          );
        }
      } catch (error) {
        this.logger.warn(
          { error: error instanceof Error ? error.message : error },
          'failed to hydrate DHCP fingerprints (remote)',
        );
      }
    }

    if (!this.spawnRemoteTcpdump()) {
      this.logger.warn(
        { host: this.options.host },
        'remote DHCP sniff failed to start; continuing without it',
      );
    }
  }

  private spawnRemoteTcpdump(): boolean {
    const host = this.options.host;
    const remoteCmd = `tcpdump -i ${this.remoteIface} -n -l -s 512 -xx udp port 67`;
    const sshBase = [
      '-o',
      'BatchMode=no',
      '-o',
      'StrictHostKeyChecking=accept-new',
      '-o',
      'ConnectTimeout=8',
      `${this.username}@${host}`,
      remoteCmd,
    ];

    try {
      let proc: ChildProcess;
      if (this.options.password) {
        proc = spawn('sshpass', ['-e', 'ssh', ...sshBase], {
          stdio: ['ignore', 'pipe', 'pipe'],
          env: { ...process.env, SSHPASS: this.options.password },
        });
      } else {
        proc = spawn(
          'ssh',
          ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=8', `${this.username}@${host}`, remoteCmd],
          { stdio: ['ignore', 'pipe', 'pipe'] },
        );
      }

      this.proc = proc;
      let sawTraffic = false;
      let started = false;
      let hexLines: string[] = [];

      const flush = () => {
        if (!hexLines.length) return;
        const payload = dhcpPayloadFromTcpdumpHex(hexLines);
        hexLines = [];
        if (payload) void this.ingest(payload);
      };

      const markListening = () => {
        if (started) return;
        started = true;
        this.listening = true;
        this.logger.info(
          { host, iface: this.remoteIface },
          'DHCP fingerprint sniffer listening via remote tcpdump (switch bridge; covers other VLANs)',
        );
      };

      // Assume start succeeded once the process is alive briefly; confirm on stderr "listening".
      const bootTimer = setTimeout(() => {
        if (this.proc === proc && proc.exitCode === null) markListening();
      }, 1500);

      proc.stdout?.setEncoding('utf8');
      proc.stdout?.on('data', (chunk: string) => {
        markListening();
        sawTraffic = true;
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
        if (!msg) return;
        if (/listening on/i.test(msg)) {
          markListening();
          return;
        }
        // Do not log credentials; redact common auth noise paths
        if (/password|passphrase|sshpass/i.test(msg)) {
          this.logger.warn({ host }, 'remote DHCP ssh/tcpdump auth or stderr issue');
          return;
        }
        this.logger.debug({ host, stderr: msg.slice(0, 200) }, 'remote dhcp tcpdump');
      });

      proc.on('exit', (code, signal) => {
        clearTimeout(bootTimer);
        flush();
        if (this.proc === proc) {
          this.proc = null;
          this.listening = false;
        }
        if (code !== 0 && code !== null) {
          this.logger.warn(
            { host, code, signal, sawTraffic },
            'remote DHCP tcpdump/ssh exited; local sniff continues if available',
          );
        }
      });

      proc.on('error', (err) => {
        clearTimeout(bootTimer);
        this.logger.warn(
          { host, error: err.message },
          'remote DHCP sniff spawn failed (is ssh/sshpass installed?)',
        );
        if (this.proc === proc) {
          this.proc = null;
          this.listening = false;
        }
      });

      return true;
    } catch (error) {
      this.logger.warn(
        { host, error: error instanceof Error ? error.message : error },
        'failed to start remote DHCP sniff',
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
    this.logger.debug(
      { mac: fp.mac, fingerprint: fp.fingerprint, source: 'remote' },
      'DHCP fingerprint captured',
    );

    if (!changed) return;

    if (this.options.persist) {
      try {
        await this.options.persist(fp);
      } catch (error) {
        this.logger.warn(
          { mac: fp.mac, error: error instanceof Error ? error.message : error },
          'failed to persist DHCP fingerprint (remote)',
        );
      }
    }

    this.options.onCaptured?.(fp);
    for (const handler of this.capturedHandlers) {
      try {
        handler(fp);
      } catch {
        /* ignore */
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
    return this.listening;
  }

  mode(): string | null {
    return this.listening ? 'remote-tcpdump' : null;
  }

  sniffIfaces(): string[] {
    return this.listening ? [`${this.options.host}:${this.remoteIface}`] : [];
  }

  onCaptured(handler: (fp: DhcpFingerprint) => void): () => void {
    this.capturedHandlers.add(handler);
    return () => this.capturedHandlers.delete(handler);
  }

  stop(): void {
    if (this.proc) {
      try {
        this.proc.kill('SIGTERM');
      } catch {
        /* ignore */
      }
      this.proc = null;
    }
    this.listening = false;
  }
}

/** Documents the remote tcpdump invocation (no secrets). */
export function remoteDhcpTcpdumpCommand(iface = 'br-lan'): string {
  return `tcpdump -i ${iface} -n -l -s 512 -xx udp port 67`;
}
