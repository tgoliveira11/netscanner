import { spawn, type ChildProcess } from 'node:child_process';
import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';
import { parseDnsTcpdumpLine } from './dns-tcpdump-line.js';

export interface RemoteDnsPassiveListenerOptions {
  host: string;
  port?: number;
  username?: string;
  /** Never logged. */
  password?: string;
  /** Remote capture iface (pfSense: any; OpenWrt bridge: br-lan). */
  remoteIface?: string;
  label?: string;
}

/**
 * Stream DNS queries via SSH + tcpdump on pfSense / OpenWrt so guest/IoT VLANs
 * are visible to the agent (local sniff only sees this host's L2 segment).
 */
export class RemoteDnsPassiveListener {
  private proc: ChildProcess | null = null;
  private listening = false;
  private readonly remoteIface: string;
  private readonly username: string;
  private readonly port: number;

  constructor(
    private readonly store: IPassiveSignalStore,
    private readonly logger: Logger,
    private readonly options: RemoteDnsPassiveListenerOptions,
  ) {
    this.remoteIface = options.remoteIface?.trim() || 'any';
    this.username = options.username?.trim() || 'admin';
    this.port = options.port && options.port > 0 ? options.port : 22;
  }

  start(): void {
    if (this.proc) return;
    const host = this.options.host;
    const remoteCmd = `tcpdump -i ${this.remoteIface} -nn -l port 53`;
    const sshBase = [
      '-p',
      String(this.port),
      '-o',
      'BatchMode=no',
      '-o',
      'StrictHostKeyChecking=accept-new',
      '-o',
      'ConnectTimeout=8',
      `${this.username}@${host}`,
      remoteCmd,
    ];

    let proc: ChildProcess;
    if (this.options.password) {
      proc = spawn('sshpass', ['-e', 'ssh', ...sshBase], {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, SSHPASS: this.options.password },
      });
    } else {
      proc = spawn(
        'ssh',
        [
          '-p',
          String(this.port),
          '-o',
          'BatchMode=yes',
          '-o',
          'StrictHostKeyChecking=accept-new',
          '-o',
          'ConnectTimeout=8',
          `${this.username}@${host}`,
          remoteCmd,
        ],
        { stdio: ['ignore', 'pipe', 'pipe'] },
      );
    }

    this.proc = proc;
    const label = this.options.label ?? host;

    const markListening = () => {
      if (this.listening) return;
      this.listening = true;
      this.logger.info(
        { host, port: this.port, iface: this.remoteIface, label },
        'remote DNS passive listener started',
      );
    };

    const bootTimer = setTimeout(() => {
      if (this.proc === proc && proc.exitCode === null) markListening();
    }, 1500);

    proc.stdout?.setEncoding('utf8');
    proc.stdout?.on('data', (chunk: string) => {
      markListening();
      for (const line of chunk.split('\n')) this.parseLine(line);
    });

    proc.stderr?.on('data', (chunk: Buffer) => {
      const msg = chunk.toString('utf8').trim();
      if (!msg) return;
      if (/listening on/i.test(msg)) {
        markListening();
        return;
      }
      if (/password|passphrase|sshpass/i.test(msg)) {
        this.logger.warn({ host, label }, 'remote DNS ssh auth issue');
      }
    });

    proc.on('exit', (code) => {
      clearTimeout(bootTimer);
      if (this.proc === proc) {
        this.proc = null;
        this.listening = false;
      }
      if (code !== 0 && code !== null) {
        this.logger.warn({ host, code, label }, 'remote DNS tcpdump exited');
      }
    });

    proc.on('error', (err) => {
      clearTimeout(bootTimer);
      this.logger.warn({ host, error: err.message, label }, 'remote DNS spawn failed');
      if (this.proc === proc) {
        this.proc = null;
        this.listening = false;
      }
    });
  }

  stop(): void {
    this.proc?.kill('SIGTERM');
    this.proc = null;
    this.listening = false;
  }

  private parseLine(line: string): void {
    const parsed = parseDnsTcpdumpLine(line);
    if (!parsed) return;

    void this.store.ingest({
      ip: parsed.clientIp,
      source: 'dns-remote',
      signals: {
        dnsRecentQueries: [parsed.query],
        dnsPassive: true,
      },
    });
  }
}
