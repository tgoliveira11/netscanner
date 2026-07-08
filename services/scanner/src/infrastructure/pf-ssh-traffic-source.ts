import { spawn } from 'node:child_process';
import type { Logger } from '@netscanner/logger';
import type { ITrafficSource, TrafficSample } from '../domain/traffic-source.js';
import { parsePfStates } from './pf-states-traffic.parser.js';

export interface PfSshTrafficSourceOptions {
  host: string;
  port?: number;
  username?: string;
  /** Never logged. */
  password?: string;
  /** Remote command (pfSense: pfctl -vvs state). */
  command?: string;
  timeoutMs?: number;
}

function hostFromUrl(baseUrl: string): string {
  try {
    const u = new URL(baseUrl.includes('://') ? baseUrl : `https://${baseUrl}`);
    return u.hostname;
  } catch {
    return baseUrl.replace(/^https?:\/\//, '').split('/')[0] ?? baseUrl;
  }
}

/** Resolve pfSense SSH host from PFSENSE_URL when host option omitted. */
export function resolvePfSenseSshHost(pfsenseUrl?: string, overrideHost?: string): string | null {
  const h = overrideHost?.trim() || (pfsenseUrl ? hostFromUrl(pfsenseUrl) : '');
  return h || null;
}

/**
 * Per-device traffic via SSH + `pfctl -vvs state` on pfSense.
 * Mirrors the remote DHCP sniffer SSH pattern (sshpass when password is set).
 */
export class PfSshTrafficSource implements ITrafficSource {
  readonly name = 'pf-ssh';
  private readonly host: string;
  private readonly port: number;
  private readonly username: string;
  private readonly password?: string;
  private readonly command: string;
  private readonly timeoutMs: number;

  constructor(
    private readonly logger: Logger,
    options: PfSshTrafficSourceOptions,
  ) {
    this.host = options.host;
    this.port = options.port && options.port > 0 ? options.port : 22;
    this.username = options.username?.trim() || 'admin';
    this.password = options.password;
    this.command = options.command?.trim() || 'pfctl -vvs state';
    this.timeoutMs = options.timeoutMs ?? 12_000;
  }

  async sample(): Promise<TrafficSample[]> {
    const output = await this.runRemote(this.command);
    if (!output) return [];
    const samples = parsePfStates(output);
    this.logger.debug({ host: this.host, devices: samples.length }, 'pf traffic sample');
    return samples;
  }

  private runRemote(remoteCmd: string): Promise<string | null> {
    return new Promise((resolve) => {
      const sshBase = [
        '-p',
        String(this.port),
        '-o',
        'BatchMode=no',
        '-o',
        'StrictHostKeyChecking=accept-new',
        '-o',
        'ConnectTimeout=8',
        `${this.username}@${this.host}`,
        remoteCmd,
      ];

      let proc;
      if (this.password) {
        proc = spawn('sshpass', ['-e', 'ssh', ...sshBase], {
          stdio: ['ignore', 'pipe', 'pipe'],
          env: { ...process.env, SSHPASS: this.password },
        });
      } else {
        proc = spawn(
          'ssh',
          ['-p', String(this.port), '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=8', `${this.username}@${this.host}`, remoteCmd],
          { stdio: ['ignore', 'pipe', 'pipe'] },
        );
      }

      let stdout = '';
      let stderr = '';
      const timer = setTimeout(() => {
        try {
          proc.kill('SIGTERM');
        } catch {
          /* ignore */
        }
        this.logger.warn({ host: this.host }, 'pf traffic SSH timed out');
        resolve(null);
      }, this.timeoutMs);

      proc.stdout?.setEncoding('utf8');
      proc.stdout?.on('data', (chunk: string) => {
        stdout += chunk;
      });
      proc.stderr?.on('data', (chunk: Buffer) => {
        stderr += chunk.toString('utf8');
      });

      proc.on('exit', (code) => {
        clearTimeout(timer);
        if (code !== 0) {
          if (stderr && !/password|passphrase/i.test(stderr)) {
            this.logger.warn(
              { host: this.host, code, stderr: stderr.slice(0, 200) },
              'pf traffic SSH failed',
            );
          } else {
            this.logger.warn({ host: this.host, code }, 'pf traffic SSH auth or command failed');
          }
          resolve(null);
          return;
        }
        resolve(stdout);
      });

      proc.on('error', (err) => {
        clearTimeout(timer);
        this.logger.warn({ host: this.host, error: err.message }, 'pf traffic SSH spawn failed');
        resolve(null);
      });
    });
  }
}
