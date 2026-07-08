import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { HostFingerprint, IDeepScanner, ScanTarget } from '../domain/deep-scanner.js';
import { parseNmapXml } from './nmap-xml.parser.js';

export interface NmapOptions {
  /** Whether the process is elevated; gates OS detection (-O). */
  elevated: boolean;
  disabled?: boolean;
}

/**
 * Deep-scan adapter wrapping the nmap binary. Emits XML to stdout (`-oX -`),
 * which is parsed by parseNmapXml. Chooses port breadth by scan depth and only
 * requests OS detection when elevated (honest capability handling).
 */
export class NmapScanner implements IDeepScanner {
  readonly name = 'nmap';

  constructor(
    private readonly runner: ICommandRunner,
    private readonly options: NmapOptions,
  ) {}

  async isAvailable(): Promise<boolean> {
    if (this.options.disabled) return false;
    return this.runner.which('nmap');
  }

  private buildArgs(target: ScanTarget): string[] {
    const args = ['-oX', '-', '-Pn', '-sV'];
    if (this.options.elevated) args.push('-sS');
    if (target.depth === 'quick') args.push('-F');
    else if (target.depth === 'deep') {
      args.push('-p-');
      if (this.options.elevated) args.push('-sU', '--top-ports', '100');
    } else args.push('--top-ports', '1000');
    if (target.osDetection && this.options.elevated) args.push('-O', '--osscan-guess');
    if (target.depth !== 'quick') {
      const scripts = [
        'banner',
        'http-title',
        'http-server-header',
        'http-enum',
        'ssl-cert',
        'ssl-ja3',
        'upnp-info',
        'smb-os-discovery',
        'smb2-security-mode',
        'smb-protocols',
        'ssh-hostkey',
        'nbstat',
      ];
      if (target.depth === 'deep') scripts.push('rpc-grind', 'ws-discovery');
      args.push('--script', scripts.join(','));
    }
    args.push('--host-timeout', `${Math.round(target.timeoutMs / 1000)}s`, target.ip);
    return args;
  }

  async scan(target: ScanTarget): Promise<HostFingerprint> {
    const res = await this.runner.run('nmap', this.buildArgs(target), {
      timeoutMs: target.timeoutMs + 5000,
    });
    const parsed = res.stdout ? parseNmapXml(res.stdout) : null;
    return (
      parsed ?? {
        ip: target.ip,
        services: [],
        os: null,
        vendorFromScan: null,
        hostname: null,
        source: 'nmap',
      }
    );
  }
}
