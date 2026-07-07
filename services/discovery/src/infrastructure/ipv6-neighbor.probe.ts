import { currentPlatform, type ICommandRunner } from '@netscanner/os-abstraction';
import type { IHostProbe, ProbeContext, RawHostSignal } from '../domain/host-probe.js';

const MAC_RE = /([0-9a-f]{1,2}(:[0-9a-f]{1,2}){5})/i;
const IPV6_RE = /([0-9a-f:]+)/i;

/**
 * Reads the OS IPv6 neighbor cache (NDP) and correlates to IPv4 hosts via MAC.
 */
export class Ipv6NeighborProbe implements IHostProbe {
  readonly name = 'ipv6-neighbor';
  readonly phase = 'enrich' as const;

  constructor(private readonly runner: ICommandRunner) {}

  private neighborCommand(): { bin: string; args: string[] } | null {
    switch (currentPlatform()) {
      case 'darwin':
        return { bin: 'ndp', args: ['-an'] };
      case 'linux':
        return { bin: 'ip', args: ['-6', 'neigh', 'show'] };
      default:
        return null;
    }
  }

  private async macToIpv4(): Promise<Map<string, string>> {
    const map = new Map<string, string>();
    const res = await this.runner.run('arp', ['-a', '-n'], { timeoutMs: 5000 });
    for (const line of res.stdout.split('\n')) {
      const ipMatch = line.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
      const macMatch = MAC_RE.exec(line);
      if (ipMatch && macMatch) map.set(macMatch[1]!.toLowerCase(), ipMatch[1]!);
    }
    return map;
  }

  async run(ctx: ProbeContext, emit: (signal: RawHostSignal) => void): Promise<void> {
    const cmd = this.neighborCommand();
    if (!cmd) return;

    const [res, macIp] = await Promise.all([
      this.runner.run(cmd.bin, cmd.args, { timeoutMs: 5000 }),
      this.macToIpv4(),
    ]);
    if (!res.stdout) return;

    for (const line of res.stdout.split('\n')) {
      const macMatch = MAC_RE.exec(line);
      const ipMatch = IPV6_RE.exec(line);
      if (!macMatch || !ipMatch) continue;
      if (/incomplete|failed/i.test(line)) continue;

      const mac = macMatch[1]!.toLowerCase();
      const ipv6 = ipMatch[1]!;
      const ipv4 = macIp.get(mac);
      if (!ipv4) continue;

      emit({
        ip: ipv4,
        mac,
        source: this.name,
        extra: { ipv6, ipv6Neighbor: true },
      });
    }
  }
}
