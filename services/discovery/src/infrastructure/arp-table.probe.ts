import { currentPlatform, type ICommandRunner } from '@netscanner/os-abstraction';
import { Cidr, IpAddress, MacAddress, isOk } from '@netscanner/kernel';
import type { IHostProbe, ProbeContext, RawHostSignal } from '../domain/host-probe.js';

const IP_RE = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
const MAC_RE = /([0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}/i;

/**
 * Reads the OS ARP cache to resolve IP→MAC (and sometimes hostname) for hosts
 * that responded at layer 2. Parses the differing macOS/Linux/Windows formats
 * behind a single adapter (cross-platform via the command runner).
 */
export class ArpTableProbe implements IHostProbe {
  readonly name = 'arp';
  readonly phase = 'enrich' as const;

  constructor(private readonly runner: ICommandRunner) {}

  private args(): string[] {
    return currentPlatform() === 'win32' ? ['-a'] : ['-a', '-n'];
  }

  private normalizeMac(raw: string): string | null {
    // Windows uses dashes and may drop leading zeros; pad each octet.
    const parts = raw.split(/[:-]/).map((p) => p.padStart(2, '0'));
    if (parts.length !== 6) return null;
    const candidate = MacAddress.create(parts.join(':'));
    if (!isOk(candidate)) return null;
    const mac = candidate.value.value;
    // Exclude broadcast, multicast, and null MACs — these are not real devices.
    if (
      mac === 'ff:ff:ff:ff:ff:ff' ||
      mac === '00:00:00:00:00:00' ||
      mac.startsWith('01:00:5e') || // IPv4 multicast
      mac.startsWith('33:33') // IPv6 multicast
    ) {
      return null;
    }
    return mac;
  }

  async run(ctx: ProbeContext, emit: (signal: RawHostSignal) => void): Promise<void> {
    const res = await this.runner.run('arp', this.args(), { timeoutMs: 5000 });
    if (res.code !== 0 && !res.stdout) return;

    for (const line of res.stdout.split('\n')) {
      const ipMatch = IP_RE.exec(line);
      const macMatch = MAC_RE.exec(line);
      if (!ipMatch || !macMatch) continue;
      if (/incomplete|no entry/i.test(line)) continue;

      const ip = IpAddress.create(ipMatch[1]!);
      if (!isOk(ip) || !ctx.cidr.contains(ip.value)) continue;
      const mac = this.normalizeMac(macMatch[0]);
      if (!mac) continue;

      // Leading token before "(" on BSD/Linux verbose output can be a hostname.
      const hostToken = line.trim().split(/\s+/)[0];
      const hostname =
        hostToken && hostToken !== '?' && !IP_RE.test(hostToken) ? hostToken : undefined;

      emit({ ip: ip.value.value, mac, hostname, source: this.name });
    }
  }

  /** Guard used by tests/DI so a bad CIDR never reaches this probe. */
  static supports(cidr: unknown): cidr is Cidr {
    return cidr instanceof Cidr;
  }
}
