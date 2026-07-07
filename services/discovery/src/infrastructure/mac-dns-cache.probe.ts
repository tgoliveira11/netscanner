import { lookupMacDnsCache } from '@netscanner/os-abstraction';
import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { IHostProbe, ProbeContext, RawHostSignal } from '../domain/host-probe.js';

/** macOS mDNSResponder cache via dscacheutil — complements tcpdump DNS passive. */
export class MacDnsCacheProbe implements IHostProbe {
  readonly name = 'mac-dns-cache';
  readonly phase = 'enrich' as const;

  constructor(private readonly runner: ICommandRunner) {}

  async run(ctx: ProbeContext, emit: (signal: RawHostSignal) => void): Promise<void> {
    const ips = [...ctx.cidr.hosts(128)].map((h) => h.value).slice(0, 128);
    await Promise.allSettled(
      ips.map(async (ip) => {
        if (ctx.signal.aborted) return;
        const name = await lookupMacDnsCache(this.runner, ip);
        if (name) emit({ ip, hostname: name, source: 'mac-dns-cache', extra: { resolverCacheName: name } });
      }),
    );
  }
}
