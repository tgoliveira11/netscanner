import type { Cidr } from '@netscanner/kernel';
import type { DiscoveredHost } from '@netscanner/contracts';
import type { Logger } from '@netscanner/logger';
import type { IHostProbe, ProbeContext } from '../domain/host-probe.js';
import { HostAggregator } from '../domain/host-aggregator.js';

export interface DiscoverHostsInput {
  cidr: Cidr;
  concurrency: number;
  timeoutMs: number;
  signal?: AbortSignal;
  /** Streamed as hosts are found/enriched, powering live UI updates. */
  onHost?: (host: DiscoveredHost) => void;
}

/**
 * Orchestrates the registered probes to discover live hosts on a subnet.
 * Runs 'sweep' probes first (active liveness that populates the ARP cache),
 * then 'enrich' probes concurrently. Depends only on the IHostProbe port (DIP),
 * so probes can be added/removed without touching this use case (OCP).
 */
export class DiscoverHostsUseCase {
  constructor(
    private readonly probes: readonly IHostProbe[],
    private readonly logger: Logger,
  ) {}

  async execute(input: DiscoverHostsInput): Promise<DiscoveredHost[]> {
    const aggregator = new HostAggregator();
    const controller = new AbortController();
    if (input.signal) {
      input.signal.addEventListener('abort', () => controller.abort(), { once: true });
    }

    const ctx: ProbeContext = {
      cidr: input.cidr,
      concurrency: input.concurrency,
      timeoutMs: input.timeoutMs,
      signal: controller.signal,
    };

    const emit = (raw: Parameters<HostAggregator['ingest']>[0]) => {
      const changed = aggregator.ingest(raw);
      if (changed) input.onHost?.(changed);
    };

    const run = async (phase: 'sweep' | 'enrich') => {
      const active = this.probes.filter((p) => p.phase === phase);
      await Promise.allSettled(
        active.map(async (probe) => {
          try {
            await probe.run(ctx, emit);
          } catch (error) {
            this.logger.warn({ probe: probe.name, error }, 'probe failed');
          }
        }),
      );
    };

    await run('sweep');
    await run('enrich');

    const hosts = aggregator.all();
    this.logger.info({ cidr: ctx.cidr.toString(), count: hosts.length }, 'discovery complete');
    return hosts;
  }
}
