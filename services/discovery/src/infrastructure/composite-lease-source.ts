import type { Logger } from '@netscanner/logger';
import type { IRouterLeaseSource, RouterLease } from '../domain/router-lease-source.js';

function mergeLease(existing: RouterLease, lease: RouterLease): RouterLease {
  return {
    ip: lease.ip || existing.ip,
    mac: lease.mac ?? existing.mac,
    hostname: lease.hostname ?? existing.hostname,
    interface: lease.interface ?? existing.interface,
    description: lease.description ?? existing.description,
    online: lease.online || existing.online,
  };
}

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    promise.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      },
    );
  });
}

/**
 * Merges multiple router lease sources in parallel.
 * Each source is bounded so a hung Compal/SNMP scrape cannot block discovery.
 */
export class CompositeLeaseSource implements IRouterLeaseSource {
  readonly name = 'composite';

  constructor(
    private readonly sources: IRouterLeaseSource[],
    private readonly logger: Logger,
    private readonly perSourceTimeoutMs = 8_000,
  ) {}

  async getLeases(): Promise<RouterLease[]> {
    const byKey = new Map<string, RouterLease>();
    const results = await Promise.allSettled(
      this.sources.map((source) =>
        withTimeout(source.getLeases(), this.perSourceTimeoutMs, source.name),
      ),
    );

    for (let i = 0; i < results.length; i++) {
      const source = this.sources[i]!;
      const result = results[i]!;
      if (result.status === 'rejected') {
        this.logger.warn(
          {
            source: source.name,
            error: result.reason instanceof Error ? result.reason.message : result.reason,
          },
          'router lease source failed (continuing)',
        );
        continue;
      }
      for (const lease of result.value) {
        const key = (lease.mac ?? lease.ip).toLowerCase();
        if (!key) continue;
        const existing = byKey.get(key);
        byKey.set(key, existing ? mergeLease(existing, lease) : lease);
      }
    }
    return [...byKey.values()];
  }

  listSources(): readonly IRouterLeaseSource[] {
    return this.sources;
  }
}
