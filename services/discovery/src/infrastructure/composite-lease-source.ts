import type { Logger } from '@netscanner/logger';
import type { IRouterLeaseSource, RouterLease } from '../domain/router-lease-source.js';

/** Merges multiple router lease sources; first hostname wins per MAC/IP. */
export class CompositeLeaseSource implements IRouterLeaseSource {
  readonly name = 'composite';

  constructor(
    private readonly sources: IRouterLeaseSource[],
    private readonly logger: Logger,
  ) {}

  async getLeases(): Promise<RouterLease[]> {
    const byKey = new Map<string, RouterLease>();
    for (const source of this.sources) {
      try {
        const rows = await source.getLeases();
        for (const lease of rows) {
          const key = (lease.mac ?? lease.ip).toLowerCase();
          if (!key) continue;
          const existing = byKey.get(key);
          if (!existing) {
            byKey.set(key, lease);
            continue;
          }
          byKey.set(key, {
            ip: lease.ip || existing.ip,
            mac: lease.mac ?? existing.mac,
            hostname: lease.hostname ?? existing.hostname,
            interface: lease.interface ?? existing.interface,
            description: lease.description ?? existing.description,
            online: lease.online || existing.online,
          });
        }
      } catch (error) {
        this.logger.warn(
          { source: source.name, error: error instanceof Error ? error.message : error },
          'router lease source failed (continuing)',
        );
      }
    }
    return [...byKey.values()];
  }
}
