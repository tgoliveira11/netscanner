import type { Logger } from '@netscanner/logger';
import type { IRouterLeaseSource, RouterLease } from '../domain/router-lease-source.js';
import { HttpRouterScrapeAdapter, type HttpRouterScrapeConfig } from './http-router-scrape.adapter.js';

/** Resolves scrape targets dynamically (config + per-device credentials) on each call. */
export class DynamicRouterScrapeLeaseSource implements IRouterLeaseSource {
  readonly name = 'router-scrape';

  constructor(
    private readonly loadTargets: () => Promise<HttpRouterScrapeConfig[]>,
    private readonly logger: Logger,
  ) {}

  async getLeases(): Promise<RouterLease[]> {
    const targets = await this.loadTargets();
    const byKey = new Map<string, RouterLease>();
    for (const target of targets) {
      const adapter = new HttpRouterScrapeAdapter(
        {
          baseUrl: target.baseUrl,
          kind: target.kind,
          username: target.username,
          password: target.password,
          insecureTls: true,
        },
        this.logger,
      );
      try {
        for (const lease of await adapter.getLeases()) {
          const key = (lease.mac ?? lease.ip).toLowerCase();
          if (key) byKey.set(key, lease);
        }
      } catch (error) {
        this.logger.warn(
          { url: target.baseUrl, error: error instanceof Error ? error.message : error },
          'router lease source failed (continuing)',
        );
      }
    }
    return [...byKey.values()];
  }
}
