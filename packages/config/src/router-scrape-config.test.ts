import { describe, expect, it } from 'vitest';
import { parseRouterScrapeTargetsLine, resolveRouterScrapeTargets } from './router-scrape-config.js';

describe('parseRouterScrapeTargetsLine', () => {
  it('parses semicolon-separated targets', () => {
    const rows = parseRouterScrapeTargetsLine(
      'http://192.168.1.2|openwrt|root|pass1;http://192.168.10.3|openwrt|root|pass|with|pipes',
    );
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({
      baseUrl: 'http://192.168.1.2',
      kind: 'openwrt',
      username: 'root',
      password: 'pass1',
    });
    expect(rows[1]?.password).toBe('pass|with|pipes');
  });
});

describe('resolveRouterScrapeTargets', () => {
  it('merges legacy single config with multi targets', () => {
    const rows = resolveRouterScrapeTargets({
      ROUTER_SCRAPE_TARGETS: 'http://192.168.10.3|openwrt|root|x',
      ROUTER_SCRAPE_URL: 'http://192.168.1.2',
      ROUTER_SCRAPE_KIND: 'openwrt',
      ROUTER_SCRAPE_USER: 'root',
      ROUTER_SCRAPE_PASSWORD: 'y',
    } as never);
    expect(rows).toHaveLength(2);
    expect(rows.map((r) => r.baseUrl).sort()).toEqual(['http://192.168.1.2', 'http://192.168.10.3']);
  });
});
