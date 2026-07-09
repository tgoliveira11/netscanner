import { describe, expect, it } from 'vitest';
import { parseRouterScrapeTargetsLine, mergeRouterScrapeTargets, resolveRouterScrapeTargets } from './router-scrape-config.js';

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

describe('normalizeRouterScrapeTargetsInput', () => {
  it('joins multiline admin input with semicolons', async () => {
    const { normalizeRouterScrapeTargetsInput, formatRouterScrapeTargetsForAdmin } = await import(
      './router-scrape-config.js'
    );
    const stored = normalizeRouterScrapeTargetsInput(
      'http://192.168.40.2|openwrt|root|pass1\nhttp://192.168.51.101|compal|CLARO_21A469|pass2\n',
    );
    expect(stored).toBe(
      'http://192.168.40.2|openwrt|root|pass1;http://192.168.51.101|compal|CLARO_21A469|pass2',
    );
    expect(formatRouterScrapeTargetsForAdmin(stored)).toBe(
      'http://192.168.40.2|openwrt|root|pass1\nhttp://192.168.51.101|compal|CLARO_21A469|pass2',
    );
  });
});

describe('mergeRouterScrapeTargets', () => {
  it('keeps compal kind from env when per-device credentials override user/password', () => {
    const rows = mergeRouterScrapeTargets(
      {
        ROUTER_SCRAPE_TARGETS: 'http://192.168.51.101|compal|CLARO_21A469|envpass',
      } as never,
      [
        {
          ip: '192.168.51.101',
          deviceType: 'router',
          brand: 'OpenWRT',
          routerScrapeUser: 'CLARO_21A469',
          routerScrapePassword: 'devicepass',
        },
      ],
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      baseUrl: 'http://192.168.51.101',
      kind: 'compal',
      username: 'CLARO_21A469',
      password: 'devicepass',
    });
  });

  it('infers compal for CBN hostname when no env target exists', () => {
    const rows = mergeRouterScrapeTargets({} as never, [
      {
        ip: '192.168.52.101',
        deviceType: 'router',
        hostname: 'CBN_RE_21A44B',
        brand: null,
        routerScrapeUser: 'CLARO_21A44B',
        routerScrapePassword: 'x',
      },
    ]);
    expect(rows[0]?.kind).toBe('compal');
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
