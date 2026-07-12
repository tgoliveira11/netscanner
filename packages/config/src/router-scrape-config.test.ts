import { describe, expect, it } from 'vitest';
import {
  parseRouterScrapeTargetsLine,
  mergeRouterScrapeTargets,
  resolveRouterScrapeTargets,
  extractFloatingCompalCredentials,
  credentialMatchesDevice,
  macTailHex,
} from './router-scrape-config.js';

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

  it('parses identity Compal credentials without IP', () => {
    const rows = parseRouterScrapeTargetsLine('compal|CLARO_21A469|secret');
    expect(rows).toEqual([
      { baseUrl: '', kind: 'compal', username: 'CLARO_21A469', password: 'secret' },
    ]);
  });
});

describe('normalizeRouterScrapeTargetsInput', () => {
  it('joins multiline admin input with semicolons', async () => {
    const { normalizeRouterScrapeTargetsInput, formatRouterScrapeTargetsForAdmin } = await import(
      './router-scrape-config.js'
    );
    const stored = normalizeRouterScrapeTargetsInput(
      'http://192.168.40.2|openwrt|root|pass1\ncompal|CLARO_21A469|pass2\n',
    );
    expect(stored).toBe('http://192.168.40.2|openwrt|root|pass1;compal|CLARO_21A469|pass2');
    expect(formatRouterScrapeTargetsForAdmin(stored)).toBe(
      'http://192.168.40.2|openwrt|root|pass1\ncompal|CLARO_21A469|pass2',
    );
  });
});

describe('credentialMatchesDevice', () => {
  it('matches CLARO_ user to MAC tail', () => {
    expect(
      credentialMatchesDevice('CLARO_21A469', {
        ip: '192.168.51.200',
        mac: 'b4:f2:67:21:a4:69',
        deviceType: 'router',
        hostname: 'CBN_RE_21A469',
      }),
    ).toBe(true);
    expect(macTailHex('b4:f2:67:21:a4:69')).toBe('21A469');
  });
});

describe('mergeRouterScrapeTargets', () => {
  it('binds Compal env credentials to the discovered IP (not the stale env URL)', () => {
    const rows = mergeRouterScrapeTargets(
      {
        ROUTER_SCRAPE_TARGETS:
          'http://192.168.52.101|compal|CLARO_21A44B|guestpass;http://192.168.40.2|openwrt|root|sw',
      } as never,
      [
        {
          ip: '192.168.52.100',
          mac: 'b4:f2:67:21:a4:4b',
          deviceType: 'router',
          brand: 'Compal Broadband Networks',
          hostname: 'CBN_RE_21A44B',
          isOnline: true,
        },
      ],
    );
    expect(rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          baseUrl: 'http://192.168.40.2',
          kind: 'openwrt',
          username: 'root',
        }),
        expect.objectContaining({
          baseUrl: 'http://192.168.52.100',
          kind: 'compal',
          username: 'CLARO_21A44B',
          password: 'guestpass',
        }),
      ]),
    );
    expect(rows.some((r) => r.baseUrl.includes('192.168.52.101'))).toBe(false);
  });

  it('uses identity-form Compal credentials', () => {
    const rows = mergeRouterScrapeTargets(
      { ROUTER_SCRAPE_TARGETS: 'compal|CLARO_21A469|p' } as never,
      [
        {
          ip: '192.168.51.101',
          mac: 'b4:f2:67:21:a4:69',
          deviceType: 'access-point',
          hostname: 'CBN_RE_21A469',
          brand: 'Compal Broadband Networks',
        },
      ],
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      baseUrl: 'http://192.168.51.101',
      kind: 'compal',
      username: 'CLARO_21A469',
    });
  });

  it('prefers per-device credentials when present', () => {
    const rows = mergeRouterScrapeTargets(
      { ROUTER_SCRAPE_TARGETS: 'compal|CLARO_21A469|envpass' } as never,
      [
        {
          ip: '192.168.51.101',
          mac: 'b4:f2:67:21:a4:69',
          deviceType: 'router',
          hostname: 'CBN_RE_21A469',
          brand: 'Compal Broadband Networks',
          routerScrapeUser: 'CLARO_21A469',
          routerScrapePassword: 'devicepass',
        },
      ],
    );
    expect(rows[0]?.password).toBe('devicepass');
  });
});

describe('resolveRouterScrapeTargets', () => {
  it('keeps OpenWrt URLs and ignores Compal fixed URLs', () => {
    const rows = resolveRouterScrapeTargets({
      ROUTER_SCRAPE_TARGETS:
        'http://192.168.10.3|openwrt|root|x;http://192.168.51.101|compal|CLARO_21A469|y',
      ROUTER_SCRAPE_URL: 'http://192.168.1.2',
      ROUTER_SCRAPE_KIND: 'openwrt',
      ROUTER_SCRAPE_USER: 'root',
      ROUTER_SCRAPE_PASSWORD: 'y',
    } as never);
    expect(rows.map((r) => r.baseUrl).sort()).toEqual(['http://192.168.1.2', 'http://192.168.10.3']);
    expect(extractFloatingCompalCredentials({
      ROUTER_SCRAPE_TARGETS: 'http://192.168.51.101|compal|CLARO_21A469|y',
    } as never)).toEqual([{ username: 'CLARO_21A469', password: 'y' }]);
  });
});
