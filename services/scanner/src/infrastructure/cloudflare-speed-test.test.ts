import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { CloudflareSpeedTester } from './cloudflare-speed-test.js';
import { createLogger } from '@netscanner/logger';

describe('CloudflareSpeedTester', () => {
  const logger = createLogger('speed-test-test');

  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: RequestInit) => {
        if (url.includes('__down?bytes=0')) {
          return new Response(new ArrayBuffer(0), { status: 200 });
        }
        if (url.includes('__down?bytes=1000')) {
          await new Promise((r) => setTimeout(r, 10));
          return new Response(new ArrayBuffer(1000), { status: 200 });
        }
        if (url.includes('__up') && init?.method === 'POST') {
          await new Promise((r) => setTimeout(r, 10));
          return new Response(new ArrayBuffer(0), { status: 200 });
        }
        return new Response(null, { status: 404 });
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('measures download and upload Mbps', async () => {
    const tester = new CloudflareSpeedTester(logger);
    const result = await tester.run({
      baseUrl: 'https://speed.cloudflare.com',
      downloadBytes: 1000,
      uploadBytes: 1000,
    });
    expect(result.latencyMs).toBeGreaterThan(0);
    expect(result.downloadMbps).toBeGreaterThan(0);
    expect(result.uploadMbps).toBeGreaterThan(0);
    expect(result.error).toBeNull();
  });
});
