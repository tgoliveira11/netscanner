import { describe, it, expect, vi } from 'vitest';
import type { ICommandRunner } from '@netscanner/os-abstraction';
import { NmapScanner } from './nmap.scanner.js';

const minimalXml = `<?xml version="1.0"?><nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports/></host></nmaprun>`;

function runner(): ICommandRunner & { lastArgs: string[] } {
  const state = { lastArgs: [] as string[] };
  return {
    get lastArgs() {
      return state.lastArgs;
    },
    which: vi.fn(async () => true),
    run: vi.fn(async (_cmd, args) => {
      state.lastArgs = args;
      return { stdout: minimalXml, stderr: '', code: 0, timedOut: false };
    }),
  };
}

describe('NmapScanner', () => {
  it('uses SYN scan and UDP top ports on elevated deep scans', async () => {
    const r = runner();
    const scanner = new NmapScanner(r, { elevated: true });
    await scanner.scan({ ip: '10.0.0.1', depth: 'deep', osDetection: true, timeoutMs: 120_000 });
    expect(r.lastArgs).toContain('-sS');
    expect(r.lastArgs).toContain('-sU');
    expect(r.lastArgs).toContain('-p-');
    expect(r.lastArgs).toContain('--top-ports');
    expect(r.lastArgs).toContain('100');
  });

  it('does not request SYN or UDP when not elevated', async () => {
    const r = runner();
    const scanner = new NmapScanner(r, { elevated: false });
    await scanner.scan({ ip: '10.0.0.1', depth: 'deep', osDetection: false, timeoutMs: 60_000 });
    expect(r.lastArgs).not.toContain('-sS');
    expect(r.lastArgs).not.toContain('-sU');
    expect(r.lastArgs).toContain('-p-');
  });
});
