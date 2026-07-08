import { describe, expect, it, vi } from 'vitest';
import { detectCapabilities, resolveNmapCapability } from './capabilities.js';
import type { ICommandRunner } from './command-runner.js';

describe('resolveNmapCapability', () => {
  it('reports disabled-by-config when DISABLE_NMAP is true', () => {
    expect(resolveNmapCapability(true, true)).toEqual({
      nmap: false,
      nmapOffReason: 'disabled-by-config',
    });
  });

  it('reports not-in-path when nmap is missing', () => {
    expect(resolveNmapCapability(false, false)).toEqual({
      nmap: false,
      nmapOffReason: 'not-in-path',
    });
  });

  it('enables nmap when config allows and binary exists', () => {
    expect(resolveNmapCapability(false, true)).toEqual({ nmap: true });
  });
});

describe('detectCapabilities', () => {
  const runner = {
    which: vi.fn(),
  } as unknown as ICommandRunner;

  it('skips which lookup when DISABLE_NMAP is true', async () => {
    vi.mocked(runner.which).mockResolvedValue(true);
    const caps = await detectCapabilities(runner, true);
    expect(caps.nmap).toBe(false);
    expect(caps.nmapOffReason).toBe('disabled-by-config');
    expect(runner.which).not.toHaveBeenCalled();
  });

  it('detects missing nmap binary when not disabled', async () => {
    vi.mocked(runner.which).mockResolvedValue(false);
    const caps = await detectCapabilities(runner, false);
    expect(caps.nmap).toBe(false);
    expect(caps.nmapOffReason).toBe('not-in-path');
    expect(runner.which).toHaveBeenCalledWith('nmap');
  });

  it('enables nmap when binary is present and not disabled', async () => {
    vi.mocked(runner.which).mockResolvedValue(true);
    const caps = await detectCapabilities(runner, false);
    expect(caps.nmap).toBe(true);
    expect(caps.nmapOffReason).toBeUndefined();
  });
});
