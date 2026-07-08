import { describe, expect, it, beforeEach } from 'vitest';
import { loadConfig, resetConfigCache } from './config-loader.js';

describe('loadConfig DISABLE_NMAP regression', () => {
  beforeEach(() => resetConfigCache());

  it('keeps nmap enabled when config.env writes DISABLE_NMAP=false', () => {
    const config = loadConfig({ DISABLE_NMAP: 'false' });
    expect(config.DISABLE_NMAP).toBe(false);
  });

  it('disables nmap only when DISABLE_NMAP=true', () => {
    const config = loadConfig({ DISABLE_NMAP: 'true' });
    expect(config.DISABLE_NMAP).toBe(true);
  });
});
