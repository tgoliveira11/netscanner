import { describe, expect, it } from 'vitest';
import { EnvSchema } from './env-schema.js';
import { parseEnvBool } from './env-bool.js';

describe('parseEnvBool', () => {
  it('parses common false strings from config.env', () => {
    for (const v of ['false', 'False', '0', 'no', 'off']) {
      expect(parseEnvBool(v)).toBe(false);
    }
  });

  it('parses common true strings from config.env', () => {
    for (const v of ['true', 'True', '1', 'yes', 'on']) {
      expect(parseEnvBool(v)).toBe(true);
    }
  });
});

describe('EnvSchema DISABLE_NMAP', () => {
  it('defaults to false so nmap is enabled when installed', () => {
    const parsed = EnvSchema.parse({});
    expect(parsed.DISABLE_NMAP).toBe(false);
  });

  it('coerces string "true" from config.env', () => {
    const parsed = EnvSchema.parse({ DISABLE_NMAP: 'true' });
    expect(parsed.DISABLE_NMAP).toBe(true);
  });

  it('coerces string "false" from config.env', () => {
    const parsed = EnvSchema.parse({ DISABLE_NMAP: 'false' });
    expect(parsed.DISABLE_NMAP).toBe(false);
  });
});
