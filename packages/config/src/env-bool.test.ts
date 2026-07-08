import { describe, expect, it } from 'vitest';
import { envBool, parseEnvBool } from './env-bool.js';

describe('parseEnvBool', () => {
  it('returns fallback for empty values', () => {
    expect(parseEnvBool(undefined, false)).toBe(false);
    expect(parseEnvBool('', true)).toBe(true);
  });

  it('does not treat the string "false" as true (Zod coerce.boolean bug)', () => {
    expect(parseEnvBool('false')).toBe(false);
    expect(parseEnvBool('FALSE')).toBe(false);
  });
});

describe('envBool schema', () => {
  const schema = envBool(false);

  it('accepts string false from config.env files', () => {
    expect(schema.parse('false')).toBe(false);
  });

  it('accepts string true from config.env files', () => {
    expect(schema.parse('true')).toBe(true);
  });
});
