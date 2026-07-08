import { z } from 'zod';

/** Parse env-style booleans; z.coerce.boolean treats "false" as true (Boolean("false")). */
export function parseEnvBool(value: unknown, fallback?: boolean): boolean | undefined {
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  const s = String(value).trim().toLowerCase();
  if (s === 'true' || s === '1' || s === 'yes' || s === 'on') return true;
  if (s === 'false' || s === '0' || s === 'no' || s === 'off') return false;
  return Boolean(value);
}

export function envBool(defaultValue: boolean) {
  return z.preprocess((val) => parseEnvBool(val, defaultValue) ?? defaultValue, z.boolean()).default(defaultValue);
}
