import { describe, it, expect } from 'vitest';
import { resolvePfSenseSshHost } from './pf-ssh-traffic-source.js';

describe('resolvePfSenseSshHost', () => {
  it('extracts hostname from PFSENSE_URL', () => {
    expect(resolvePfSenseSshHost('https://192.168.51.1')).toBe('192.168.51.1');
    expect(resolvePfSenseSshHost('192.168.51.1')).toBe('192.168.51.1');
  });

  it('prefers explicit override', () => {
    expect(resolvePfSenseSshHost('https://10.0.0.1', '192.168.51.1')).toBe('192.168.51.1');
  });

  it('returns null when unset', () => {
    expect(resolvePfSenseSshHost(undefined)).toBeNull();
  });
});
