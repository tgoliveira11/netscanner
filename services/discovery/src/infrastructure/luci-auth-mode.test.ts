import { describe, expect, it } from 'vitest';
import { resolveLuciAuthMode } from './luci-auth-mode.js';

describe('resolveLuciAuthMode', () => {
  it('uses compal-rsa only for compal kind', () => {
    expect(resolveLuciAuthMode({ kind: 'compal', username: 'root' })).toBe('compal-rsa');
  });

  it('uses plain auth for openwrt even with CLARO_ username', () => {
    expect(resolveLuciAuthMode({ kind: 'openwrt', username: 'CLARO_112233' })).toBe('plain');
  });

  it('uses plain auth for standard openwrt', () => {
    expect(resolveLuciAuthMode({ kind: 'openwrt', username: 'root' })).toBe('plain');
  });
});
