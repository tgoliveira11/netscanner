import { describe, expect, it } from 'vitest';
import { resolveLuciAuthMode } from './luci-auth-mode.js';

describe('resolveLuciAuthMode', () => {
  it('uses compal-rsa for compal kind', () => {
    expect(resolveLuciAuthMode({ kind: 'compal', username: 'root' })).toBe('compal-rsa');
  });

  it('uses compal-rsa for CLARO_ usernames on openwrt kind', () => {
    expect(resolveLuciAuthMode({ kind: 'openwrt', username: 'CLARO_112233' })).toBe('compal-rsa');
  });

  it('uses plain auth for standard openwrt', () => {
    expect(resolveLuciAuthMode({ kind: 'openwrt', username: 'root' })).toBe('plain');
  });
});
