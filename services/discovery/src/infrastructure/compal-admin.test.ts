import { describe, expect, it } from 'vitest';
import { isCompalRebootConfirmed } from './compal-admin.js';

describe('isCompalRebootConfirmed', () => {
  it('accepts low uptime after reboot', () => {
    expect(isCompalRebootConfirmed(300_000, 45)).toBe(true);
  });

  it('accepts significant uptime drop', () => {
    expect(isCompalRebootConfirmed(300_000, 299_000)).toBe(true);
  });

  it('rejects unchanged uptime', () => {
    expect(isCompalRebootConfirmed(300_000, 299_950)).toBe(false);
    expect(isCompalRebootConfirmed(300_000, 300_100)).toBe(false);
  });
});
