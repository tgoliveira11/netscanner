import { describe, it, expect } from 'vitest';
import { extractOsVersion, resolveHardwareName } from './fingerbank-client.js';

describe('resolveHardwareName', () => {
  it('uses specific path leaf when API name is generic Apple iPhone', () => {
    expect(
      resolveHardwareName('Apple iPhone', 'Hardware/Apple/iPhone/iPhone 15 Pro'),
    ).toBe('iPhone 15 Pro');
  });

  it('keeps specific API name', () => {
    expect(
      resolveHardwareName('iPhone 15 Pro', 'Hardware/Apple/iPhone/iPhone 15 Pro'),
    ).toBe('iPhone 15 Pro');
  });
});

describe('extractOsVersion', () => {
  it('prefers top-level version', () => {
    expect(extractOsVersion({ version: '18.2' })).toBe('18.2');
  });

  it('parses version from operating_system name', () => {
    expect(
      extractOsVersion({
        operating_system: { name: 'iOS 18.1', parents: [] },
      }),
    ).toBe('18.1');
  });
});
