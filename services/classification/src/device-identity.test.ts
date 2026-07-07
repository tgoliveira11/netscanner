import { describe, it, expect } from 'vitest';
import { normalizeBrandName, resolveBrandModel, resolveOs } from './domain/device-identity.js';

describe('resolveBrandModel', () => {
  it('prefers Fingerbank path + device name', () => {
    const id = resolveBrandModel('Randomized/Private MAC', {
      fingerbankDevice: 'iPhone 15 Pro',
      fingerbankPath: 'Hardware/Apple/iPhone/iPhone 15 Pro',
    });
    expect(id.brand).toBe('Apple');
    expect(id.model).toBe('iPhone 15 Pro');
  });

  it('falls back to UPnP then OUI vendor', () => {
    expect(
      resolveBrandModel('Apple, Inc.', {
        upnpManufacturer: 'Apple Inc.',
        upnpModel: 'Apple TV',
      }),
    ).toEqual({ brand: 'Apple', model: 'Apple TV' });
    expect(resolveBrandModel('Espressif Inc.', {})).toEqual({ brand: 'Espressif', model: null });
  });
});

describe('resolveOs', () => {
  it('infers tvOS for Apple TV hostname', () => {
    const { os } = resolveOs(null, {
      services: [],
      signals: {},
      vendor: 'Apple, Inc.',
      hostname: 'hometheater.home.arpa',
    });
    expect(os?.family).toBe('tvOS');
  });

  it('merges Fingerbank version into macOS hostname guess', () => {
    const { os } = resolveOs(null, {
      services: [],
      signals: {
        fingerbankDevice: 'MacBook Air',
        fingerbankPath: 'Hardware/Apple/MacBook/MacBook Air',
        fingerbankVersion: '14.5',
        fingerbankScore: 80,
      },
      vendor: 'Randomized/Private MAC',
      hostname: 'SAMPLE-MBP-Thiago',
    });
    expect(os?.family).toBe('macOS');
    expect(os?.version).toBe('14.5');
  });

  it('parses Android version from DHCP vendor class', () => {
    const { os } = resolveOs(null, {
      services: [],
      signals: { dhcpVendorClass: 'android-dhcp-14' },
      vendor: 'Randomized/Private MAC',
      hostname: null,
    });
    expect(os).toMatchObject({ family: 'Android', version: '14' });
  });
});

describe('normalizeBrandName', () => {
  it('strips corporate suffixes', () => {
    expect(normalizeBrandName('Apple, Inc.')).toBe('Apple');
    expect(normalizeBrandName('S-Bluetech co., limited')).toBe('S-Bluetech');
  });
});
