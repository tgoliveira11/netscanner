import { describe, expect, it } from 'vitest';
import { resolveDeviceVlan } from './device-vlan.js';

describe('resolveDeviceVlan', () => {
  it('prefers pfSense interface name', () => {
    expect(
      resolveDeviceVlan({
        ip: '10.0.3.10',
        signals: { pfsenseInterface: 'LAN_IOT' },
      }),
    ).toEqual({ id: 'LAN_IOT', label: 'LAN_IOT' });
  });

  it('falls back to /24 subnet from IP', () => {
    expect(resolveDeviceVlan({ ip: '10.0.2.101', signals: {} })).toEqual({
      id: '10.0.2.0/24',
      label: '10.0.2.0/24',
    });
  });
});
