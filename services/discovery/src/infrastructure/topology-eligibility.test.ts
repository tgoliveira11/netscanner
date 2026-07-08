import { describe, expect, it } from 'vitest';
import type { Device } from '@netscanner/contracts';
import {
  hasRandomizedMac,
  isLocalScannerDevice,
  isWiredUplinkRouter,
} from './topology-eligibility.js';

const bridgeDevice = {
  id: 'local-bridge',
  ip: '192.168.64.1',
  mac: '62:3e:5f:00:00:01',
  deviceType: 'router' as const,
  connectionType: 'wifi' as const,
  signals: { connectionBasis: 'randomized/private MAC (a WiFi-only feature)' },
  // Partial fixture: the functions under test only read id/ip/mac/deviceType/
  // connectionType/signals. Cast through unknown rather than stub every field.
} as unknown as Device;

const ctx = {
  localIfaces: [
    {
      name: 'bridge100',
      address: '192.168.64.1',
      netmask: '255.255.255.0',
      mac: '62:3e:5f:00:00:01',
      cidr: '192.168.64.0/24',
    },
  ],
  managedRouterIps: new Set(['10.0.2.101']),
  gatewayId: 'gw',
};

describe('isLocalScannerDevice', () => {
  it('detects the agent host bridge interface', () => {
    expect(isLocalScannerDevice(bridgeDevice, ctx.localIfaces)).toBe(true);
  });
});

describe('isWiredUplinkRouter', () => {
  it('excludes local bridge and wifi-only pseudo-routers', () => {
    expect(isWiredUplinkRouter(bridgeDevice, ctx, null)).toBe(false);
  });

  it('includes configured scrape targets', () => {
    expect(
      isWiredUplinkRouter(
        {
          ...bridgeDevice,
          id: 'ap1',
          ip: '10.0.2.101',
          mac: '00:11:22:33:44:55',
          connectionType: 'wired',
        },
        ctx,
        null,
      ),
    ).toBe(true);
  });

  it('excludes unknown routers on non-managed subnets', () => {
    expect(
      isWiredUplinkRouter(
        {
          ...bridgeDevice,
          id: 'r2',
          ip: '10.0.99.1',
          mac: '00:11:22:33:44:55',
          connectionType: 'unknown',
          signals: {},
        },
        ctx,
        null,
      ),
    ).toBe(false);
  });
});

describe('hasRandomizedMac', () => {
  it('flags locally administered MACs', () => {
    expect(hasRandomizedMac('62:3e:5f:00:00:01')).toBe(true);
    expect(hasRandomizedMac('00:11:22:33:44:55')).toBe(false);
  });
});
