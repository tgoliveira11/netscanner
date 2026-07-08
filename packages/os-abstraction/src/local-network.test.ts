import { describe, expect, it } from 'vitest';
import { isIgnoredScanCidr, isSniffableInterfaceName } from './local-network.js';

describe('isIgnoredScanCidr', () => {
  it('skips ISP handoff, Mac Sharing, and VPN overlays', () => {
    expect(isIgnoredScanCidr('192.168.0.0/24')).toBe(true);
    expect(isIgnoredScanCidr('192.168.64.0/24')).toBe(true);
    expect(isIgnoredScanCidr('10.8.0.0/24')).toBe(true);
    expect(isIgnoredScanCidr('10.14.1.0/24')).toBe(true);
  });

  it('allows normal LAN / extra VLAN CIDRs', () => {
    expect(isIgnoredScanCidr('192.168.1.0/24')).toBe(false);
    expect(isIgnoredScanCidr('10.0.51.0/24')).toBe(false);
    expect(isIgnoredScanCidr('10.0.0.0/24')).toBe(false);
  });
});

describe('isSniffableInterfaceName', () => {
  it('skips loopback, VM, docker, veth, and tunnel ifaces', () => {
    expect(isSniffableInterfaceName('lo')).toBe(false);
    expect(isSniffableInterfaceName('lo0')).toBe(false);
    expect(isSniffableInterfaceName('vmnet8')).toBe(false);
    expect(isSniffableInterfaceName('docker0')).toBe(false);
    expect(isSniffableInterfaceName('veth0a1b')).toBe(false);
    expect(isSniffableInterfaceName('utun3')).toBe(false);
  });

  it('keeps physical, wifi, and bridge ifaces (incl. Internet Sharing)', () => {
    expect(isSniffableInterfaceName('en0')).toBe(true);
    expect(isSniffableInterfaceName('eth0')).toBe(true);
    expect(isSniffableInterfaceName('wlan0')).toBe(true);
    expect(isSniffableInterfaceName('bridge100')).toBe(true);
  });
});
