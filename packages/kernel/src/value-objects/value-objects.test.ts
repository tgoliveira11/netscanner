import { describe, it, expect } from 'vitest';
import { MacAddress } from './mac-address.js';
import { IpAddress } from './ip-address.js';
import { Cidr } from './cidr.js';

describe('MacAddress', () => {
  it('normalizes separators and case', () => {
    const mac = MacAddress.create('AA-BB-CC-DD-EE-FF');
    expect(mac.ok && mac.value.value).toBe('aa:bb:cc:dd:ee:ff');
  });

  it('extracts OUI prefix and flags randomized MACs', () => {
    const mac = MacAddress.create('b8:27:eb:12:34:56');
    expect(mac.ok && mac.value.ouiPrefix).toBe('b827eb');
    const random = MacAddress.create('a2:00:00:00:00:01');
    expect(random.ok && random.value.isLocallyAdministered).toBe(true);
  });

  it('rejects malformed input', () => {
    expect(MacAddress.create('nope').ok).toBe(false);
  });
});

describe('IpAddress', () => {
  it('round-trips through integer form', () => {
    const ip = IpAddress.create('192.168.1.42');
    expect(ip.ok && IpAddress.fromInt(ip.value.toInt()).value).toBe('192.168.1.42');
  });

  it('detects private ranges', () => {
    const ip = IpAddress.create('10.0.0.5');
    expect(ip.ok && ip.value.isPrivate).toBe(true);
  });
});

describe('Cidr', () => {
  it('computes the network address and host count for /24', () => {
    const cidr = Cidr.create('192.168.1.55/24');
    expect(cidr.ok && cidr.value.network.value).toBe('192.168.1.0');
    expect(cidr.ok && cidr.value.hostCount).toBe(254);
  });

  it('enumerates usable hosts and respects the max cap', () => {
    const cidr = Cidr.create('192.168.1.0/24');
    if (!cidr.ok) throw new Error('bad cidr');
    const hosts = [...cidr.value.hosts()];
    expect(hosts[0]?.value).toBe('192.168.1.1');
    expect(hosts.at(-1)?.value).toBe('192.168.1.254');
    expect([...cidr.value.hosts(5)]).toHaveLength(5);
  });

  it('tests containment', () => {
    const cidr = Cidr.create('192.168.1.0/24');
    const inside = IpAddress.create('192.168.1.9');
    const outside = IpAddress.create('192.168.2.9');
    expect(cidr.ok && inside.ok && cidr.value.contains(inside.value)).toBe(true);
    expect(cidr.ok && outside.ok && cidr.value.contains(outside.value)).toBe(false);
  });
});
