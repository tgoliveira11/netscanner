import { describe, it, expect } from 'vitest';
import { parseTsharkDeepLine } from './infrastructure/tshark-deep-listener.js';
import { parseLldpctlKeyvalue } from './infrastructure/lldpd-neighbor-source.js';
import { parseNetdiscoverLine } from './infrastructure/netdiscover-passive-listener.js';

describe('parseTsharkDeepLine', () => {
  it('extracts SNI and HTTP host', () => {
    const row = parseTsharkDeepLine(
      'eth:ethertype:ip:tcp:tls\t192.168.1.10\taa:bb:cc:dd:ee:ff\tapi.ring.com\t\t\t',
    );
    expect(row?.ip).toBe('192.168.1.10');
    expect(row?.tlsSni).toBe('api.ring.com');
  });

  it('returns null without useful fields', () => {
    expect(parseTsharkDeepLine('eth\t1.2.3.4\taa:bb:cc:dd:ee:ff\t\t\t\t')).toBeNull();
  });
});

describe('parseLldpctlKeyvalue', () => {
  it('groups neighbors by interface', () => {
    const neighbors = parseLldpctlKeyvalue(`
lldp.eth0.chassis.name=core-sw
lldp.eth0.chassis.mac=11:22:33:44:55:66
lldp.eth0.port.ifname=Gi1/0/1
lldp.eth0.chassis.mgmt-ip=192.168.40.1
`);
    expect(neighbors).toHaveLength(1);
    expect(neighbors[0]?.systemName).toBe('core-sw');
    expect(neighbors[0]?.mgmtIp).toBe('192.168.40.1');
    expect(neighbors[0]?.mac).toBe('11:22:33:44:55:66');
  });
});

describe('parseNetdiscoverLine', () => {
  it('parses IP/MAC/vendor rows', () => {
    const row = parseNetdiscoverLine(
      ' 192.168.1.50    aa:bb:cc:dd:ee:ff     1      60   Apple, Inc.',
    );
    expect(row).toEqual({
      ip: '192.168.1.50',
      mac: 'aa:bb:cc:dd:ee:ff',
      vendor: 'Apple, Inc.',
    });
  });

  it('ignores headers', () => {
    expect(parseNetdiscoverLine('IP At MAC Address')).toBeNull();
  });
});
