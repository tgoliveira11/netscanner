import { describe, it, expect } from 'vitest';
import { parseTsharkDeepLine } from './infrastructure/tshark-deep-listener.js';
import { parseLldpctlKeyvalue } from './infrastructure/lldpd-neighbor-source.js';
import {
  parseNetdiscoverLine,
  parseTcpdumpArpLine,
} from './infrastructure/netdiscover-passive-listener.js';

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

describe('parseTcpdumpArpLine', () => {
  it('parses ARP request teller from -e lines', () => {
    const row = parseTcpdumpArpLine(
      '05:18:52.898873 60:be:b4:23:9c:62 > ff:ff:ff:ff:ff:ff, ethertype ARP (0x0806), length 60: Request who-has 192.168.40.112 tell 192.168.40.1, length 46',
    );
    expect(row).toEqual({ ip: '192.168.40.1', mac: '60:be:b4:23:9c:62' });
  });

  it('parses ARP reply is-at', () => {
    const row = parseTcpdumpArpLine(
      '05:18:52.900000 aa:bb:cc:dd:ee:ff > 60:be:b4:23:9c:62, ethertype ARP (0x0806), length 60: Reply 192.168.40.2 is-at aa:bb:cc:dd:ee:ff, length 46',
    );
    expect(row).toEqual({ ip: '192.168.40.2', mac: 'aa:bb:cc:dd:ee:ff' });
  });
});
