import { describe, it, expect } from 'vitest';
import { parseDhcpPacket } from './domain/dhcp-fingerprint.js';
import { DhcpSniffer } from './infrastructure/dhcp-sniffer.js';
import {
  dhcpPayloadFromTcpdumpHex,
  extractDhcpPayloadFromFrame,
} from './infrastructure/dhcp-tcpdump-parser.js';

/** Build a minimal but valid DHCP DISCOVER packet for the parser. */
function buildDiscover(): Buffer {
  const buf = Buffer.alloc(300);
  buf[0] = 1; // op = BOOTREQUEST
  buf[1] = 1; // htype = Ethernet
  buf[2] = 6; // hlen
  // chaddr (client MAC) at offset 28
  Buffer.from([0xaa, 0xbb, 0xcc, 0x11, 0x22, 0x33]).copy(buf, 28);
  // magic cookie at 236
  buf.writeUInt32BE(0x63825363, 236);
  let i = 240;
  const put = (bytes: number[]) => {
    for (const b of bytes) buf[i++] = b;
  };
  put([53, 1, 1]); // Message type = DISCOVER
  put([55, 4, 1, 3, 6, 15]); // Parameter Request List → fingerprint "1,3,6,15"
  const vendor = Buffer.from('MSFT 5.0', 'latin1');
  put([60, vendor.length, ...vendor]); // Vendor class
  const host = Buffer.from('laptop', 'latin1');
  put([12, host.length, ...host]); // Hostname
  put([255]); // end
  return buf.subarray(0, i);
}

describe('parseDhcpPacket', () => {
  it('extracts MAC, message type, fingerprint, vendor class and hostname', () => {
    const parsed = parseDhcpPacket(buildDiscover());
    expect(parsed).not.toBeNull();
    expect(parsed!.mac).toBe('aa:bb:cc:11:22:33');
    expect(parsed!.messageType).toBe(1);
    expect(parsed!.fingerprint).toBe('1,3,6,15');
    expect(parsed!.vendorClass).toBe('MSFT 5.0');
    expect(parsed!.hostname).toBe('laptop');
  });

  it('rejects non-DHCP packets (bad magic cookie / too short)', () => {
    expect(parseDhcpPacket(Buffer.alloc(10))).toBeNull();
    const noCookie = Buffer.alloc(300);
    expect(parseDhcpPacket(noCookie)).toBeNull();
  });
});

describe('dhcp tcpdump parser', () => {
  it('extracts DHCP payload from a padded frame', () => {
    const dhcp = buildDiscover();
    const frame = Buffer.concat([Buffer.alloc(42), dhcp]);
    const payload = extractDhcpPayloadFromFrame(frame);
    expect(payload?.equals(dhcp)).toBe(true);
    expect(parseDhcpPacket(payload!)?.mac).toBe('aa:bb:cc:11:22:33');
  });

  it('parses tcpdump -xx hex lines', () => {
    const dhcp = buildDiscover();
    const frame = Buffer.concat([Buffer.alloc(42), dhcp]);
    const hex = [...frame].map((b) => b.toString(16).padStart(2, '0')).join('');
    const lines: string[] = [];
    for (let i = 0; i < hex.length; i += 16) {
      const slice = hex.slice(i, i + 16);
      const pairs = slice.match(/.{1,2}/g) ?? [];
      lines.push(`        0x${(i / 2).toString(16).padStart(4, '0')}:  ${pairs.join(' ')}`);
    }
    const payload = dhcpPayloadFromTcpdumpHex(lines);
    expect(parseDhcpPacket(payload!)?.fingerprint).toBe('1,3,6,15');
  });
});

describe('DhcpSniffer', () => {
  it('lists captured fingerprints keyed by MAC', async () => {
    const sniffer = new DhcpSniffer({ debug: () => {}, info: () => {}, warn: () => {} } as never);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await (sniffer as any).ingest(buildDiscover());
    expect(sniffer.size()).toBe(1);
    expect(sniffer.list()).toEqual([
      {
        mac: 'aa:bb:cc:11:22:33',
        fingerprint: '1,3,6,15',
        vendorClass: 'MSFT 5.0',
        hostname: 'laptop',
      },
    ]);
    expect(sniffer.get('AA:BB:CC:11:22:33')?.fingerprint).toBe('1,3,6,15');
  });
});
