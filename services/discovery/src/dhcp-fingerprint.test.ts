import { describe, it, expect, vi } from 'vitest';
import { parseDhcpPacket } from './domain/dhcp-fingerprint.js';
import { DhcpSniffer, resolveDhcpSniffIfaces } from './infrastructure/dhcp-sniffer.js';
import { CompositeDhcpFingerprintSource } from './infrastructure/composite-dhcp-fingerprint-source.js';
import { remoteDhcpTcpdumpCommand } from './infrastructure/remote-dhcp-sniffer.js';
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

  it('parses OpenWrt/BusyBox tcpdump -xx (4-nibble groups)', () => {
    const lines = [
      '\t0x0000:  ffff ffff ffff be06 6032 27c6 8100 0033',
      '\t0x0010:  0800 4500 0148 f404 0000 ff11 c6a0 0000',
      '\t0x0020:  0000 ffff ffff 0044 0043 0134 5503 0101',
      '\t0x0030:  0600 3057 658a 0000 0000 0000 0000 0000',
      '\t0x0040:  0000 0000 0000 0000 0000 be06 6032 27c6',
      '\t0x0050:  0000 0000 0000 0000 0000 0000 0000 0000',
      '\t0x0060:  0000 0000 0000 0000 0000 0000 0000 0000',
      '\t0x0070:  0000 0000 0000 0000 0000 0000 0000 0000',
      '\t0x0080:  0000 0000 0000 0000 0000 0000 0000 0000',
      '\t0x0090:  0000 0000 0000 0000 0000 0000 0000 0000',
      '\t0x00a0:  0000 0000 0000 0000 0000 0000 0000 0000',
      '\t0x00b0:  0000 0000 0000 0000 0000 0000 0000 0000',
      '\t0x00c0:  0000 0000 0000 0000 0000 0000 0000 0000',
      '\t0x00d0:  0000 0000 0000 0000 0000 0000 0000 0000',
      '\t0x00e0:  0000 0000 0000 0000 0000 0000 0000 0000',
      '\t0x00f0:  0000 0000 0000 0000 0000 0000 0000 0000',
      '\t0x0100:  0000 0000 0000 0000 0000 0000 0000 0000',
      '\t0x0110:  0000 0000 0000 0000 0000 6382 5363 3501',
      '\t0x0120:  0337 0a01 7903 060f 6c72 77a2 fc39 0205',
      '\t0x0130:  dc3d 0701 be06 6032 27c6 3204 c0a8 3366',
      '\t0x0140:  3304 0076 a700 0c05 5761 7463 68ff 0000',
      '\t0x0150:  0000 0000 0000 0000 0000 0000 0000 0000',
    ];
    const payload = dhcpPayloadFromTcpdumpHex(lines);
    const parsed = parseDhcpPacket(payload!);
    expect(parsed?.mac).toBe('be:06:60:32:27:c6');
    expect(parsed?.messageType).toBe(3);
    expect(parsed?.hostname).toBe('Watch');
  });
});

describe('resolveDhcpSniffIfaces', () => {
  it('prefers ifaces array over deprecated iface', () => {
    expect(resolveDhcpSniffIfaces({ ifaces: ['any', 'en0'], iface: 'eth0' })).toEqual(['any', 'en0']);
  });

  it('falls back to iface then en0', () => {
    expect(resolveDhcpSniffIfaces({ iface: 'bridge100' })).toEqual(['bridge100']);
    expect(resolveDhcpSniffIfaces({})).toEqual(['en0']);
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

  it('stop() clears listening state after multi-proc tracking init', () => {
    const sniffer = new DhcpSniffer({ debug: () => {}, info: () => {}, warn: () => {} } as never, {
      ifaces: ['any'],
    });
    expect(sniffer.isListening()).toBe(false);
    sniffer.stop();
    expect(sniffer.mode()).toBeNull();
    expect(sniffer.sniffIfaces()).toEqual([]);
  });
});

describe('CompositeDhcpFingerprintSource', () => {
  it('merges get/list and reports composite mode', async () => {
    const a = {
      start: vi.fn(async () => {}),
      stop: vi.fn(),
      get: (mac: string) =>
        mac.toLowerCase() === 'aa:bb:cc:11:22:33'
          ? {
              mac: 'aa:bb:cc:11:22:33',
              fingerprint: '1,3,6,15',
              vendorClass: null,
              hostname: null,
            }
          : undefined,
      list: () => [
        {
          mac: 'aa:bb:cc:11:22:33',
          fingerprint: '1,3,6,15',
          vendorClass: null,
          hostname: null,
        },
      ],
      size: () => 1,
      isListening: () => true,
      mode: () => 'tcpdump' as const,
      sniffIfaces: () => ['any'],
      onCaptured: () => () => {},
    };
    const b = {
      start: vi.fn(async () => {}),
      stop: vi.fn(),
      get: () => undefined,
      list: () => [
        {
          mac: 'dd:ee:ff:00:11:22',
          fingerprint: '1,28,121',
          vendorClass: 'android-dhcp',
          hostname: 'pixel',
        },
      ],
      size: () => 1,
      isListening: () => true,
      mode: () => 'remote-tcpdump',
      sniffIfaces: () => ['192.168.40.2:br-lan'],
      onCaptured: () => () => {},
    };
    const composite = new CompositeDhcpFingerprintSource([a, b]);
    await composite.start();
    expect(a.start).toHaveBeenCalled();
    expect(b.start).toHaveBeenCalled();
    expect(composite.size()).toBe(2);
    expect(composite.get('AA:BB:CC:11:22:33')?.fingerprint).toBe('1,3,6,15');
    expect(composite.mode()).toBe('composite:tcpdump+remote-tcpdump');
    expect(composite.sniffIfaces()).toEqual(['any', '192.168.40.2:br-lan']);
    composite.stop();
    expect(a.stop).toHaveBeenCalled();
    expect(b.stop).toHaveBeenCalled();
  });
});

describe('remoteDhcpTcpdumpCommand', () => {
  it('documents br-lan capture without secrets', () => {
    expect(remoteDhcpTcpdumpCommand()).toContain('br-lan');
    expect(remoteDhcpTcpdumpCommand()).toContain('udp port 67');
  });
});
