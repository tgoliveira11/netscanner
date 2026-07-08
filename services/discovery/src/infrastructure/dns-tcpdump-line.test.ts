import { describe, expect, it } from 'vitest';
import { parseDnsTcpdumpLine } from './dns-tcpdump-line.js';

describe('parseDnsTcpdumpLine', () => {
  it('extracts LAN client and domain from a query line', () => {
    const line =
      '12:34:56.789 IP 10.0.51.100.54321 > 8.8.8.8.53: 12345+ A? device.tuyaus.com. (32)';
    expect(parseDnsTcpdumpLine(line)).toEqual({
      clientIp: '10.0.51.100',
      query: 'device.tuyaus.com',
    });
  });

  it('ignores resolver responses with only public IPs', () => {
    const line = '12:34:56.789 IP 8.8.8.8.53 > 1.2.3.4.1234: 12345+ A? example.com. (28)';
    expect(parseDnsTcpdumpLine(line)).toBeNull();
  });

  it('uses private IP when query direction is reversed', () => {
    const line = '12:34:56.789 IP 142.250.79.197.53 > 10.0.40.2.41000: 12345+ A? pool.ntp.org. (32)';
    expect(parseDnsTcpdumpLine(line)?.clientIp).toBe('10.0.40.2');
  });
});
