import { describe, expect, it } from 'vitest';
import { guessOsFromSynTraits, parseTcpSynLine } from './p0f-fingerprint.js';

describe('p0f-fingerprint', () => {
  it('parses a verbose tcpdump SYN line', () => {
    const line =
      '15:04:05.123 IP (tos 0x0, ttl 64, id 123, offset 0, flags [DF], proto TCP (6), length 60) ' +
      '10.0.51.100.54321 > 8.8.8.8.443: Flags [S], seq 1, win 65535, options [mss 1460,sackOK,TS val 1 ecr 0,nop,wscale 6], length 0';
    const parsed = parseTcpSynLine(line);
    expect(parsed?.ip).toBe('10.0.51.100');
    expect(parsed?.traits.ttl).toBe(64);
    expect(parsed?.traits.wscale).toBe(6);
  });

  it('guesses iOS from Apple-like SYN stack', () => {
    const guess = guessOsFromSynTraits({
      ttl: 64,
      window: 65535,
      mss: 1460,
      wscale: 6,
      sack: true,
      ts: true,
    });
    expect(guess?.family).toBe('iOS');
  });
});
