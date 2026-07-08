import { MAGIC_COOKIE_OFFSET } from '../domain/dhcp-fingerprint.js';

const MAGIC_COOKIE = 0x63825363;

/** Locate the BOOTP/DHCP payload inside a captured L2/L3 frame. */
export function extractDhcpPayloadFromFrame(frame: Buffer): Buffer | null {
  for (let i = 0; i <= frame.length - 4; i++) {
    if (frame.readUInt32BE(i) === MAGIC_COOKIE) {
      const start = i - MAGIC_COOKIE_OFFSET;
      if (start >= 0) return frame.subarray(start);
    }
  }
  return null;
}

/** Reassemble a tcpdump `-xx` packet dump into a frame buffer. */
export function frameFromTcpdumpHex(hexLines: string[]): Buffer | null {
  const bytes: number[] = [];
  for (const line of hexLines) {
    const m = /^\s*0x[0-9a-f]+:\s+(.+)$/i.exec(line);
    if (!m) continue;
    // tcpdump -xx groups nibbles as "ffff ffff" (OpenWrt/BusyBox) or "ff ff" (BSD);
    // strip whitespace and read byte pairs from the contiguous hex run.
    const pairs = m[1]!.replace(/\s/g, '').match(/[0-9a-f]{2}/gi);
    if (!pairs) continue;
    for (const p of pairs) bytes.push(Number.parseInt(p, 16));
  }
  return bytes.length ? Buffer.from(bytes) : null;
}

/** Parse tcpdump `-xx` lines for one packet into a DHCP message buffer. */
export function dhcpPayloadFromTcpdumpHex(hexLines: string[]): Buffer | null {
  const frame = frameFromTcpdumpHex(hexLines);
  return frame ? extractDhcpPayloadFromFrame(frame) : null;
}

export function isTcpdumpPacketHeader(line: string): boolean {
  return /^\d{2}:\d{2}:\d{2}\./.test(line);
}

export function isTcpdumpHexLine(line: string): boolean {
  return /^\s+0x[0-9a-f]+:/i.test(line);
}
