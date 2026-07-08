/** A DHCP fingerprint captured from a client's DISCOVER/REQUEST packet. */
export interface DhcpFingerprint {
  mac: string;
  /** Option 55 (Parameter Request List) as comma-separated option numbers. */
  fingerprint: string;
  /** Option 60 (Vendor Class Identifier), e.g. "android-dhcp-14". */
  vendorClass: string | null;
  /** Option 12 (Hostname) as sent by the client. */
  hostname: string | null;
}

/**
 * Port for a source of DHCP fingerprints keyed by MAC (DIP). Implemented by a
 * passive on-LAN sniffer; the resolver (Fingerbank) consumes these to name the
 * exact device model/OS version.
 *
 * Local sniff only sees VLANs present on this host's L2 interfaces. Cross-VLAN
 * capture (e.g. guest behind an OpenWrt DSA switch) requires a remote tcpdump
 * on the switch/gateway bridge.
 */
export interface IDhcpFingerprintSource {
  start(): Promise<void>;
  stop(): void;
  get(mac: string): DhcpFingerprint | undefined;
  /** All fingerprints captured so far (in-memory cache; also persisted when configured). */
  list(): DhcpFingerprint[];
  size(): number;
  isListening(): boolean;
  /** Active capture backend(s), when listening (e.g. udp, tcpdump, remote-tcpdump, composite). */
  mode(): string | null;
  /** Fired when a new or updated fingerprint is captured (sync; keep handler fast). */
  onCaptured(handler: (fp: DhcpFingerprint) => void): () => void;
}

const MAGIC_COOKIE = 0x63825363;
export const MAGIC_COOKIE_OFFSET = 236;

function hexMac(buf: Buffer): string {
  return [...buf.subarray(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join(':');
}

/**
 * Parse a BOOTP/DHCP packet into a fingerprint. Reads chaddr for the MAC and
 * options 55 (parameter request list → the fingerprint), 60 (vendor class),
 * 12 (hostname), and 53 (message type). Returns null for non-DHCP or malformed
 * packets. Pure and allocation-light so it can run in the hot receive path.
 */
export function parseDhcpPacket(
  buf: Buffer,
): { mac: string; messageType: number; fingerprint: string; vendorClass: string | null; hostname: string | null } | null {
  // Fixed BOOTP header is 236 bytes, then a 4-byte magic cookie, then options.
  if (buf.length < 240) return null;
  if (buf.readUInt32BE(236) !== MAGIC_COOKIE) return null;

  const mac = hexMac(buf.subarray(28, 34)); // chaddr starts at offset 28
  let messageType = 0;
  let fingerprint = '';
  let vendorClass: string | null = null;
  let hostname: string | null = null;

  let i = 240;
  while (i < buf.length) {
    const code = buf[i++];
    if (code === undefined || code === 255) break; // end
    if (code === 0) continue; // pad
    const len = buf[i++];
    if (len === undefined || i + len > buf.length) break;
    const value = buf.subarray(i, i + len);
    i += len;

    switch (code) {
      case 53: // DHCP Message Type
        messageType = value[0] ?? 0;
        break;
      case 55: // Parameter Request List → the fingerprint
        fingerprint = [...value].join(',');
        break;
      case 60: // Vendor Class Identifier
        vendorClass = value.toString('latin1');
        break;
      case 12: // Hostname
        hostname = value.toString('latin1');
        break;
    }
  }

  if (!fingerprint) return null; // no PRL → not useful for fingerprinting
  return { mac, messageType, fingerprint, vendorClass, hostname };
}
