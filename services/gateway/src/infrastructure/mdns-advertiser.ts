import os from 'node:os';
import { Bonjour, type Service } from 'bonjour-service';
import type { Logger } from '@netscanner/logger';

export interface MdnsAdvertiseOptions {
  /** Hostname label without .local (e.g. netscanner). */
  hostname: string;
  /** HTTP port advertised in the service record. */
  port: number;
  /**
   * When set, only publish this IPv4 A record (and AAAA on the same NIC).
   * Use CLUSTER_ADVERTISE_HOST so peers on other VLANs do not flood extra As.
   */
  ipv4?: string;
}

/**
 * Advertise netscanner.local via mDNS (honest A/AAAA for this host).
 * Cross-VLAN helpers must also reverse-proxy to the inventory leader — macOS
 * ignores mDNS answers that claim another machine's IP.
 *
 * Important: macOS dual-stack getaddrinfo waits ~5s when a .local name has A
 * but no AAAA answer. We therefore keep AAAA (including link-local) so lookups
 * stay fast; Happy Eyeballs falls back to IPv4 within milliseconds if needed.
 */
export class MdnsAdvertiser {
  private bonjour: Bonjour | null = null;
  private service: Service | null = null;
  private activeName: string | null = null;

  constructor(private readonly logger: Logger) {}

  start(opts: MdnsAdvertiseOptions): void {
    const host = opts.hostname.replace(/\.local$/i, '').trim() || 'netscanner';
    const fqdn = `${host}.local`;
    if (this.activeName === fqdn && this.service) return;

    this.stop();
    try {
      this.bonjour = new Bonjour();
      this.service = this.bonjour.publish({
        name: 'NetScanner',
        type: 'http',
        protocol: 'tcp',
        port: opts.port,
        host: fqdn,
        txt: { path: '/' },
        probe: false, // multiple VLAN agents may claim the same name
      });
      const ipv4 = opts.ipv4?.trim();
      if (ipv4) {
        const aaaas = linkLocalOnSameNic(ipv4);
        const orig = this.service.records.bind(this.service);
        this.service.records = () =>
          orig().filter((r) => {
            if (r.type === 'A') return r.data === ipv4;
            if (r.type === 'AAAA') return typeof r.data === 'string' && aaaas.has(r.data);
            return true;
          });
      }
      this.activeName = fqdn;
      this.logger.info(
        { mdnsName: fqdn, port: opts.port, ipv4: ipv4 || null },
        'mDNS advertisement started',
      );
    } catch (error) {
      this.logger.warn(
        { error: error instanceof Error ? error.message : String(error) },
        'mDNS advertisement failed',
      );
      this.stop();
    }
  }

  stop(): void {
    try {
      this.service?.stop();
    } catch {
      /* ignore */
    }
    try {
      this.bonjour?.destroy();
    } catch {
      /* ignore */
    }
    this.service = null;
    this.bonjour = null;
    if (this.activeName) {
      this.logger.info({ mdnsName: this.activeName }, 'mDNS advertisement stopped');
    }
    this.activeName = null;
  }

  name(): string | null {
    return this.activeName;
  }
}

/** Link-local IPv6 addresses on the NIC that owns `ipv4` (for fast dual-stack mDNS). */
function linkLocalOnSameNic(ipv4: string): Set<string> {
  const out = new Set<string>();
  for (const addrs of Object.values(os.networkInterfaces())) {
    if (!addrs?.some((a) => a.family === 'IPv4' && a.address === ipv4)) continue;
    for (const a of addrs) {
      if (a.family === 'IPv6' && a.address.toLowerCase().startsWith('fe80:')) {
        out.add(a.address);
      }
    }
  }
  return out;
}
