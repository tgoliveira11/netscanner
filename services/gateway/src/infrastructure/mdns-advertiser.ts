import { Bonjour, type Service } from 'bonjour-service';
import type { Logger } from '@netscanner/logger';

export interface MdnsAdvertiseOptions {
  /** Hostname label without .local (e.g. netscanner). */
  hostname: string;
  /** HTTP port advertised in the service record. */
  port: number;
}

/**
 * Advertise netscanner.local via mDNS (honest A records for this host).
 * Cross-VLAN helpers must also reverse-proxy to the inventory leader — macOS
 * ignores mDNS answers that claim another machine's IP.
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
      this.activeName = fqdn;
      this.logger.info({ mdnsName: fqdn, port: opts.port }, 'mDNS advertisement started');
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
