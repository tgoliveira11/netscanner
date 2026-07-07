import { Socket } from 'node:net';
import type { ServiceInfo } from '@netscanner/contracts';
import type { HostFingerprint, IDeepScanner, ScanTarget } from '../domain/deep-scanner.js';

/** Common TCP ports probed by the fallback, with their well-known service names. */
const COMMON_PORTS: Record<number, string> = {
  21: 'ftp',
  22: 'ssh',
  23: 'telnet',
  25: 'smtp',
  53: 'domain',
  80: 'http',
  110: 'pop3',
  139: 'netbios-ssn',
  143: 'imap',
  443: 'https',
  445: 'microsoft-ds',
  515: 'printer',
  631: 'ipp',
  1900: 'upnp',
  3389: 'ms-wbt-server',
  161: 'snmp',
  548: 'afp',
  5000: 'upnp',
  5353: 'mdns',
  62078: 'lockdown',
  7000: 'airplay',
  8008: 'http',
  8009: 'cast',
  8080: 'http-proxy',
  8443: 'https-alt',
  9100: 'jetdirect',
  32400: 'plex',
  5683: 'coap',
  1883: 'mqtt',
};

const QUICK_PORTS = [22, 80, 443, 445, 161, 8080];

/**
 * Pure-Node fallback scanner (no external binary, no root). Performs bounded TCP
 * connect() probes to well-known ports and grabs a short banner when offered.
 * Always available, guaranteeing baseline fingerprinting even without nmap.
 */
export class TcpConnectScanner implements IDeepScanner {
  readonly name = 'tcp-connect';

  async isAvailable(): Promise<boolean> {
    return true;
  }

  private probePort(ip: string, port: number, timeoutMs: number): Promise<ServiceInfo | null> {
    return new Promise((resolve) => {
      const socket = new Socket();
      let banner = '';
      let settled = false;
      const finish = (result: ServiceInfo | null) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve(result);
      };
      socket.setTimeout(timeoutMs);
      socket.once('connect', () => {
        // Give the service a brief window to send a greeting banner.
        setTimeout(() => {
          finish({
            port,
            protocol: 'tcp',
            state: 'open',
            serviceName: COMMON_PORTS[port],
            banner: banner.trim().slice(0, 200) || undefined,
          });
        }, Math.min(300, timeoutMs));
      });
      socket.on('data', (chunk) => {
        banner += chunk.toString('utf8');
        if (banner.length > 512) finish({ port, protocol: 'tcp', state: 'open', serviceName: COMMON_PORTS[port], banner: banner.trim().slice(0, 200) });
      });
      socket.once('timeout', () => finish(null));
      socket.once('error', () => finish(null));
      socket.connect(port, ip);
    });
  }

  async scan(target: ScanTarget): Promise<HostFingerprint> {
    const ports = target.depth === 'quick' ? QUICK_PORTS : Object.keys(COMMON_PORTS).map(Number);
    const perPortTimeout = Math.max(300, Math.min(1500, Math.round(target.timeoutMs / 4)));
    const results = await Promise.all(ports.map((p) => this.probePort(target.ip, p, perPortTimeout)));
    return {
      ip: target.ip,
      services: results.filter((s): s is ServiceInfo => s !== null),
      os: null,
      vendorFromScan: null,
      hostname: null,
      source: 'tcp-connect',
    };
  }
}
