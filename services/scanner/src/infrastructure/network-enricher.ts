import { connect as tlsConnect } from 'node:tls';
import type { ServiceInfo } from '@netscanner/contracts';
import type { HostEnrichment, IHostEnricher } from '../domain/host-enricher.js';

const WEB_PORTS = new Set([80, 8080, 8008, 443, 8443]);
const TLS_PORTS = new Set([443, 8443]);

function firstMatch(re: RegExp, text: string): string | undefined {
  return re.exec(text)?.[1]?.trim() || undefined;
}

/**
 * Application-layer enricher. For each host it opportunistically:
 *  - fetches the UPnP device-description XML (from the SSDP LOCATION) →
 *    manufacturer / modelName / friendlyName;
 *  - grabs the HTTP `Server` header and page <title> on web ports;
 *  - reads the TLS certificate subject CN on HTTPS ports.
 * These frequently reveal an exact vendor/model even when the MAC is randomized.
 * Every probe is best-effort and time-boxed, so failures never block a scan.
 */
export class NetworkEnricher implements IHostEnricher {
  constructor(private readonly timeoutMs = 2500) {}

  async enrich(
    ip: string,
    services: ServiceInfo[],
    signals: Record<string, unknown>,
  ): Promise<HostEnrichment> {
    const out: HostEnrichment = { signals: {} };
    const openPorts = new Set(services.filter((s) => s.state === 'open').map((s) => s.port));

    const jobs: Promise<void>[] = [];

    const location = signals['ssdpLocation'];
    if (typeof location === 'string' && location) {
      jobs.push(this.fetchUpnp(location, out));
    } else if (openPorts.has(5000)) {
      jobs.push(this.fetchUpnpOnPort(ip, 5000, out));
    }

    const webPort = [...openPorts].find((p) => WEB_PORTS.has(p));
    if (webPort) {
      jobs.push(this.fetchHttp(ip, webPort, out));
    }

    const tlsPort = [...openPorts].find((p) => TLS_PORTS.has(p));
    if (tlsPort) {
      jobs.push(this.fetchTlsSubject(ip, tlsPort, out));
    }

    await Promise.allSettled(jobs);
    return out;
  }

  private async fetchUpnp(location: string, out: HostEnrichment): Promise<void> {
    const xml = await this.httpText(location);
    if (!xml) return;
    this.parseUpnpXml(xml, out);
  }

  /** Try common UPnP description paths when SSDP LOCATION was not captured. */
  private async fetchUpnpOnPort(ip: string, port: number, out: HostEnrichment): Promise<void> {
    const paths = ['/description.xml', '/rootDesc.xml', '/xml/device.xml'];
    for (const path of paths) {
      const xml = await this.httpText(`http://${ip}:${port}${path}`);
      if (!xml || !/<manufacturer>/i.test(xml)) continue;
      this.parseUpnpXml(xml, out);
      if (out.signals['upnpManufacturer']) return;
    }
  }

  private parseUpnpXml(xml: string, out: HostEnrichment): void {
    const manufacturer = firstMatch(/<manufacturer>([^<]+)<\/manufacturer>/i, xml);
    const model = firstMatch(/<modelName>([^<]+)<\/modelName>/i, xml);
    const friendly = firstMatch(/<friendlyName>([^<]+)<\/friendlyName>/i, xml);
    const deviceKind = firstMatch(/<deviceType>([^<]+)<\/deviceType>/i, xml);
    if (manufacturer) out.vendor = out.vendor ?? manufacturer;
    if (friendly) out.hostname = out.hostname ?? friendly;
    out.signals['upnpManufacturer'] = manufacturer;
    out.signals['upnpModel'] = model;
    out.signals['upnpFriendlyName'] = friendly;
    out.signals['upnpDeviceType'] = deviceKind;
  }

  private async fetchHttp(ip: string, port: number, out: HostEnrichment): Promise<void> {
    const scheme = TLS_PORTS.has(port) ? 'https' : 'http';
    const res = await this.httpResponse(`${scheme}://${ip}:${port}/`);
    if (!res) return;
    out.signals['httpServer'] = res.server;
    const title = firstMatch(/<title[^>]*>([^<]+)<\/title>/i, res.body);
    out.signals['httpTitle'] = title;
  }

  private fetchTlsSubject(ip: string, port: number, out: HostEnrichment): Promise<void> {
    return new Promise((resolve) => {
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        socket.destroy();
        resolve();
      };
      // No `servername`: Node rejects an IP as SNI, and without SNI the device
      // returns its default certificate — exactly what we want to fingerprint.
      const socket = tlsConnect(
        { host: ip, port, rejectUnauthorized: false, timeout: this.timeoutMs },
        () => {
          const cert = socket.getPeerCertificate();
          const subject = cert?.subject?.CN;
          const issuer = cert?.issuer?.O;
          if (subject) out.signals['tlsSubject'] = subject;
          if (issuer) out.signals['tlsIssuer'] = issuer;
          finish();
        },
      );
      socket.on('timeout', finish);
      socket.on('error', finish);
    });
  }

  private async httpResponse(
    url: string,
  ): Promise<{ server?: string; body: string } | null> {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      const res = await fetch(url, {
        signal: controller.signal,
        redirect: 'manual',
        // Devices often use self-signed certs; Node fetch ignores that for us
        // only via undici options, so HTTPS titles may fail — TLS CN covers it.
      }).finally(() => clearTimeout(timer));
      const reader = res.body?.getReader();
      let body = '';
      if (reader) {
        const { value } = await reader.read();
        body = value ? new TextDecoder().decode(value).slice(0, 4096) : '';
        await reader.cancel().catch(() => undefined);
      }
      return { server: res.headers.get('server') ?? undefined, body };
    } catch {
      return null;
    }
  }

  private async httpText(url: string): Promise<string | null> {
    const res = await this.httpResponse(url);
    return res?.body ?? null;
  }
}
