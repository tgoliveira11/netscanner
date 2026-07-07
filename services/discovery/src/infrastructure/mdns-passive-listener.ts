import { Bonjour } from 'bonjour-service';
import type { Logger } from '@netscanner/logger';
import { MDNS_SERVICE_TYPES } from '../domain/mdns-service-types.js';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';

function parseTxtRecord(txt?: Record<string, string> | Array<{ name: string; value: string }>): Record<string, string> {
  if (!txt) return {};
  if (Array.isArray(txt)) {
    const out: Record<string, string> = {};
    for (const e of txt) out[e.name] = e.value;
    return out;
  }
  return { ...txt };
}

/** Continuous mDNS/Bonjour listener — accumulates host signals between scans. */
export class MdnsPassiveListener {
  private bonjour: InstanceType<typeof Bonjour> | null = null;
  private browsers: Array<{ stop: () => void }> = [];

  constructor(
    private readonly store: IPassiveSignalStore,
    private readonly logger: Logger,
  ) {}

  start(): void {
    if (this.bonjour) return;
    this.bonjour = new Bonjour();
    for (const type of MDNS_SERVICE_TYPES) {
      const browser = this.bonjour.find({ type }, (service) => {
        const ipv4 = service.addresses?.find((a) => /^\d{1,3}(\.\d{1,3}){3}$/.test(a));
        if (!ipv4) return;

        const txt = parseTxtRecord(service.txt as Record<string, string> | undefined);
        const signals: Record<string, unknown> = {
          mdnsServices: [`${type}:${service.name}`],
          mdnsType: type,
          mdnsPassive: true,
        };
        if (Object.keys(txt).length) signals['mdnsTxt'] = txt;
        if (txt['model']) signals['mdnsModel'] = txt['model'];
        if (txt['osxvers']) signals['mdnsOsVersion'] = txt['osxvers'];
        if (txt['am']) signals['mdnsAppleModel'] = txt['am'];
        if (type === 'airplay' || type === 'raop') signals['airplay'] = true;

        void this.store.ingest({
          ip: ipv4,
          hostname: service.host?.replace(/\.local\.?$/, '') ?? service.name,
          source: 'mdns-passive',
          signals,
        });
      });
      this.browsers.push(browser);
    }
    this.logger.info({ types: MDNS_SERVICE_TYPES.length }, 'mDNS passive listener started');
  }

  stop(): void {
    for (const b of this.browsers) b.stop();
    this.browsers = [];
    this.bonjour?.destroy();
    this.bonjour = null;
  }
}
