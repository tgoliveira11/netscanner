import { Bonjour } from 'bonjour-service';
import type { IHostProbe, ProbeContext, RawHostSignal } from '../domain/host-probe.js';
import { MDNS_SERVICE_TYPES } from '../domain/mdns-service-types.js';

/**
 * mDNS discovery during an active scan (bounded listen window).
 */
export class MdnsProbe implements IHostProbe {
  readonly name = 'mdns';
  readonly phase = 'enrich' as const;

  async run(ctx: ProbeContext, emit: (signal: RawHostSignal) => void): Promise<void> {
    const bonjour = new Bonjour();
    const browsers = MDNS_SERVICE_TYPES.map((type) =>
      bonjour.find({ type }, (service) => {
        const addresses = service.addresses ?? [];
        const ipv4 = addresses.find((a) => /^\d{1,3}(\.\d{1,3}){3}$/.test(a));
        if (!ipv4) return;
        emit({
          ip: ipv4,
          hostname: service.host?.replace(/\.local\.?$/, '') ?? service.name,
          source: this.name,
          extra: {
            mdnsServices: [`${type}:${service.name}`],
            mdnsType: type,
          },
        });
      }),
    );

    await new Promise<void>((resolve) => {
      const done = () => {
        browsers.forEach((b) => b.stop());
        bonjour.destroy();
        resolve();
      };
      const timer = setTimeout(done, Math.max(ctx.timeoutMs, 5000));
      ctx.signal.addEventListener('abort', () => {
        clearTimeout(timer);
        done();
      });
    });
  }
}
