import type { IHostProbe, ProbeContext, RawHostSignal } from '../domain/host-probe.js';
import { SsdpClient } from './ssdp-import.js';

/**
 * SSDP / UPnP discovery via an M-SEARCH broadcast. The SERVER header and search
 * target (ST) frequently name the device (routers, smart TVs, media servers,
 * IoT hubs), providing manufacturer/model hints for classification.
 */
export class SsdpProbe implements IHostProbe {
  readonly name = 'ssdp';
  readonly phase = 'enrich' as const;

  async run(ctx: ProbeContext, emit: (signal: RawHostSignal) => void): Promise<void> {
    const client = new SsdpClient();

    client.on('response', (headers: Record<string, unknown>, _code: number, rinfo) => {
      const ip = rinfo?.address;
      if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return;
      const str = (v: unknown): string | undefined => (v == null ? undefined : String(v));
      emit({
        ip,
        source: this.name,
        extra: {
          ssdpServer: str(headers['SERVER']),
          ssdpSt: str(headers['ST']),
          ssdpUsn: str(headers['USN']),
          ssdpLocation: str(headers['LOCATION']),
        },
      });
    });

    try {
      client.search('ssdp:all');
    } catch {
      /* network may be unavailable; treated as no results */
    }

    await new Promise<void>((resolve) => {
      const done = () => {
        try {
          client.stop();
        } catch {
          /* ignore */
        }
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
