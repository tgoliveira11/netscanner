import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';
import { SsdpClient } from './ssdp-import.js';

/**
 * Periodic SSDP/UPnP discovery (M-SEARCH) feeding the passive signal store.
 * Devices respond with SERVER, ST, and LOCATION for UPnP enrichment later.
 */
export class SsdpPassiveListener {
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly store: IPassiveSignalStore,
    private readonly logger: Logger,
    private readonly intervalMs = 120_000,
  ) {}

  start(): void {
    if (this.timer) return;
    void this.search();
    this.timer = setInterval(() => void this.search(), this.intervalMs);
    this.logger.info({ intervalMs: this.intervalMs }, 'SSDP passive listener started');
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  private search(): Promise<void> {
    return new Promise((resolve) => {
      let client: InstanceType<typeof SsdpClient> | undefined;
      const done = () => {
        try {
          client?.stop();
        } catch {
          /* ignore */
        }
        resolve();
      };

      try {
        client = new SsdpClient();
      } catch {
        done();
        return;
      }

      client.on('response', (headers: Record<string, unknown>, _code: number, rinfo) => {
        const ip = rinfo?.address;
        if (!ip || !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return;
        const str = (v: unknown): string | undefined => (v == null ? undefined : String(v));
        void this.store.ingest({
          ip,
          source: 'ssdp-passive',
          signals: {
            ssdpServer: str(headers['SERVER']),
            ssdpSt: str(headers['ST']),
            ssdpUsn: str(headers['USN']),
            ssdpLocation: str(headers['LOCATION']),
            ssdpPassive: true,
          },
        });
      });

      try {
        client.search('ssdp:all');
      } catch {
        done();
        return;
      }
      setTimeout(done, 8000);
    });
  }
}
