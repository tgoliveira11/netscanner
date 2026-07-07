import type { Logger } from '@netscanner/logger';
import type { IConnectionSource, ConnectionLookup } from '@netscanner/contracts';

interface UniFiSta {
  mac: string;
  hostname?: string;
  is_wired?: boolean;
  ap_mac?: string;
}

/** UniFi controller REST — authoritative WiFi association per MAC. */
export class UnifiConnectionSource implements IConnectionSource {
  readonly name = 'unifi-api';
  private macToWifi = new Map<string, ConnectionLookup>();

  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string,
    private readonly site: string,
    private readonly logger: Logger,
    private readonly insecureTls = true,
  ) {}

  async refresh(): Promise<void> {
    this.macToWifi.clear();
    const url = `${this.baseUrl.replace(/\/$/, '')}/proxy/network/api/s/${this.site}/stat/sta`;
    try {
      const res = await fetch(url, {
        headers: { 'X-API-KEY': this.apiKey, Accept: 'application/json' },
      });
      if (!res.ok) {
        this.logger.warn({ status: res.status }, 'UniFi stat/sta failed');
        return;
      }
      const body = (await res.json()) as { data?: UniFiSta[] };
      for (const sta of body.data ?? []) {
        const mac = sta.mac?.toLowerCase();
        if (!mac) continue;
        const wifi = !sta.is_wired;
        this.macToWifi.set(mac, {
          type: wifi ? 'wifi' : 'wired',
          ifName: sta.ap_mac ? `ap:${sta.ap_mac}` : undefined,
          basis: wifi ? 'UniFi AP association' : 'UniFi wired uplink',
        });
      }
      this.logger.info({ count: this.macToWifi.size }, 'UniFi clients refreshed');
    } catch (error) {
      this.logger.warn({ error: error instanceof Error ? error.message : error }, 'UniFi refresh failed');
    }
  }

  lookupByMac(mac: string): ConnectionLookup | null {
    return this.macToWifi.get(mac.toLowerCase()) ?? null;
  }
}
