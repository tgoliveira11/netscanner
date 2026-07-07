import type { Logger } from '@netscanner/logger';
import type { IConnectionSource, ConnectionLookup } from '@netscanner/contracts';

/** TP-Link Omada controller — client list for wired/WiFi. */
export class OmadaConnectionSource implements IConnectionSource {
  readonly name = 'omada-api';
  private macToConn = new Map<string, ConnectionLookup>();

  constructor(
    private readonly baseUrl: string,
    private readonly clientId: string,
    private readonly clientSecret: string,
    private readonly siteId: string,
    private readonly logger: Logger,
  ) {}

  private async token(): Promise<string | null> {
    const url = `${this.baseUrl.replace(/\/$/, '')}/openapi/authorize/token?grant_type=client_credentials`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: this.clientId, client_secret: this.clientSecret }),
    });
    if (!res.ok) return null;
    const body = (await res.json()) as { accessToken?: string; result?: { accessToken?: string } };
    return body.accessToken ?? body.result?.accessToken ?? null;
  }

  async refresh(): Promise<void> {
    this.macToConn.clear();
    const access = await this.token();
    if (!access) return;

    const url = `${this.baseUrl.replace(/\/$/, '')}/openapi/v1/sites/${this.siteId}/clients?page=1&pageSize=500`;
    const res = await fetch(url, { headers: { Authorization: `AccessToken=${access}` } });
    if (!res.ok) {
      this.logger.warn({ status: res.status }, 'Omada clients failed');
      return;
    }
    const body = (await res.json()) as { data?: Array<{ mac?: string; wireless?: boolean }> };
    for (const c of body.data ?? []) {
      const mac = c.mac?.toLowerCase();
      if (!mac) continue;
      this.macToConn.set(mac, {
        type: c.wireless ? 'wifi' : 'wired',
        basis: c.wireless ? 'Omada wireless client' : 'Omada wired client',
      });
    }
    this.logger.info({ count: this.macToConn.size }, 'Omada clients refreshed');
  }

  lookupByMac(mac: string): ConnectionLookup | null {
    return this.macToConn.get(mac.toLowerCase()) ?? null;
  }
}
