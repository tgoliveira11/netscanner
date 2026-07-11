import type { AppConfig } from '@netscanner/config';
import type { Logger } from '@netscanner/logger';
import type { InventoryEvent } from '@netscanner/contracts';
import type { ClusterService } from './cluster-service.js';

/**
 * Near-realtime push of observed inventory events to a self-host cloud.
 * Only the inventory leader syncs; requires CLOUD_PII_CONSENT for PII fields.
 */
export class CloudSyncWorker {
  private timer: ReturnType<typeof setInterval> | null = null;
  private readonly queue: InventoryEvent[] = [];
  private cursor = 0;

  constructor(
    private readonly config: AppConfig,
    private readonly logger: Logger,
    private readonly cluster: ClusterService,
    private readonly agentId: string,
  ) {}

  start(): void {
    if (!this.config.CLOUD_SYNC_ENABLED || !this.config.CLOUD_SYNC_URL?.trim()) {
      this.logger.info('cloud sync disabled');
      return;
    }
    if (!this.config.CLOUD_PII_CONSENT) {
      this.logger.warn('cloud sync enabled but CLOUD_PII_CONSENT=false — refusing to upload PII');
      return;
    }
    const ms = Math.max(2_000, this.config.CLOUD_SYNC_INTERVAL_MS);
    this.timer = setInterval(() => void this.flush(), ms);
    this.logger.info({ url: this.config.CLOUD_SYNC_URL, intervalMs: ms }, 'cloud sync started');
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  enqueue(event: Omit<InventoryEvent, 'id' | 'agentId' | 'at'> & { at?: string }): void {
    if (!this.config.CLOUD_SYNC_ENABLED) return;
    this.cursor += 1;
    this.queue.push({
      id: `evt-${this.cursor}`,
      agentId: this.agentId,
      at: event.at ?? new Date().toISOString(),
      siteId: event.siteId,
      type: event.type,
      payload: event.payload,
    });
    if (this.queue.length > 2_000) this.queue.splice(0, this.queue.length - 2_000);
  }

  /** Pull pending remote commands from cloud (control leader only). */
  async pullCommands(): Promise<unknown[]> {
    if (!this.cluster.isControlLeader()) return [];
    const base = this.config.CLOUD_SYNC_URL?.replace(/\/$/, '');
    const token = this.config.CLOUD_SYNC_TOKEN?.trim();
    if (!base || !token) return [];
    try {
      const res = await fetch(`${base}/api/v1/commands/pending`, {
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
        signal: AbortSignal.timeout(8_000),
      });
      if (!res.ok) return [];
      const body = (await res.json()) as { data?: unknown[] };
      return Array.isArray(body.data) ? body.data : [];
    } catch (err) {
      this.logger.warn({ err }, 'cloud command pull failed');
      return [];
    }
  }

  private async flush(): Promise<void> {
    if (!this.cluster.isInventoryLeader()) return;
    if (!this.queue.length) return;
    const base = this.config.CLOUD_SYNC_URL?.replace(/\/$/, '');
    const token = this.config.CLOUD_SYNC_TOKEN?.trim();
    if (!base || !token) return;

    const batch = this.queue.splice(0, 100);
    try {
      const res = await fetch(`${base}/api/v1/events`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify({ events: batch }),
        signal: AbortSignal.timeout(15_000),
      });
      if (!res.ok) {
        this.queue.unshift(...batch);
        this.logger.warn({ status: res.status }, 'cloud sync push rejected');
      }
    } catch (err) {
      this.queue.unshift(...batch);
      this.logger.warn({ err }, 'cloud sync push failed');
    }
  }
}
