import { Cidr, isOk } from '@netscanner/kernel';
import type { AppConfig } from '@netscanner/config';
import type { IEventPublisher } from '@netscanner/contracts';
import type { Logger } from '@netscanner/logger';
import { listScanCidrs } from '@netscanner/os-abstraction';
import type { DhcpFingerprint, DiscoverHostsUseCase, IPassiveSignalStore } from '@netscanner/discovery';
import type { IDeviceRepository } from '@netscanner/inventory';
import type { DeviceEnrichmentService } from './device-enrichment.service.js';
import type { RunScanUseCase } from './run-scan.use-case.js';
import type { ScanSessionStore } from './scan-session.js';

export const BACKGROUND_ENRICH_SCAN_ID = 'background-enrich';
export const BACKGROUND_LIGHT_SCAN_ID = 'background-scan';

export interface BackgroundWorkerDeps {
  config: AppConfig;
  logger: Logger;
  enrichment: DeviceEnrichmentService;
  repo: IDeviceRepository;
  lightDiscover: DiscoverHostsUseCase;
  runScan: RunScanUseCase;
  sessions: ScanSessionStore;
  events: IEventPublisher;
  detectPrimaryCidr: () => string | null;
  dhcpSource?: { onCaptured(handler: (fp: DhcpFingerprint) => void): () => void };
  passiveStore?: IPassiveSignalStore;
}

/**
 * Background loops that improve inventory over time without manual rescans:
 *  1) re-enrich when a new DHCP fingerprint arrives;
 *  2) periodic sweep for devices with uncaptured fingerprints;
 *  3) periodic light scan (ping + ARP only);
 *  4) emit device.changed / device.new over the event bus (→ WebSocket).
 */
export class BackgroundWorker {
  private enrichTimer: ReturnType<typeof setInterval> | null = null;
  private scanTimer: ReturnType<typeof setInterval> | null = null;
  private enrichRunning = false;
  private scanRunning = false;
  private dhcpUnsub: (() => void) | null = null;
  private passiveUnsub: (() => void) | null = null;

  constructor(private readonly deps: BackgroundWorkerDeps) {}

  start(): void {
    const { config, logger, dhcpSource } = this.deps;

    if (dhcpSource) {
      this.dhcpUnsub = dhcpSource.onCaptured((fp) => {
        void this.onDhcpCaptured(fp);
      });
    }

    if (this.deps.passiveStore) {
      this.passiveUnsub = this.deps.passiveStore.onUpdated((ip) => {
        void this.onPassiveSignal(ip);
      });
    }

    const enrichMs = config.BACKGROUND_ENRICH_INTERVAL_MS;
    this.enrichTimer = setInterval(() => void this.enrichPending(), enrichMs);

    if (config.BACKGROUND_SCAN_ENABLED) {
      const scanMs = config.BACKGROUND_SCAN_INTERVAL_MS;
      this.scanTimer = setInterval(() => void this.runLightScan(), scanMs);
      // Kick once shortly after start so Extra scan CIDRs are covered without waiting a full interval.
      setTimeout(() => void this.runLightScan(), 5_000);
      logger.info({ enrichMs, scanMs, scanCidrs: listScanCidrs(config.SCAN_CIDRS) }, 'background worker started');
    } else {
      logger.info({ enrichMs }, 'background worker started (light scan disabled)');
    }
  }

  stop(): void {
    if (this.enrichTimer) clearInterval(this.enrichTimer);
    if (this.scanTimer) clearInterval(this.scanTimer);
    this.dhcpUnsub?.();
    this.passiveUnsub?.();
    this.enrichTimer = null;
    this.scanTimer = null;
    this.dhcpUnsub = null;
    this.passiveUnsub = null;
  }

  /** Re-read interval flags from live config and restart timers. */
  reconfigure(): void {
    this.stop();
    this.start();
  }

  private async onPassiveSignal(ip: string): Promise<void> {
    if (ip.startsWith('lldp:')) return;
    const device = await this.deps.repo.findByIp(ip);
    if (!device) return;
    if (
      !this.deps.enrichment.needsPassiveEnrichment(device) &&
      !this.deps.enrichment.needsEnrichment(device)
    ) {
      return;
    }
    await this.enrichOne(device.id, BACKGROUND_ENRICH_SCAN_ID);
  }

  private async onDhcpCaptured(fp: DhcpFingerprint): Promise<void> {
    const device = await this.deps.repo.findByMac(fp.mac);
    if (!device) return;
    await this.enrichOne(device.id, BACKGROUND_ENRICH_SCAN_ID);
  }

  private async enrichPending(): Promise<void> {
    if (this.enrichRunning || this.deps.sessions.activeScan()) return;
    this.enrichRunning = true;
    try {
      const devices = await this.deps.repo.list();
      for (const device of devices) {
        if (!this.deps.enrichment.needsEnrichment(device) && !this.deps.enrichment.needsPassiveEnrichment(device)) {
          continue;
        }
        await this.enrichOne(device.id, BACKGROUND_ENRICH_SCAN_ID);
      }
    } catch (error) {
      this.deps.logger.warn(
        { error: error instanceof Error ? error.message : error },
        'background enrich sweep failed',
      );
    } finally {
      this.enrichRunning = false;
    }
  }

  private async enrichOne(deviceId: string, scanId: string): Promise<void> {
    const device = await this.deps.repo.findById(deviceId);
    if (!device) return;

    const cidr = this.deps.detectPrimaryCidr();
    const gatewayIp = cidr ? this.inferGateway(cidr) : null;
    const result = await this.deps.enrichment.enrichDevice(device, gatewayIp);
    const { device: updated, isNew, changes } = result;

    this.deps.events.emit({ type: 'device.classified', payload: { scanId, device: updated } });
    if (isNew) {
      this.deps.events.emit({ type: 'device.new', payload: { scanId, device: updated } });
    } else if (changes.length) {
      this.deps.events.emit({ type: 'device.changed', payload: { scanId, device: updated, changes } });
      this.deps.logger.info({ mac: updated.mac, changes }, 'background enrichment updated device');
    }
  }

  private async runLightScan(): Promise<void> {
    if (this.scanRunning || this.deps.sessions.activeScan()) return;

    const cidrs = listScanCidrs(this.deps.config.SCAN_CIDRS);
    if (!cidrs.length) return;

    this.scanRunning = true;
    const scanId = BACKGROUND_LIGHT_SCAN_ID;
    try {
      const parsed: Cidr[] = [];
      for (const cidrRaw of cidrs) {
        const cidr = Cidr.create(cidrRaw);
        if (isOk(cidr)) parsed.push(cidr.value);
      }
      if (!parsed.length) return;
      this.deps.logger.info({ cidrs, count: parsed.length }, 'background light scan starting');
      await this.deps.runScan.executeLight(scanId, parsed);
    } catch (error) {
      this.deps.logger.warn(
        { error: error instanceof Error ? error.message : error },
        'background light scan failed',
      );
    } finally {
      this.scanRunning = false;
    }
  }

  private inferGateway(cidr: string): string | null {
    const parsed = Cidr.create(cidr);
    if (!isOk(parsed)) return null;
    const first = [...parsed.value.hosts(1)][0];
    return first ? first.value : null;
  }
}
