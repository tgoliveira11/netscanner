import { Cidr, isOk } from '@netscanner/kernel';
import type { AppConfig } from '@netscanner/config';
import type { IEventPublisher } from '@netscanner/contracts';
import type { Logger } from '@netscanner/logger';
import { listScanCidrs } from '@netscanner/os-abstraction';
import type { DhcpFingerprint, DiscoverHostsUseCase, IPassiveSignalStore, ICloudDeviceIdentitySource } from '@netscanner/discovery';
import type { FingerprintHostUseCase, ITrafficSource, TrafficMonitor } from '@netscanner/scanner';
import type { CveFeedRefreshWorker } from '@netscanner/classification';
import type { IDeviceRepository } from '@netscanner/inventory';
import type { DeviceEnrichmentService } from './device-enrichment.service.js';
import type { RunScanUseCase } from './run-scan.use-case.js';
import type { ScanSessionStore } from './scan-session.js';
import { emitDeviceUpsertEvents, emitDeviceAnomalies } from './scan-events.js';
import type { DnsActivityLog } from './dns-activity-log.js';

export const BACKGROUND_ENRICH_SCAN_ID = 'background-enrich';
export const BACKGROUND_LIGHT_SCAN_ID = 'background-scan';

export interface BackgroundWorkerDeps {
  config: AppConfig;
  logger: Logger;
  enrichment: DeviceEnrichmentService;
  repo: IDeviceRepository;
  lightDiscover: DiscoverHostsUseCase;
  runScan: RunScanUseCase;
  fingerprint: FingerprintHostUseCase;
  elevated: boolean;
  sessions: ScanSessionStore;
  events: IEventPublisher;
  detectPrimaryCidr: () => string | null;
  dhcpSource?: { onCaptured(handler: (fp: DhcpFingerprint) => void): () => void };
  passiveStore?: IPassiveSignalStore;
  trafficSource?: ITrafficSource;
  trafficMonitor?: TrafficMonitor;
  dnsActivityLog?: DnsActivityLog;
  cveRefresh?: CveFeedRefreshWorker;
  tuyaIdentity?: ICloudDeviceIdentitySource;
  getSiteId: () => string;
  needsSiteConfirmation?: () => boolean;
  refreshSite?: () => Promise<void>;
}

/**
 * Background loops that improve inventory over time without manual rescans:
 *  1) re-enrich when a new DHCP fingerprint arrives;
 *  2) periodic sweep for devices with uncaptured fingerprints;
 *  3) periodic light scan (ping + ARP only);
 *  4) background port rescan for stale online devices;
 *  5) emit device.changed / device.new over the event bus (→ WebSocket).
 */
export class BackgroundWorker {
  private enrichTimer: ReturnType<typeof setInterval> | null = null;
  private scanTimer: ReturnType<typeof setInterval> | null = null;
  private cveTimer: ReturnType<typeof setInterval> | null = null;
  private tuyaTimer: ReturnType<typeof setInterval> | null = null;
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

    // Daily CVE index refresh (no-op when CVE_NVD_SYNC=false).
    setTimeout(() => void this.refreshCveIndex(), 45_000);
    this.cveTimer = setInterval(() => void this.refreshCveIndex(), 24 * 60 * 60 * 1000);

    if (this.deps.tuyaIdentity) {
      const tuyaMs = config.TUYA_SYNC_INTERVAL_MS;
      setTimeout(() => void this.refreshTuyaIdentity(), 30_000);
      this.tuyaTimer = setInterval(() => void this.refreshTuyaIdentity(), tuyaMs);
      logger.info({ tuyaMs }, 'Tuya identity sync scheduled');
    }
  }

  stop(): void {
    if (this.enrichTimer) clearInterval(this.enrichTimer);
    if (this.scanTimer) clearInterval(this.scanTimer);
    if (this.cveTimer) clearInterval(this.cveTimer);
    if (this.tuyaTimer) clearInterval(this.tuyaTimer);
    this.dhcpUnsub?.();
    this.passiveUnsub?.();
    this.enrichTimer = null;
    this.scanTimer = null;
    this.cveTimer = null;
    this.tuyaTimer = null;
    this.dhcpUnsub = null;
    this.passiveUnsub = null;
  }

  /** Re-read interval flags from live config and restart timers. */
  reconfigure(): void {
    this.stop();
    this.start();
  }

  private async onPassiveSignal(ip: string): Promise<void> {
    if (ip.startsWith('lldp:') || ip.startsWith('tshark:')) return;
    const siteId = this.deps.getSiteId();
    const device = await this.deps.repo.findByIp(siteId, ip);
    if (!device) return;
    if (
      !this.deps.enrichment.needsPassiveEnrichment(device) &&
      !this.deps.enrichment.needsEnrichment(device) &&
      !this.deps.enrichment.needsTrafficEnrichment(device) &&
      !this.deps.enrichment.needsDnsEnrichment(device)
    ) {
      return;
    }
    await this.enrichOne(device.id, BACKGROUND_ENRICH_SCAN_ID);
  }

  private async onDhcpCaptured(fp: DhcpFingerprint): Promise<void> {
    const device = await this.deps.repo.findByMac(this.deps.getSiteId(), fp.mac);
    if (!device) return;
    await this.enrichOne(device.id, BACKGROUND_ENRICH_SCAN_ID);
  }

  private async enrichPending(): Promise<void> {
    if (this.enrichRunning || this.deps.sessions.activeScan()) return;
    this.enrichRunning = true;
    try {
      await this.refreshTraffic();
      const devices = await this.deps.repo.list({ siteId: this.deps.getSiteId() });
      for (const device of devices) {
        if (
          !this.deps.enrichment.needsEnrichment(device) &&
          !this.deps.enrichment.needsPassiveEnrichment(device) &&
          !this.deps.enrichment.needsTrafficEnrichment(device) &&
          !this.deps.enrichment.needsDnsEnrichment(device)
        ) {
          continue;
        }
        await this.enrichOne(device.id, BACKGROUND_ENRICH_SCAN_ID);
      }
      await this.rescanStalePorts();
    } catch (error) {
      this.deps.logger.warn(
        { error: error instanceof Error ? error.message : error },
        'background enrich sweep failed',
      );
    } finally {
      this.enrichRunning = false;
    }
  }

  private async rescanStalePorts(): Promise<void> {
    const { config, enrichment, repo, fingerprint, elevated, logger } = this.deps;
    if (!config.BACKGROUND_PORT_RESCAN_ENABLED) return;

    const maxAgeMs = config.BACKGROUND_PORT_RESCAN_MAX_AGE_MS;
    const batch = config.BACKGROUND_PORT_RESCAN_BATCH;
    const devices = await repo.list({ siteId: this.deps.getSiteId() });
    const stale = devices.filter((d) => enrichment.needsPortRescan(d, maxAgeMs)).slice(0, batch);
    if (!stale.length) return;

    const cidr = this.deps.detectPrimaryCidr();
    const gatewayIp = cidr ? this.inferGateway(cidr) : null;

    for (const device of stale) {
      try {
        const fp = await fingerprint.execute({
          ip: device.ip,
          depth: 'standard',
          osDetection: elevated,
          timeoutMs: 30_000,
        });
        const result = await enrichment.enrichFromFingerprint(device, fp, gatewayIp);
        const { device: updated, isNew, changes, anomalies } = result;
        this.deps.events.emit({
          type: 'device.classified',
          payload: { scanId: BACKGROUND_ENRICH_SCAN_ID, device: updated },
        });
        if (isNew) {
          this.deps.events.emit({
            type: 'device.new',
            payload: { scanId: BACKGROUND_ENRICH_SCAN_ID, device: updated },
          });
        } else if (changes.length) {
          this.deps.events.emit({
            type: 'device.changed',
            payload: { scanId: BACKGROUND_ENRICH_SCAN_ID, device: updated, changes },
          });
          logger.info({ mac: updated.mac, changes }, 'background port rescan updated device');
        }
        for (const anomaly of anomalies) {
          emitDeviceAnomalies(this.deps.events, BACKGROUND_ENRICH_SCAN_ID, updated, [anomaly], this.deps.dnsActivityLog);
        }
      } catch (error) {
        logger.warn(
          { ip: device.ip, error: error instanceof Error ? error.message : error },
          'background port rescan failed',
        );
      }
    }
  }

  private async enrichOne(deviceId: string, scanId: string): Promise<void> {
    const device = await this.deps.repo.findById(deviceId);
    if (!device) return;

    const cidr = this.deps.detectPrimaryCidr();
    const gatewayIp = cidr ? this.inferGateway(cidr) : null;
    const result = await this.deps.enrichment.enrichDevice(device, gatewayIp);
    const { device: updated, isNew, changes, anomalies } = result;

    this.deps.events.emit({ type: 'device.classified', payload: { scanId, device: updated } });
    if (isNew) {
      this.deps.events.emit({ type: 'device.new', payload: { scanId, device: updated } });
    } else if (changes.length) {
      this.deps.events.emit({ type: 'device.changed', payload: { scanId, device: updated, changes } });
      this.deps.logger.info({ mac: updated.mac, changes }, 'background enrichment updated device');
    }
    for (const anomaly of anomalies) {
      emitDeviceAnomalies(this.deps.events, scanId, updated, [anomaly], this.deps.dnsActivityLog);
    }
  }

  private async runLightScan(): Promise<void> {
    if (this.scanRunning || this.deps.sessions.activeScan()) return;
    if (this.deps.needsSiteConfirmation?.()) return;

    await this.deps.refreshSite?.();

    const cidrs = listScanCidrs(this.deps.config.SCAN_CIDRS);
    if (!cidrs.length) return;

    this.scanRunning = true;
    const scanId = BACKGROUND_LIGHT_SCAN_ID;
    const watchdogMs = 240_000;
    const ac = new AbortController();
    let watchdog: ReturnType<typeof setTimeout> | undefined;
    try {
      const parsed: Cidr[] = [];
      for (const cidrRaw of cidrs) {
        const cidr = Cidr.create(cidrRaw);
        if (isOk(cidr)) parsed.push(cidr.value);
      }
      if (!parsed.length) return;
      this.deps.logger.info({ cidrs, count: parsed.length }, 'background light scan starting');
      watchdog = setTimeout(() => {
        this.deps.logger.error(
          { scanId, watchdogMs },
          'background light scan watchdog — aborting stuck scan',
        );
        ac.abort();
      }, watchdogMs);
      await this.deps.runScan.executeLight(scanId, parsed, ac.signal);
    } catch (error) {
      this.deps.logger.warn(
        { error: error instanceof Error ? error.message : error },
        'background light scan failed',
      );
    } finally {
      if (watchdog) clearTimeout(watchdog);
      this.scanRunning = false;
    }
  }

  private inferGateway(cidr: string): string | null {
    const parsed = Cidr.create(cidr);
    if (!isOk(parsed)) return null;
    const first = [...parsed.value.hosts(1)][0];
    return first ? first.value : null;
  }

  private async refreshTraffic(): Promise<void> {
    const { trafficSource, trafficMonitor, logger } = this.deps;
    if (!trafficSource || !trafficMonitor) return;
    try {
      const count = await trafficMonitor.refresh(trafficSource);
      logger.debug({ count, source: trafficSource.name }, 'background traffic sample');
    } catch (error) {
      logger.warn(
        { error: error instanceof Error ? error.message : error },
        'background traffic sample failed',
      );
    }
  }

  private async refreshCveIndex(): Promise<void> {
    const { cveRefresh, config, repo, logger } = this.deps;
    if (!cveRefresh || !config.CVE_NVD_SYNC) return;
    try {
      const devices = await repo.list({ siteId: this.deps.getSiteId() });
      const keywords = new Set<string>();
      for (const d of devices) {
        if (d.brand) keywords.add(d.brand.toLowerCase());
        if (d.os?.name) keywords.add(d.os.name.toLowerCase());
        for (const s of d.services ?? []) {
          if (s.product) keywords.add(String(s.product).toLowerCase());
        }
      }
      const result = await cveRefresh.refresh({
        enabled: true,
        keywords: [...keywords],
      });
      logger.info(result, 'CVE NVD subset refresh finished');
    } catch (error) {
      logger.warn(
        { error: error instanceof Error ? error.message : error },
        'CVE NVD subset refresh failed — keeping local index',
      );
    }
  }

  private async refreshTuyaIdentity(): Promise<void> {
    const { tuyaIdentity, logger } = this.deps;
    if (!tuyaIdentity) return;
    try {
      const count = await tuyaIdentity.refresh();
      logger.debug({ count }, 'Tuya identity sync finished');
    } catch (error) {
      logger.warn(
        { error: error instanceof Error ? error.message : error },
        'Tuya identity sync failed',
      );
    }
  }
}
