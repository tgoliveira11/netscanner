import { Cidr, IpAddress, isOk } from '@netscanner/kernel';
import { reverseDns, batchReverseDns } from '@netscanner/os-abstraction';
import type { AppConfig } from '@netscanner/config';
import type { IEventPublisher, ScanType, IConnectionSource } from '@netscanner/contracts';
import type { Logger } from '@netscanner/logger';
import {
  DiscoverHostsUseCase,
  mapPool,
  mergePassiveSignals,
  buildFingerbankQuery,
  type IRouterLeaseSource,
  type RouterLease,
  type IDhcpFingerprintSource,
  type IDeviceFingerprintResolver,
  type IPassiveSignalStore,
  resolvePfSenseTelemetry,
} from '@netscanner/discovery';
import { FingerprintHostUseCase, type IHostEnricher, type ScanDepth, type SnmpEnricher } from '@netscanner/scanner';
import { ClassifyDeviceUseCase } from '@netscanner/classification';
import { UpsertDeviceUseCase, type DeviceSnapshot, type IDeviceRepository } from '@netscanner/inventory';
import type { ScanSessionStore } from './scan-session.js';
import { DeviceEnrichmentService } from './device-enrichment.service.js';
import { applyConnectionSignals } from './connection-signals.js';
import type { Device } from '@netscanner/contracts';

export interface RunScanDeps {
  discover: DiscoverHostsUseCase;
  /** Ping + ARP only — used by the background light scan. */
  lightDiscover?: DiscoverHostsUseCase;
  fingerprint: FingerprintHostUseCase;
  enricher: IHostEnricher;
  enrichment: DeviceEnrichmentService;
  /** Optional router (pfSense) integration for authoritative DHCP lease data. */
  leaseSource?: IRouterLeaseSource;
  /** Optional passive DHCP fingerprint source (feeds Fingerbank). */
  dhcpSource?: IDhcpFingerprintSource;
  /** Optional Fingerbank resolver for exact device model/OS. */
  fingerbank?: IDeviceFingerprintResolver;
  passiveStore?: IPassiveSignalStore;
  snmp?: SnmpEnricher;
  connectionSource?: IConnectionSource;
  classify: ClassifyDeviceUseCase;
  upsert: UpsertDeviceUseCase;
  repo: IDeviceRepository;
  sessions: ScanSessionStore;
  events: IEventPublisher;
  logger: Logger;
  config: AppConfig;
  elevated: boolean;
}

const DEPTH_BY_TYPE: Record<ScanType, ScanDepth> = {
  quick: 'quick',
  standard: 'standard',
  deep: 'deep',
};

/**
 * Orchestrates a full scan across the service pipeline, emitting domain events
 * at each stage so the dashboard updates live. This is the gateway's single
 * coordinating use case; each stage remains an independent, injected collaborator
 * (SRP for the stages, orchestration isolated here).
 */
export class RunScanUseCase {
  constructor(private readonly deps: RunScanDeps) {}

  async execute(scanId: string, cidr: Cidr, scanType: ScanType): Promise<void> {
    return this.executeMany(scanId, [cidr], scanType);
  }

  /**
   * Full scan across one or more CIDRs in a single session.
   * Offline marking runs once at the end so earlier subnets are not wiped.
   */
  async executeMany(scanId: string, cidrs: Cidr[], scanType: ScanType): Promise<void> {
    const { sessions, events, logger } = this.deps;
    if (!cidrs.length) {
      this.progress(scanId, {
        status: 'failed',
        error: 'No CIDRs to scan',
        finishedAt: new Date().toISOString(),
      });
      events.emit({ type: 'scan.failed', payload: { scanId, error: 'No CIDRs to scan' } });
      return;
    }

    const cidrLabel = cidrs.map((c) => c.toString()).join(',');
    sessions.update(scanId, { cidr: cidrLabel });
    const gatewayIp = this.inferGateway(cidrs[0]!);

    const leases = await this.fetchLeases();
    const pfSenseSignals = this.pfSenseSignalExtras();
    if (this.deps.connectionSource) {
      try {
        await this.deps.connectionSource.refresh();
      } catch (error) {
        this.deps.logger.warn(
          { error: error instanceof Error ? error.message : error },
          'SNMP bridge refresh failed (continuing)',
        );
      }
    }
    const leaseByMac = new Map<string, RouterLease>();
    const leaseByIp = new Map<string, RouterLease>();
    for (const lease of leases) {
      if (lease.mac) leaseByMac.set(lease.mac, lease);
      if (lease.ip) leaseByIp.set(lease.ip, lease);
    }
    const usedLeaseKeys = new Set<string>();
    const leaseFor = (ip: string, mac: string | null): RouterLease | undefined => {
      const lease = (mac ? leaseByMac.get(mac) : undefined) ?? leaseByIp.get(ip);
      if (lease) usedLeaseKeys.add(lease.mac ?? lease.ip);
      return lease;
    };

    try {
      this.progress(scanId, { status: 'discovering' });
      events.emit({ type: 'scan.started', payload: sessions.get(scanId)! });

      const seenIds: string[] = [];
      let hostsTotal = 0;
      let hostsDiscovered = 0;

      for (const cidr of cidrs) {
        const subnetGateway = this.inferGateway(cidr) ?? gatewayIp;
        const discoveredIps = new Set<string>();
        const hosts = await this.deps.discover.execute({
          cidr,
          concurrency: this.deps.config.SCAN_CONCURRENCY,
          timeoutMs: this.deps.config.DISCOVERY_TIMEOUT_MS,
          onHost: (host) => {
            discoveredIps.add(host.ip);
            const s = this.progress(scanId, {
              hostsDiscovered: hostsDiscovered + discoveredIps.size,
            });
            events.emit({ type: 'host.discovered', payload: { scanId, host } });
            if (s) events.emit({ type: 'scan.progress', payload: s });
          },
        });

        hostsTotal += hosts.length;
        hostsDiscovered += hosts.length;
        const s = this.progress(scanId, {
          status: 'fingerprinting',
          hostsTotal,
          hostsDiscovered,
        });
        if (s) events.emit({ type: 'scan.progress', payload: s });

        const ptrMap = await batchReverseDns(
          hosts.map((h) => h.ip),
          this.deps.config.SCAN_CONCURRENCY,
        );

        await mapPool(hosts, this.deps.config.SCAN_CONCURRENCY, async (host) => {
          const lease = leaseFor(host.ip, host.mac);
          const mac = host.mac ?? lease?.mac ?? null;
          const depth = await this.resolveDepth(host.ip, mac, scanType);
          const fp = await this.deps.fingerprint.execute({
            ip: host.ip,
            depth,
            osDetection: depth !== 'quick' && this.deps.elevated,
            timeoutMs: depth === 'deep' ? 60000 : depth === 'standard' ? 30000 : 15000,
          });

          const enrichment = await this.deps.enricher.enrich(host.ip, fp.services, host.signals);
          const dhcp = mac ? this.deps.dhcpSource?.get(mac) : undefined;
          let mergedSignals: Record<string, unknown> = { ...host.signals, ...enrichment.signals };
          if (fp.signals) mergedSignals = { ...mergedSignals, ...fp.signals };
          if (this.deps.passiveStore) {
            const fromPassive = mergePassiveSignals(
              this.deps.passiveStore.get(host.ip),
              mac ? this.deps.passiveStore.getByMac(mac) : {},
            );
            mergedSignals = { ...fromPassive, ...mergedSignals };
          }
          if (dhcp) {
            mergedSignals['dhcpFingerprint'] = dhcp.fingerprint;
            mergedSignals['dhcpVendorClass'] = dhcp.vendorClass;
            mergedSignals['dhcpHostname'] = dhcp.hostname;
          }
          if (lease?.interface) mergedSignals['routerInterface'] = lease.interface;
          if (lease?.description) mergedSignals['routerDescription'] = lease.description;
          if (lease?.interface) mergedSignals['pfsenseInterface'] = lease.interface;
          if (lease?.description) mergedSignals['pfsenseDescription'] = lease.description;
          Object.assign(mergedSignals, pfSenseSignals);
          mergedSignals = applyConnectionSignals(mac, mergedSignals, this.deps.connectionSource);

          const openPorts = new Set(fp.services.filter((svc) => svc.state === 'open').map((svc) => svc.port));
          if (this.deps.snmp && (openPorts.has(161) || host.ip === subnetGateway)) {
            const snmp = await this.deps.snmp.query(host.ip);
            if (snmp) Object.assign(mergedSignals, this.deps.snmp.signalsFrom(snmp));
          }

          const hostname =
            lease?.hostname ??
            dhcp?.hostname ??
            strSignal(mergedSignals, 'resolverCacheName') ??
            strSignal(mergedSignals, 'netbiosName') ??
            strSignal(mergedSignals, 'llmnrName') ??
            strSignal(mergedSignals, 'lldpSystemName') ??
            host.hostname ??
            fp.hostname ??
            enrichment.hostname ??
            ptrMap.get(host.ip) ??
            (await reverseDns(host.ip));

          const fb = await this.resolveFingerbank(mac, hostname, mergedSignals);
          if (fb) Object.assign(mergedSignals, fb);

          const classification = this.deps.classify.execute({
            ip: host.ip,
            mac,
            hostname,
            os: fp.os,
            services: fp.services,
            vendorFromScan: fp.vendorFromScan ?? enrichment.vendor ?? null,
            gatewayIp: subnetGateway,
            signals: mergedSignals,
          });

          const snapshot: DeviceSnapshot = {
            ip: host.ip,
            mac,
            vendor: classification.vendor,
            brand: classification.brand,
            model: classification.model,
            hostname,
            deviceType: classification.deviceType as DeviceSnapshot['deviceType'],
            confidence: classification.confidence,
            os: classification.os,
            connectionType: classification.connectionType,
            services: fp.services,
            latencyMs: host.latencyMs,
            securityFlags: classification.securityFlags,
            signals: {
              ...mergedSignals,
              connectionBasis: classification.connectionBasis,
              classification: classification.reasons,
            },
          };

          const { device, isNew, changes } = await this.deps.upsert.execute(snapshot);
          seenIds.push(device.id);

          events.emit({ type: 'device.classified', payload: { scanId, device } });
          if (isNew) events.emit({ type: 'device.new', payload: { scanId, device } });
          else if (changes.length)
            events.emit({ type: 'device.changed', payload: { scanId, device, changes } });

          const prog = this.progress(scanId, {
            devicesClassified: (sessions.get(scanId)?.devicesClassified ?? 0) + 1,
          });
          if (prog) events.emit({ type: 'scan.progress', payload: prog });
        });
      }

      for (const lease of leases) {
        const key = lease.mac ?? lease.ip;
        if (!lease.ip || !lease.online || usedLeaseKeys.has(key)) continue;
        const signals: Record<string, unknown> = {
          pfsenseInterface: lease.interface,
          pfsenseDescription: lease.description,
          source: 'pfsense-lease',
          ...pfSenseSignals,
        };
        const fb = await this.resolveFingerbank(lease.mac, lease.hostname, signals);
        if (fb) Object.assign(signals, fb);
        const classification = this.deps.classify.execute({
          ip: lease.ip,
          mac: lease.mac,
          hostname: lease.hostname,
          os: null,
          services: [],
          vendorFromScan: null,
          gatewayIp,
          signals,
        });
        const snapshot: DeviceSnapshot = {
          ip: lease.ip,
          mac: lease.mac,
          vendor: classification.vendor,
          brand: classification.brand,
          model: classification.model,
          hostname: lease.hostname,
          deviceType: classification.deviceType as DeviceSnapshot['deviceType'],
          confidence: classification.confidence,
          os: classification.os,
          connectionType: classification.connectionType,
          services: [],
          latencyMs: null,
          securityFlags: classification.securityFlags,
          signals: {
            ...signals,
            connectionBasis: classification.connectionBasis,
            classification: classification.reasons,
          },
        };
        const { device, isNew } = await this.deps.upsert.execute(snapshot);
        seenIds.push(device.id);
        events.emit({ type: 'device.classified', payload: { scanId, device } });
        if (isNew) events.emit({ type: 'device.new', payload: { scanId, device } });
      }

      const offline = await this.deps.repo.markOfflineExcept(seenIds);
      for (const deviceId of offline) {
        events.emit({ type: 'device.offline', payload: { deviceId } });
      }

      const done = this.progress(scanId, {
        status: 'completed',
        finishedAt: new Date().toISOString(),
      });
      if (done) events.emit({ type: 'scan.completed', payload: done });
      logger.info(
        { scanId, cidrs: cidrLabel, devices: seenIds.length },
        'scan completed',
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.progress(scanId, { status: 'failed', error: message, finishedAt: new Date().toISOString() });
      events.emit({ type: 'scan.failed', payload: { scanId, error: message } });
      logger.error({ scanId, error }, 'scan failed');
    }
  }

  /**
   * Light scan for background use: ping + ARP discovery only (no nmap/TCP).
   * Walks every configured CIDR and marks offline once at the end.
   */
  async executeLight(scanId: string, cidrs: Cidr | Cidr[]): Promise<void> {
    const list = Array.isArray(cidrs) ? cidrs : [cidrs];
    const { sessions, events, logger } = this.deps;
    const discover = this.deps.lightDiscover ?? this.deps.discover;
    const cidrLabel = list.map((c) => c.toString()).join(',') || 'none';

    if (!sessions.get(scanId)) {
      sessions.createWithId(scanId, cidrLabel, 'quick');
    } else {
      sessions.update(scanId, {
        cidr: cidrLabel,
        scanType: 'quick',
        status: 'pending',
        hostsTotal: 0,
        hostsDiscovered: 0,
        devicesClassified: 0,
        startedAt: new Date().toISOString(),
        finishedAt: null,
        error: null,
      });
    }

    if (!list.length) {
      this.progress(scanId, {
        status: 'failed',
        error: 'No CIDRs to scan',
        finishedAt: new Date().toISOString(),
      });
      return;
    }

    try {
      this.progress(scanId, { status: 'discovering' });
      events.emit({ type: 'scan.started', payload: sessions.get(scanId)! });

      const leases = await this.fetchLeases();
      const pfSenseSignals = this.pfSenseSignalExtras();
      const leaseByMac = new Map<string, RouterLease>();
      const leaseByIp = new Map<string, RouterLease>();
      for (const lease of leases) {
        if (lease.mac) leaseByMac.set(lease.mac, lease);
        if (lease.ip) leaseByIp.set(lease.ip, lease);
      }
      const usedLeaseKeys = new Set<string>();

      const seenIds: string[] = [];
      let hostsTotal = 0;

      for (const cidr of list) {
        const gatewayIp = this.inferGateway(cidr);
        const hosts = await discover.execute({
          cidr,
          concurrency: this.deps.config.SCAN_CONCURRENCY,
          timeoutMs: this.deps.config.DISCOVERY_TIMEOUT_MS,
        });

        hostsTotal += hosts.length;
        this.progress(scanId, {
          status: 'fingerprinting',
          hostsTotal,
          hostsDiscovered: hostsTotal,
        });

        await mapPool(hosts, this.deps.config.SCAN_CONCURRENCY, async (host) => {
          const existing =
            (host.mac ? await this.deps.repo.findByMac(host.mac) : null) ??
            (await this.deps.repo.findByIp(host.ip));
          const lease =
            (host.mac ? leaseByMac.get(host.mac) : undefined) ?? leaseByIp.get(host.ip);
          if (lease) usedLeaseKeys.add(lease.mac ?? lease.ip);
          const mac = host.mac ?? lease?.mac ?? existing?.mac ?? null;

          const signals: Record<string, unknown> = {
            ...existing?.signals,
            ...host.signals,
            ...pfSenseSignals,
          };
          if (lease?.interface) {
            signals['routerInterface'] = lease.interface;
            signals['pfsenseInterface'] = lease.interface;
          }
          if (lease?.description) {
            signals['routerDescription'] = lease.description;
            signals['pfsenseDescription'] = lease.description;
          }

          const snapshot = await this.deps.enrichment.buildSnapshot({
            ip: host.ip,
            mac,
            hostname: lease?.hostname ?? host.hostname ?? existing?.hostname ?? null,
            services: existing?.services ?? [],
            os: existing?.os ?? null,
            latencyMs: host.latencyMs,
            signals,
            gatewayIp,
          });

          const { device, isNew, changes } = await this.deps.upsert.execute(snapshot);
          seenIds.push(device.id);

          events.emit({ type: 'device.classified', payload: { scanId, device } });
          if (isNew) events.emit({ type: 'device.new', payload: { scanId, device } });
          else if (changes.length)
            events.emit({ type: 'device.changed', payload: { scanId, device, changes } });

          const prog = this.progress(scanId, {
            devicesClassified: (sessions.get(scanId)?.devicesClassified ?? 0) + 1,
          });
          if (prog) events.emit({ type: 'scan.progress', payload: prog });
        });
      }

      // Lease-only hosts (e.g. WAN CPE on ignored scan CIDRs) still need inventory + signals.
      const gatewayIp = this.inferGateway(list[0]!);
      for (const lease of leases) {
        const key = lease.mac ?? lease.ip;
        if (!lease.ip || !lease.online || usedLeaseKeys.has(key)) continue;
        const existing =
          (lease.mac ? await this.deps.repo.findByMac(lease.mac) : null) ??
          (await this.deps.repo.findByIp(lease.ip));
        const signals: Record<string, unknown> = {
          ...existing?.signals,
          pfsenseInterface: lease.interface,
          pfsenseDescription: lease.description,
          routerInterface: lease.interface,
          routerDescription: lease.description,
          source: 'pfsense-lease',
          ...pfSenseSignals,
        };
        const snapshot = await this.deps.enrichment.buildSnapshot({
          ip: lease.ip,
          mac: lease.mac,
          hostname: lease.hostname ?? existing?.hostname ?? null,
          services: existing?.services ?? [],
          os: existing?.os ?? null,
          latencyMs: existing?.latencyMs ?? null,
          signals,
          gatewayIp,
        });
        const { device, isNew } = await this.deps.upsert.execute(snapshot);
        seenIds.push(device.id);
        events.emit({ type: 'device.classified', payload: { scanId, device } });
        if (isNew) events.emit({ type: 'device.new', payload: { scanId, device } });
      }

      const offline = await this.deps.repo.markOfflineExcept(seenIds);
      for (const deviceId of offline) {
        events.emit({ type: 'device.offline', payload: { deviceId } });
      }

      const done = this.progress(scanId, {
        status: 'completed',
        finishedAt: new Date().toISOString(),
      });
      if (done) events.emit({ type: 'scan.completed', payload: done });
      logger.info({ scanId, cidrs: cidrLabel, devices: seenIds.length }, 'light scan completed');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.progress(scanId, { status: 'failed', error: message, finishedAt: new Date().toISOString() });
      events.emit({ type: 'scan.failed', payload: { scanId, error: message } });
      logger.error({ scanId, error }, 'light scan failed');
    }
  }

  /** Resolve exact device identity via Fingerbank (DHCP fingerprint + MAC/hostname). */
  private async resolveFingerbank(
    mac: string | null,
    hostname: string | null,
    signals: Record<string, unknown>,
  ): Promise<Record<string, unknown> | null> {
    if (!this.deps.fingerbank) return null;
    const fp = mac ? this.deps.dhcpSource?.get(mac) : undefined;
    const query = buildFingerbankQuery(mac, hostname, signals, fp);
    if (!query.dhcpFingerprint && !query.mac && !query.userAgents?.length && !query.dhcpv6Fingerprint) {
      return null;
    }
    const res = await this.deps.fingerbank.resolve(query);
    if (!res) return null;
    return {
      fingerbankDevice: res.deviceName,
      fingerbankPath: res.devicePath,
      fingerbankVersion: res.version,
      fingerbankScore: res.score,
    };
  }

  /** Adaptive depth: skip deep probes on well-known inventory rows. */
  private async resolveDepth(ip: string, mac: string | null, scanType: ScanType): Promise<ScanDepth> {
    const base = DEPTH_BY_TYPE[scanType];
    if (!this.deps.config.ADAPTIVE_SCAN_ENABLED || scanType === 'quick') return base;

    const existing: Device | null =
      (mac ? await this.deps.repo.findByMac(mac) : null) ?? (await this.deps.repo.findByIp(ip));
    if (!existing) return base;

    const known =
      existing.classificationConfidence >= 0.7 &&
      Boolean(existing.os || existing.model) &&
      existing.services.filter((s) => s.state === 'open').length >= 2;
    return known ? 'quick' : base;
  }

  /** Fetch router leases, tolerating an unconfigured/unavailable integration. */
  private async fetchLeases(): Promise<RouterLease[]> {
    if (!this.deps.leaseSource) return [];
    try {
      return await this.deps.leaseSource.getLeases();
    } catch (error) {
      this.deps.logger.warn(
        { error: error instanceof Error ? error.message : error },
        'router lease source failed (continuing without it)',
      );
      return [];
    }
  }

  private pfSenseSignalExtras(): Record<string, unknown> {
    const telemetry = resolvePfSenseTelemetry(this.deps.leaseSource);
    if (!telemetry) return {};
    const out: Record<string, unknown> = {};
    if (telemetry.version) out.pfsenseVersion = telemetry.version;
    if (telemetry.hostname) out.pfsenseHostname = telemetry.hostname;
    if (telemetry.gateways.length) out.pfsenseGateways = telemetry.gateways;
    if (telemetry.interfaces.length) out.pfsenseInterfaces = telemetry.interfaces;
    return out;
  }

  private progress(scanId: string, patch: Parameters<ScanSessionStore['update']>[1]) {
    return this.deps.sessions.update(scanId, patch);
  }

  /** Heuristic default gateway = first usable host (.1) of the subnet. */
  private inferGateway(cidr: Cidr): string | null {
    const first = [...cidr.hosts(1)][0];
    return first ? first.value : null;
  }

  static parseCidr(raw: string): Cidr | null {
    const cidr = Cidr.create(raw);
    return isOk(cidr) ? cidr.value : null;
  }

  static isValidIp(raw: string): boolean {
    return isOk(IpAddress.create(raw));
  }
}

function strSignal(signals: Record<string, unknown>, key: string): string | null {
  const v = signals[key];
  return typeof v === 'string' && v ? v : null;
}
