import type { Device, OsGuess, ServiceInfo } from '@netscanner/contracts';
import type {
  IDhcpFingerprintSource,
  IDeviceFingerprintResolver,
  IPassiveSignalStore,
} from '@netscanner/discovery';
import { mergePassiveSignals, buildFingerbankQuery } from '@netscanner/discovery';
import type { IConnectionSource } from '@netscanner/contracts';
import {
  ClassifyDeviceUseCase,
  analyzeDns,
  dnsVendorHints,
  dnsSecurityFlags,
  buildCpes,
  StaticCveResolver,
  scoreRisk,
  cvesToSecurityFlags,
  type ICveResolver,
} from '@netscanner/classification';
import type { SnmpEnricher, TrafficMonitor, HostFingerprint } from '@netscanner/scanner';
import { applyConnectionSignals } from './connection-signals.js';
import {
  UpsertDeviceUseCase,
  type DeviceSnapshot,
  type IDeviceRepository,
  type UpsertResult,
} from '@netscanner/inventory';

export interface DeviceEnrichmentDeps {
  classify: ClassifyDeviceUseCase;
  upsert: UpsertDeviceUseCase;
  repo: IDeviceRepository;
  dhcpSource?: IDhcpFingerprintSource;
  fingerbank?: IDeviceFingerprintResolver;
  passiveStore?: IPassiveSignalStore;
  snmp?: SnmpEnricher;
  connectionSource?: IConnectionSource;
  /** Latest per-IP traffic from pfSense (or other ITrafficSource). */
  trafficMonitor?: TrafficMonitor;
  /** Known-vulnerability resolver (#2). Defaults to the offline curated set. */
  cveResolver?: ICveResolver;
}

export interface EnrichHostInput {
  ip: string;
  mac: string | null;
  hostname: string | null;
  services: ServiceInfo[];
  os: OsGuess | null;
  latencyMs: number | null;
  signals: Record<string, unknown>;
  gatewayIp: string | null;
  vendorFromScan?: string | null;
}

export class DeviceEnrichmentService {
  private readonly cve: ICveResolver;
  constructor(private readonly deps: DeviceEnrichmentDeps) {
    this.cve = deps.cveResolver ?? new StaticCveResolver();
  }

  mergePassiveSignals(
    ip: string,
    mac: string | null,
    signals: Record<string, unknown>,
  ): Record<string, unknown> {
    const store = this.deps.passiveStore;
    if (!store) return signals;
    const fromIp = store.get(ip);
    const fromMac = mac ? store.getByMac(mac) : {};
    return mergePassiveSignals(mergePassiveSignals(signals, fromIp), fromMac);
  }

  mergeDhcpSignals(mac: string | null, signals: Record<string, unknown>): Record<string, unknown> {
    if (!mac) return signals;
    const dhcp = this.deps.dhcpSource?.get(mac);
    if (!dhcp) return signals;
    return {
      ...signals,
      dhcpFingerprint: dhcp.fingerprint,
      dhcpVendorClass: dhcp.vendorClass,
      dhcpHostname: dhcp.hostname,
    };
  }

  async resolveFingerbank(
    mac: string | null,
    hostname: string | null,
    signals: Record<string, unknown> = {},
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

  async buildSnapshot(input: EnrichHostInput): Promise<DeviceSnapshot> {
    let mergedSignals = this.mergePassiveSignals(input.ip, input.mac, input.signals);
    mergedSignals = this.mergeDhcpSignals(input.mac, mergedSignals);

    const dhcp = input.mac ? this.deps.dhcpSource?.get(input.mac) : undefined;
    const hostname =
      dhcp?.hostname ??
      readStr(mergedSignals, 'resolverCacheName') ??
      readStr(mergedSignals, 'netbiosName') ??
      readStr(mergedSignals, 'llmnrName') ??
      readStr(mergedSignals, 'lldpSystemName') ??
      input.hostname;

    const openPorts = new Set(input.services.filter((s) => s.state === 'open').map((s) => s.port));
    if (this.deps.snmp && (openPorts.has(161) || input.ip === input.gatewayIp)) {
      const snmp = await this.deps.snmp.query(input.ip);
      if (snmp) mergedSignals = { ...mergedSignals, ...this.deps.snmp.signalsFrom(snmp) };
    }

    const fb = await this.resolveFingerbank(input.mac, hostname, mergedSignals);
    if (fb) mergedSignals = { ...mergedSignals, ...fb };

    mergedSignals = applyConnectionSignals(input.mac, mergedSignals, this.deps.connectionSource);

    // #1 DNS intelligence: analyze passively-observed query names into a profile
    // BEFORE classification so the DnsClassificationRule can vote on it.
    const dnsQueries = mergedSignals['dnsRecentQueries'];
    if (Array.isArray(dnsQueries) && dnsQueries.length > 0) {
      const dnsProfile = analyzeDns(dnsQueries.map(String));
      mergedSignals = {
        ...mergedSignals,
        dnsProfile,
        dnsCategories: dnsProfile.categories,
        dnsVendorHints: dnsVendorHints(dnsProfile),
      };
    }

    const nmapOs = input.os?.source === 'nmap' ? input.os : null;

    const classification = this.deps.classify.execute({
      ip: input.ip,
      mac: input.mac,
      hostname,
      os: nmapOs,
      services: input.services,
      vendorFromScan: input.vendorFromScan ?? null,
      gatewayIp: input.gatewayIp,
      signals: mergedSignals,
    });

    // #2 CVE: match the resolved identity (OS / brand+model / service products)
    // against the vulnerability DB; fold high-severity ones into securityFlags.
    const cves = this.cve.match(
      buildCpes({
        brand: classification.brand,
        model: classification.model,
        os: classification.os,
        services: input.services,
      }),
    );
    const dnsProfile = mergedSignals['dnsProfile'];
    const traffic = this.deps.trafficMonitor?.get(input.ip);
    if (traffic) mergedSignals = { ...mergedSignals, traffic };

    const securityFlags = [
      ...classification.securityFlags,
      ...(dnsProfile ? dnsSecurityFlags(dnsProfile as never) : []),
      ...cvesToSecurityFlags(cves),
    ];
    const riskScore = scoreRisk(cves, securityFlags);

    return {
      ip: input.ip,
      mac: input.mac,
      vendor: classification.vendor,
      brand: classification.brand,
      model: classification.model,
      hostname,
      deviceType: classification.deviceType as DeviceSnapshot['deviceType'],
      confidence: classification.confidence,
      os: classification.os,
      connectionType: classification.connectionType,
      services: input.services,
      latencyMs: input.latencyMs,
      securityFlags,
      signals: {
        ...mergedSignals,
        connectionBasis: classification.connectionBasis,
        classification: classification.reasons,
        classificationEvidence: classification.classificationEvidence,
        cveFindings: cves,
        riskScore,
        lastEnrichedAt: new Date().toISOString(),
      },
    };
  }

  async enrichDevice(device: Device, gatewayIp: string | null): Promise<UpsertResult> {
    const snapshot = await this.buildSnapshot({
      ip: device.ip,
      mac: device.mac,
      hostname: device.hostname,
      services: device.services,
      os: device.os,
      latencyMs: device.latencyMs,
      signals: device.signals,
      gatewayIp,
    });
    return this.deps.upsert.execute(snapshot);
  }

  async enrichFromFingerprint(
    device: Device,
    fp: HostFingerprint,
    gatewayIp: string | null,
    extraSignals: Record<string, unknown> = {},
  ): Promise<UpsertResult> {
    const signals = {
      ...device.signals,
      ...extraSignals,
      ...(fp.signals ?? {}),
      portScanAt: new Date().toISOString(),
    };
    const snapshot = await this.buildSnapshot({
      ip: device.ip,
      mac: device.mac,
      hostname: fp.hostname ?? device.hostname,
      services: fp.services,
      os: fp.os ?? device.os,
      latencyMs: device.latencyMs,
      signals,
      gatewayIp,
      vendorFromScan: fp.vendorFromScan ?? null,
    });
    return this.deps.upsert.execute(snapshot);
  }

  needsPortRescan(device: Device, maxAgeMs: number): boolean {
    if (!device.isOnline) return false;
    const openCount = device.services.filter((s) => s.state === 'open').length;
    const scannedAt = device.signals['portScanAt'] ?? (openCount > 0 ? device.lastSeen : null);
    if (!scannedAt) return true;
    const ageMs = Date.now() - Date.parse(String(scannedAt));
    return !Number.isFinite(ageMs) || ageMs >= maxAgeMs;
  }

  needsEnrichment(device: Device): boolean {
    if (this.needsPassiveEnrichment(device)) return true;
    if (!device.mac) return false;
    const dhcp = this.deps.dhcpSource?.get(device.mac);
    if (!dhcp) return false;
    const storedFp = device.signals['dhcpFingerprint'];
    const hasFb = typeof device.signals['fingerbankDevice'] === 'string';
    if (storedFp !== dhcp.fingerprint) return true;
    if (!hasFb && this.deps.fingerbank) {
      const passive = this.mergePassiveSignals(device.ip, device.mac, {});
      const hasPassiveFbHints =
        passive['mdnsModel'] ||
        passive['ja3Hash'] ||
        passive['mqttOpen'] ||
        passive['ipv6Duid'] ||
        passive['p0fOsName'];
      if (hasPassiveFbHints || dhcp) return true;
    }
    if (!device.os || !device.model) return true;
    if (device.os && !device.os.version && dhcp.vendorClass) return true;
    const fbScore = device.signals['fingerbankScore'];
    if (
      dhcp &&
      typeof fbScore === 'number' &&
      fbScore < 55 &&
      this.deps.fingerbank
    ) {
      return true;
    }
    return false;
  }

  needsPassiveEnrichment(device: Device): boolean {
    const store = this.deps.passiveStore;
    if (!store) return false;
    const passive = this.mergePassiveSignals(device.ip, device.mac, {});
    const skipKeys = new Set(['dnsQuery', 'dnsPassive']);
    for (const [key, value] of Object.entries(passive)) {
      if (skipKeys.has(key)) continue;
      if (value == null || value === '') continue;
      if (device.signals[key] !== value) return true;
    }
    return false;
  }

  needsTrafficEnrichment(device: Device): boolean {
    const cur = this.deps.trafficMonitor?.get(device.ip);
    if (!cur) return false;
    const stored = device.signals['traffic'];
    if (!stored || typeof stored !== 'object') return true;
    const s = stored as Record<string, unknown>;
    const peersEqual =
      JSON.stringify(s['topPeers'] ?? []) === JSON.stringify(cur.topPeers ?? []);
    return (
      s['bytesIn'] !== cur.bytesIn ||
      s['bytesOut'] !== cur.bytesOut ||
      s['rateBps'] !== cur.rateBps ||
      s['connections'] !== cur.connections ||
      !peersEqual
    );
  }

  needsDnsEnrichment(device: Device): boolean {
    const passive = this.mergePassiveSignals(device.ip, device.mac, {});
    const incoming = passive['dnsRecentQueries'];
    if (!Array.isArray(incoming) || incoming.length === 0) return false;
    const stored = device.signals['dnsRecentQueries'];
    return JSON.stringify(stored ?? []) !== JSON.stringify(incoming);
  }
}

function readStr(signals: Record<string, unknown>, key: string): string | null {
  const v = signals[key];
  return typeof v === 'string' && v ? v : null;
}
