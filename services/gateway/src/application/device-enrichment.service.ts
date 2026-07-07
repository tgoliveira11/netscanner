import type { Device, OsGuess, ServiceInfo } from '@netscanner/contracts';
import type {
  IDhcpFingerprintSource,
  IDeviceFingerprintResolver,
  IPassiveSignalStore,
} from '@netscanner/discovery';
import { mergePassiveSignals } from '@netscanner/discovery';
import { ClassifyDeviceUseCase } from '@netscanner/classification';
import type { SnmpEnricher } from '@netscanner/scanner';
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
}

export class DeviceEnrichmentService {
  constructor(private readonly deps: DeviceEnrichmentDeps) {}

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
  ): Promise<Record<string, unknown> | null> {
    if (!this.deps.fingerbank) return null;
    const fp = mac ? this.deps.dhcpSource?.get(mac) : undefined;
    if (!fp && !mac) return null;
    const res = await this.deps.fingerbank.resolve({
      mac,
      dhcpFingerprint: fp?.fingerprint,
      dhcpVendor: fp?.vendorClass,
      hostname,
    });
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
      readStr(mergedSignals, 'netbiosName') ??
      readStr(mergedSignals, 'llmnrName') ??
      readStr(mergedSignals, 'lldpSystemName') ??
      input.hostname;

    const openPorts = new Set(input.services.filter((s) => s.state === 'open').map((s) => s.port));
    if (this.deps.snmp && (openPorts.has(161) || input.ip === input.gatewayIp)) {
      const snmp = await this.deps.snmp.query(input.ip);
      if (snmp) mergedSignals = { ...mergedSignals, ...this.deps.snmp.signalsFrom(snmp) };
    }

    const fb = await this.resolveFingerbank(input.mac, hostname);
    if (fb) mergedSignals = { ...mergedSignals, ...fb };

    const nmapOs = input.os?.source === 'nmap' ? input.os : null;

    const classification = this.deps.classify.execute({
      ip: input.ip,
      mac: input.mac,
      hostname,
      os: nmapOs,
      services: input.services,
      vendorFromScan: null,
      gatewayIp: input.gatewayIp,
      signals: mergedSignals,
    });

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
      securityFlags: classification.securityFlags,
      signals: {
        ...mergedSignals,
        connectionBasis: classification.connectionBasis,
        classification: classification.reasons,
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

  needsEnrichment(device: Device): boolean {
    if (this.needsPassiveEnrichment(device)) return true;
    if (!device.mac) return false;
    const dhcp = this.deps.dhcpSource?.get(device.mac);
    if (!dhcp) return false;
    const storedFp = device.signals['dhcpFingerprint'];
    const hasFb = typeof device.signals['fingerbankDevice'] === 'string';
    if (storedFp !== dhcp.fingerprint) return true;
    if (!hasFb && this.deps.fingerbank) return true;
    if (!device.os || !device.model) return true;
    if (device.os && !device.os.version && dhcp.vendorClass) return true;
    return false;
  }

  needsPassiveEnrichment(device: Device): boolean {
    const store = this.deps.passiveStore;
    if (!store) return false;
    const passive = this.mergePassiveSignals(device.ip, device.mac, {});
    for (const [key, value] of Object.entries(passive)) {
      if (value == null || value === '') continue;
      if (device.signals[key] !== value) return true;
    }
    return false;
  }
}

function readStr(signals: Record<string, unknown>, key: string): string | null {
  const v = signals[key];
  return typeof v === 'string' && v ? v : null;
}
