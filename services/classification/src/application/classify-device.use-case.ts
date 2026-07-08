import { MacAddress, isOk, type IVendorLookup } from '@netscanner/kernel';
import type { ConnectionType, OsGuess, SecurityFlag, ServiceInfo } from '@netscanner/contracts';
import { ClassificationEngine, type IClassificationEngine } from '../domain/classification-engine.js';
import { SecurityAnalyzer } from '../domain/security-analyzer.js';
import { resolveBrandModel, resolveOs } from '../domain/device-identity.js';
import { inferConnection } from '../domain/connection-inference.js';

export interface ClassifyDeviceInput {
  ip: string;
  mac: string | null;
  hostname: string | null;
  os: OsGuess | null;
  services: ServiceInfo[];
  vendorFromScan: string | null;
  gatewayIp?: string | null;
  signals: Record<string, unknown>;
}

export interface ClassifyDeviceResult {
  deviceType: string;
  confidence: number;
  vendor: string | null;
  brand: string | null;
  model: string | null;
  os: OsGuess | null;
  connectionType: ConnectionType;
  connectionBasis: string;
  securityFlags: SecurityFlag[];
  reasons: string[];
  classificationEvidence?: { deviceType: string; posterior: number; reasons: string[] }[];
}

/**
 * Application service that turns raw host evidence into a classification.
 * Resolves the vendor (OUI first, scan fallback), runs the rule engine, and
 * derives security flags. Depends only on ports (IVendorLookup, engine, analyzer).
 *
 * NOTE on connectionType: wired vs WiFi cannot be determined from a remote host.
 * Unless a router/switch integration supplies it, we honestly report 'unknown'.
 */
export class ClassifyDeviceUseCase {
  constructor(
    private readonly engine: IClassificationEngine,
    private readonly vendorLookup: IVendorLookup,
    private readonly security: SecurityAnalyzer,
  ) {}

  execute(input: ClassifyDeviceInput): ClassifyDeviceResult {
    const vendor = this.resolveVendor(input.mac, input.vendorFromScan);
    const { brand, model } = resolveBrandModel(vendor, input.signals);

    const osResolved = resolveOs(input.os, {
      services: input.services,
      signals: input.signals,
      vendor,
      hostname: input.hostname,
    });
    const os = osResolved.os;

    const outcome = this.engine.classify({
      ip: input.ip,
      mac: input.mac,
      vendor,
      hostname: input.hostname,
      os,
      services: input.services,
      gatewayIp: input.gatewayIp,
      signals: input.signals,
    });

    const connection = inferConnection({
      mac: input.mac,
      deviceType: outcome.deviceType,
      isGateway: input.gatewayIp != null && input.ip === input.gatewayIp,
      authoritative: (input.signals['connectionAuthoritative'] as ConnectionType | undefined) ?? null,
      authoritativeBasis: readStr(input.signals, 'connectionAuthoritativeBasis'),
    });

    const reasons = osResolved.extraReason
      ? [...outcome.reasons, osResolved.extraReason]
      : [...outcome.reasons];
    reasons.push(`connection ${connection.type}: ${connection.basis}`);

    return {
      deviceType: outcome.deviceType,
      confidence: outcome.confidence,
      vendor,
      brand,
      model,
      os,
      connectionType: connection.type,
      connectionBasis: connection.basis,
      securityFlags: this.security.analyze(input.services),
      reasons,
      classificationEvidence: outcome.evidence,
    };
  }

  private resolveVendor(mac: string | null, scanVendor: string | null): string | null {
    if (mac) {
      const parsed = MacAddress.create(mac);
      if (isOk(parsed)) {
        const found = this.vendorLookup.resolve(parsed.value);
        if (found) return found;
      }
    }
    return scanVendor;
  }
}

function readStr(signals: Record<string, unknown>, key: string): string | null {
  const v = signals[key];
  return typeof v === 'string' && v ? v : null;
}
