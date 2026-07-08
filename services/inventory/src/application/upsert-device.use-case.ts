import { v4 as uuid } from 'uuid';
import type { ConnectionType, Device, OsGuess, SecurityFlag, ServiceInfo } from '@netscanner/contracts';
import type { IDeviceRepository } from '../domain/device-repository.js';
import type { StoredDevice } from '../domain/device-public.js';
import { toPublicDevice } from '../domain/device-public.js';
import { diffDevice } from '../domain/device-diff.js';
import {
  detectBehavioralAnomalies,
  updateBaseline,
  type BehavioralAnomaly,
} from '../domain/behavioral-anomalies.js';

/** Prefer the higher-confidence OS but keep version from either source. */
function mergeOs(next: OsGuess | null, prev: OsGuess | null): OsGuess | null {
  if (!next) return prev;
  if (!prev) return next;
  const nextAcc = next.accuracy ?? 0;
  const prevAcc = prev.accuracy ?? 0;
  const better = nextAcc >= prevAcc ? next : prev;
  const other = better === next ? prev : next;
  return { ...better, version: better.version ?? other.version };
}

/** Snapshot of a host observed in the current scan, before persistence. */
export interface DeviceSnapshot {
  ip: string;
  mac: string | null;
  vendor: string | null;
  brand: string | null;
  model: string | null;
  hostname: string | null;
  deviceType: Device['deviceType'];
  confidence: number;
  os: OsGuess | null;
  connectionType: ConnectionType;
  services: ServiceInfo[];
  latencyMs: number | null;
  securityFlags: SecurityFlag[];
  signals: Record<string, unknown>;
}

export interface UpsertResult {
  device: Device;
  isNew: boolean;
  changes: string[];
  anomalies: BehavioralAnomaly[];
}

/**
 * Persists a scan snapshot, reconciling it with existing inventory. Devices are
 * identified by MAC when available (stable across DHCP lease changes), else by
 * IP. Preserves user metadata (label/notes) and firstSeen across updates.
 */
export class UpsertDeviceUseCase {
  constructor(
    private readonly repo: IDeviceRepository,
    private readonly clock: () => Date = () => new Date(),
  ) {}

  async execute(snapshot: DeviceSnapshot): Promise<UpsertResult> {
    const now = this.clock().toISOString();
    // Identify by MAC first (stable across DHCP), falling back to IP. The IP
    // fallback is essential: a host first seen without a resolved MAC creates an
    // IP-keyed record, and a later scan that *does* resolve the MAC must update
    // that same record rather than create a duplicate.
    const existing =
      (snapshot.mac ? await this.repo.findByMac(snapshot.mac) : null) ??
      (await this.repo.findByIp(snapshot.ip));
    const stored = existing ? await this.repo.findStoredById(existing.id) : null;

    if (!stored) {
      const fields = this.snapshotFields(snapshot);
      const device: Device = {
        id: uuid(),
        ...fields,
        label: null,
        notes: null,
        routerScrapeUser: null,
        routerScrapePasswordSet: false,
        firstSeen: now,
        lastSeen: now,
        isOnline: true,
        signals: updateBaseline({
          id: 'new',
          ...fields,
          label: null,
          notes: null,
          routerScrapeUser: null,
          routerScrapePasswordSet: false,
          firstSeen: now,
          lastSeen: now,
          isOnline: true,
        } as Device),
      };
      await this.repo.save(device);
      return { device: toPublicDevice(device as StoredDevice), isNew: true, changes: [], anomalies: [] };
    }

    const fields = this.snapshotFields(snapshot);
    const keepClass =
      stored.deviceType !== 'unknown' &&
      stored.classificationConfidence >= fields.classificationConfidence;
    // Never erase a known MAC with null — ARP/ping-only passes often lack L2,
    // and wiping MAC breaks SNMP/Fingerbank/DHCP lookups keyed by address.
    const mac = fields.mac ?? stored.mac;
    const next: StoredDevice = {
      ...stored,
      ...fields,
      mac,
      os: mergeOs(fields.os, stored.os),
      hostname: fields.hostname ?? stored.hostname,
      vendor: fields.vendor ?? stored.vendor,
      brand: fields.brand ?? stored.brand,
      model: fields.model ?? stored.model,
      // Prefer an authoritative connection from either side; don't let unknown wipe wifi/wired.
      connectionType:
        fields.connectionType !== 'unknown' ? fields.connectionType : stored.connectionType,
      deviceType: keepClass ? stored.deviceType : fields.deviceType,
      classificationConfidence: keepClass
        ? stored.classificationConfidence
        : fields.classificationConfidence,
      id: stored.id,
      firstSeen: stored.firstSeen,
      label: stored.label,
      notes: stored.notes,
      routerScrapeUser: stored.routerScrapeUser ?? null,
      routerScrapePassword: stored.routerScrapePassword ?? null,
      lastSeen: now,
      isOnline: true,
    };
    const changes = diffDevice(stored, next);
    const anomalies = detectBehavioralAnomalies(stored, next);
    next.signals = updateBaseline({ ...next, signals: next.signals });
    await this.repo.save(next);
    return { device: toPublicDevice(next), isNew: false, changes, anomalies };
  }

  private snapshotFields(s: DeviceSnapshot) {
    return {
      ip: s.ip,
      mac: s.mac,
      vendor: s.vendor,
      brand: s.brand,
      model: s.model,
      hostname: s.hostname,
      deviceType: s.deviceType,
      classificationConfidence: s.confidence,
      os: s.os,
      connectionType: s.connectionType,
      services: s.services,
      latencyMs: s.latencyMs,
      securityFlags: s.securityFlags,
      signals: s.signals,
    };
  }
}
