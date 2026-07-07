import { v4 as uuid } from 'uuid';
import type { ConnectionType, Device, OsGuess, SecurityFlag, ServiceInfo } from '@netscanner/contracts';
import type { IDeviceRepository } from '../domain/device-repository.js';
import { diffDevice } from '../domain/device-diff.js';

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

    if (!existing) {
      const device: Device = {
        id: uuid(),
        ...this.snapshotFields(snapshot),
        label: null,
        notes: null,
        firstSeen: now,
        lastSeen: now,
        isOnline: true,
      };
      await this.repo.save(device);
      return { device, isNew: true, changes: [] };
    }

    const fields = this.snapshotFields(snapshot);
    // Keep the more confident classification so a flaky rescan can't downgrade a
    // well-identified device back to "unknown"/low confidence.
    const keepClass =
      existing.deviceType !== 'unknown' &&
      existing.classificationConfidence >= fields.classificationConfidence;
    const next: Device = {
      ...existing,
      ...fields,
      // Enrichment is sticky: never overwrite good data with null when a later
      // scan fails to re-detect it (OS detection especially is probabilistic).
      os: mergeOs(fields.os, existing.os),
      hostname: fields.hostname ?? existing.hostname,
      vendor: fields.vendor ?? existing.vendor,
      brand: fields.brand ?? existing.brand,
      model: fields.model ?? existing.model,
      deviceType: keepClass ? existing.deviceType : fields.deviceType,
      classificationConfidence: keepClass
        ? existing.classificationConfidence
        : fields.classificationConfidence,
      // Preserve identity and user-owned fields.
      id: existing.id,
      firstSeen: existing.firstSeen,
      label: existing.label,
      notes: existing.notes,
      lastSeen: now,
      isOnline: true,
    };
    const changes = diffDevice(existing, next);
    await this.repo.save(next);
    return { device: next, isNew: false, changes };
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
