import type { DiscoveredHost } from '@netscanner/contracts';
import type { RawHostSignal } from './host-probe.js';

/**
 * Merges raw signals from multiple probes into a single DiscoveredHost per IP.
 * Later signals enrich earlier ones without overwriting good data with nulls.
 * Pure domain logic — no I/O — so it is trivially unit-testable.
 */
export class HostAggregator {
  private readonly byIp = new Map<string, DiscoveredHost>();

  /** Returns the merged host if this signal created or changed a record. */
  ingest(signal: RawHostSignal): DiscoveredHost | null {
    const ip = signal.ip;
    if (!ip) return null;

    const existing = this.byIp.get(ip);
    const base: DiscoveredHost = existing ?? {
      ip,
      mac: null,
      hostname: null,
      latencyMs: null,
      sources: [],
      signals: {},
    };

    const before = JSON.stringify(base);

    const next: DiscoveredHost = {
      ip,
      mac: signal.mac ?? base.mac,
      hostname: signal.hostname ?? base.hostname,
      latencyMs: signal.latencyMs ?? base.latencyMs,
      sources: base.sources.includes(signal.source)
        ? base.sources
        : [...base.sources, signal.source],
      signals: { ...base.signals, ...(signal.extra ?? {}) },
    };

    this.byIp.set(ip, next);
    return JSON.stringify(next) === before ? null : next;
  }

  all(): DiscoveredHost[] {
    return [...this.byIp.values()];
  }
}
