import type { Cidr } from '@netscanner/kernel';

/** A single observation about a host emitted by a probe. */
export interface RawHostSignal {
  ip?: string;
  mac?: string;
  hostname?: string;
  latencyMs?: number;
  /** Probe that produced this signal, e.g. 'arp', 'ping', 'mdns', 'ssdp'. */
  source: string;
  /** Probe-specific extras (service types, UPnP descriptors, etc.). */
  extra?: Record<string, unknown>;
}

export interface ProbeContext {
  cidr: Cidr;
  concurrency: number;
  timeoutMs: number;
  signal: AbortSignal;
}

/**
 * Strategy port for host-discovery probes (LSP: all probes are interchangeable).
 * `phase` lets the use case run active sweeps before passive/enrichment probes
 * that depend on their side effects (e.g. ARP cache populated by a ping sweep).
 */
export interface IHostProbe {
  readonly name: string;
  readonly phase: 'sweep' | 'enrich';
  run(ctx: ProbeContext, emit: (signal: RawHostSignal) => void): Promise<void>;
}
