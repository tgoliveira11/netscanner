import type { DeviceType, OsGuess, ServiceInfo } from '@netscanner/contracts';

/** All evidence a rule may inspect about a host. */
export interface ClassificationInput {
  ip: string;
  mac: string | null;
  vendor: string | null;
  hostname: string | null;
  os: OsGuess | null;
  services: ServiceInfo[];
  /** Gateway IP for this subnet, if known (enables router detection). */
  gatewayIp?: string | null;
  /** Merged discovery signals (mDNS/SSDP/etc.). */
  signals: Record<string, unknown>;
}

/** A weighted vote for a device type with a human-readable justification. */
export interface RuleVerdict {
  deviceType: DeviceType;
  /** Vote strength in [0,1]; the engine sums and normalizes these. */
  weight: number;
  reason: string;
}

/**
 * Strategy contract for a classification heuristic (OCP: add device categories
 * by adding a rule, never by editing the engine). A rule returns zero or more
 * weighted verdicts.
 */
export interface ClassificationRule {
  readonly name: string;
  evaluate(input: ClassificationInput): RuleVerdict[];
}
