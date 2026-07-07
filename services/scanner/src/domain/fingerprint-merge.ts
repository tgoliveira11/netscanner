import type { OsGuess, ServiceInfo } from '@netscanner/contracts';
import type { HostFingerprint } from './deep-scanner.js';

/**
 * Merge multiple fingerprints of the same host into one. Services are unioned
 * (keyed by protocol/port, richer entry wins); the OS guess with the highest
 * accuracy is kept. Pure function — unit-testable in isolation.
 */
export function mergeFingerprints(ip: string, parts: HostFingerprint[]): HostFingerprint {
  const services = new Map<string, ServiceInfo>();
  for (const part of parts) {
    for (const svc of part.services) {
      const key = `${svc.protocol}/${svc.port}`;
      const existing = services.get(key);
      services.set(key, existing ? preferRicher(existing, svc) : svc);
    }
  }

  const os = parts
    .map((p) => p.os)
    .filter((o): o is OsGuess => Boolean(o))
    .sort((a, b) => (b.accuracy ?? 0) - (a.accuracy ?? 0))[0] ?? null;

  return {
    ip,
    services: [...services.values()].sort((a, b) => a.port - b.port),
    os,
    vendorFromScan: parts.map((p) => p.vendorFromScan).find(Boolean) ?? null,
    hostname: parts.map((p) => p.hostname).find(Boolean) ?? null,
    source: parts.map((p) => p.source).join('+'),
  };
}

function score(s: ServiceInfo): number {
  return (s.product ? 2 : 0) + (s.version ? 2 : 0) + (s.serviceName ? 1 : 0) + (s.banner ? 1 : 0);
}

function preferRicher(a: ServiceInfo, b: ServiceInfo): ServiceInfo {
  return score(b) > score(a) ? b : a;
}
