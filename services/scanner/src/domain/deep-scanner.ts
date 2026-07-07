import type { OsGuess, ServiceInfo } from '@netscanner/contracts';

export type ScanDepth = 'quick' | 'standard' | 'deep';

export interface ScanTarget {
  ip: string;
  depth: ScanDepth;
  /** Attempt OS detection (nmap -O). Ignored by adapters that can't do it. */
  osDetection: boolean;
  timeoutMs: number;
}

/** Result of fingerprinting a single host. */
export interface HostFingerprint {
  ip: string;
  services: ServiceInfo[];
  os: OsGuess | null;
  vendorFromScan: string | null;
  hostname: string | null;
  /** Which adapter produced this fingerprint (for auditing/merge priority). */
  source: string;
}

/**
 * Strategy port for deep host fingerprinting (LSP). Implementations: nmap
 * (rich) and a pure-Node TCP-connect fallback. The use case merges any number
 * of these, so adapters are added without modification (OCP/DIP).
 */
export interface IDeepScanner {
  readonly name: string;
  /** Whether this scanner is usable in the current environment. */
  isAvailable(): Promise<boolean>;
  scan(target: ScanTarget): Promise<HostFingerprint>;
}
