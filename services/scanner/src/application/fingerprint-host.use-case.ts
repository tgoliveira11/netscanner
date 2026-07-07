import type { Logger } from '@netscanner/logger';
import type { HostFingerprint, IDeepScanner, ScanTarget } from '../domain/deep-scanner.js';
import { mergeFingerprints } from '../domain/fingerprint-merge.js';

/**
 * Fingerprints a host by running every available scanner and merging results.
 * With nmap present it yields deep OS/service data; without it, the TCP fallback
 * still returns open ports — graceful degradation, no configuration branches
 * leaking into callers.
 */
export class FingerprintHostUseCase {
  constructor(
    private readonly scanners: readonly IDeepScanner[],
    private readonly logger: Logger,
  ) {}

  async execute(target: ScanTarget): Promise<HostFingerprint> {
    const usable: IDeepScanner[] = [];
    for (const scanner of this.scanners) {
      if (await scanner.isAvailable()) usable.push(scanner);
    }

    const results = await Promise.allSettled(usable.map((s) => s.scan(target)));
    const parts: HostFingerprint[] = [];
    for (const r of results) {
      if (r.status === 'fulfilled') parts.push(r.value);
      else this.logger.warn({ ip: target.ip, error: r.reason }, 'scanner failed');
    }

    if (parts.length === 0) {
      return {
        ip: target.ip,
        services: [],
        os: null,
        vendorFromScan: null,
        hostname: null,
        source: 'none',
      };
    }
    return mergeFingerprints(target.ip, parts);
  }
}
