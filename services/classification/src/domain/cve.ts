import type { CveFinding } from '@netscanner/contracts';
import { formatCpe, type Cpe } from './cpe.js';
import {
  CVE_INDEX_SEED,
  versionMatchesRange,
  type CveIndexEntry,
} from './cve-index.js';
import { compareVersions } from './cve-index.js';

/** Re-export for existing importers (`from './cve.js'` / tests). */
export { compareVersions };

/**
 * Port for a known-vulnerability database (DIP). The bundled StaticCveResolver
 * ships a curated offline seed; IndexedCveResolver adds a local JSON index and
 * optional NVD subset refresh.
 */
export interface ICveResolver {
  match(cpes: readonly Cpe[]): CveFinding[];
}

interface SeedEntry {
  vendor: string;
  product: string;
  /** Version predicate; when omitted, any version matches (fuzzy). */
  affected?: (version: string) => boolean;
  cveId: string;
  cvss: number;
  severity: CveFinding['severity'];
  summary: string;
}

const lt = (max: string) => (v: string) => compareVersions(v, max) < 0;
const between = (min: string, maxExcl: string) => (v: string) =>
  compareVersions(v, min) >= 0 && compareVersions(v, maxExcl) < 0;

function indexEntryToSeed(e: CveIndexEntry): SeedEntry {
  return {
    vendor: e.vendor,
    product: e.product,
    affected: e.versionRange ? (v) => versionMatchesRange(v, e.versionRange) : undefined,
    cveId: e.cveId,
    cvss: e.cvss,
    severity: e.severity,
    summary: e.summary,
  };
}

/**
 * Small legacy seed kept for focused unit tests. Production default uses the
 * expanded CVE_INDEX_SEED via StaticCveResolver / IndexedCveResolver.
 */
export const CVE_SEED: SeedEntry[] = [
  {
    vendor: 'openbsd',
    product: 'openssh',
    affected: between('8.5', '9.8'),
    cveId: 'CVE-2024-6387',
    cvss: 8.1,
    severity: 'high',
    summary: 'OpenSSH "regreSSHion" — unauthenticated remote code execution (signal handler race).',
  },
  {
    vendor: 'openbsd',
    product: 'openssh',
    affected: lt('9.6'),
    cveId: 'CVE-2023-48795',
    cvss: 5.9,
    severity: 'medium',
    summary: 'OpenSSH "Terrapin" — SSH transport prefix truncation weakens channel integrity.',
  },
  {
    vendor: 'nginx',
    product: 'nginx',
    affected: between('0.6.18', '1.21.0'),
    cveId: 'CVE-2021-23017',
    cvss: 7.7,
    severity: 'high',
    summary: 'nginx resolver off-by-one heap write — potential remote code execution.',
  },
];

/** Offline resolver. Defaults to the expanded index seed. */
export class StaticCveResolver implements ICveResolver {
  private readonly seed: readonly SeedEntry[];

  constructor(seed?: readonly SeedEntry[]) {
    this.seed = seed ?? CVE_INDEX_SEED.map(indexEntryToSeed);
  }

  match(cpes: readonly Cpe[]): CveFinding[] {
    const findings: CveFinding[] = [];
    const seen = new Set<string>();
    for (const cpe of cpes) {
      for (const entry of this.seed) {
        if (entry.vendor !== cpe.vendor || entry.product !== cpe.product) continue;

        let confidence: CveFinding['confidence'];
        if (entry.affected) {
          if (cpe.version) {
            if (!entry.affected(cpe.version)) continue;
            confidence = 'exact';
          } else {
            confidence = 'fuzzy';
          }
        } else {
          confidence = 'fuzzy';
        }

        const key = `${entry.cveId}:${cpe.vendor}:${cpe.product}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          cveId: entry.cveId,
          cvss: entry.cvss,
          severity: entry.severity,
          summary: entry.summary,
          url: `https://nvd.nist.gov/vuln/detail/${entry.cveId}`,
          cpe: formatCpe(cpe),
          confidence,
        });
      }
    }
    return findings;
  }
}
