import type { CveFinding } from '@netscanner/contracts';
import { formatCpe, type Cpe } from './cpe.js';

/**
 * Port for a known-vulnerability database (DIP). The bundled StaticCveResolver
 * ships a small curated seed so it works offline out of the box; a real
 * NvdCveResolver (indexed NVD feed) can implement the same interface later.
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

/** Compare dotted numeric versions: -1 / 0 / 1. Non-numeric parts ignored. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[^0-9]+/).filter(Boolean).map(Number);
  const pb = b.split(/[^0-9]+/).filter(Boolean).map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
const lt = (max: string) => (v: string) => compareVersions(v, max) < 0;
const between = (min: string, maxExcl: string) => (v: string) =>
  compareVersions(v, min) >= 0 && compareVersions(v, maxExcl) < 0;

/**
 * Curated starter set of well-known CVEs. Deliberately small and conservative;
 * grow it or swap in a full NVD feed. Findings without a matched version are
 * reported as `fuzzy` ("potentially affected").
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

/** Offline resolver backed by the curated CVE_SEED. */
export class StaticCveResolver implements ICveResolver {
  constructor(private readonly seed: readonly SeedEntry[] = CVE_SEED) {}

  match(cpes: readonly Cpe[]): CveFinding[] {
    const findings: CveFinding[] = [];
    const seen = new Set<string>();
    for (const cpe of cpes) {
      for (const entry of this.seed) {
        if (entry.vendor !== cpe.vendor || entry.product !== cpe.product) continue;

        let confidence: CveFinding['confidence'];
        if (entry.affected) {
          if (cpe.version) {
            if (!entry.affected(cpe.version)) continue; // version known & not affected
            confidence = 'exact';
          } else {
            confidence = 'fuzzy'; // product matches, version unknown → potentially affected
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
