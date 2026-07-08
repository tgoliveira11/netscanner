import type { CveFinding, SecurityFlag } from '@netscanner/contracts';

const CVE_WEIGHT: Record<CveFinding['severity'], number> = {
  critical: 40,
  high: 25,
  medium: 12,
  low: 5,
};
const FLAG_WEIGHT: Record<SecurityFlag['severity'], number> = {
  high: 15,
  medium: 8,
  low: 3,
  info: 1,
};

/**
 * Aggregate a device's exposure into a 0–100 risk score from matched CVEs and
 * security flags. Fuzzy CVE matches count at half weight (uncertain). Pure.
 */
export function scoreRisk(cves: readonly CveFinding[], flags: readonly SecurityFlag[]): number {
  let score = 0;
  for (const c of cves) score += CVE_WEIGHT[c.severity] * (c.confidence === 'exact' ? 1 : 0.5);
  for (const f of flags) score += FLAG_WEIGHT[f.severity];
  return Math.min(100, Math.round(score));
}

/** Surface high-impact CVEs into the existing SecurityFlag channel for the UI. */
export function cvesToSecurityFlags(cves: readonly CveFinding[]): SecurityFlag[] {
  return cves
    .filter((c) => c.severity === 'high' || c.severity === 'critical')
    .map((c) => ({
      code: c.cveId.toLowerCase(),
      severity: 'high' as const,
      message: `${c.cveId} (CVSS ${c.cvss ?? '?'}${c.confidence === 'fuzzy' ? ', potential' : ''}): ${c.summary}`,
    }));
}
