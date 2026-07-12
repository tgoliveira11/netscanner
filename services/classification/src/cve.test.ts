import { describe, it, expect } from 'vitest';
import { buildCpes, cpeToken } from './domain/cpe.js';
import { StaticCveResolver, compareVersions } from './domain/cve.js';
import { scoreRisk, cvesToSecurityFlags } from './domain/risk.js';

describe('cpeToken', () => {
  it('normalizes vendor strings', () => {
    expect(cpeToken('Apple, Inc.')).toBe('apple');
    expect(cpeToken('Tuya Smart Inc')).toBe('tuya_smart');
  });
});

describe('buildCpes', () => {
  it('builds OS, hardware and service CPEs', () => {
    const cpes = buildCpes({
      brand: 'Synology',
      model: 'DS920+',
      os: { name: 'Linux', family: 'Linux', version: undefined },
      services: [{ port: 22, protocol: 'tcp', state: 'open', product: 'OpenSSH', version: '9.6' }],
    });
    expect(cpes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ part: 'o', vendor: 'linux', product: 'linux_kernel' }),
        expect.objectContaining({ part: 'h', vendor: 'synology' }),
        expect.objectContaining({ part: 'a', vendor: 'openbsd', product: 'openssh', version: '9.6' }),
      ]),
    );
  });

  it('maps pfSense version onto FreeBSD CPE so ranged FreeBSD CVEs are exact', () => {
    const cpes = buildCpes({
      brand: null,
      model: null,
      os: { name: 'FreeBSD (pfSense/OPNsense)', family: 'FreeBSD', accuracy: 70, source: 'inferred' },
      services: [],
      signals: { pfsenseVersion: '2.8.1-RELEASE' },
    });
    expect(cpes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ part: 'o', vendor: 'freebsd', product: 'freebsd', version: '15.0' }),
        expect.objectContaining({ part: 'a', vendor: 'netgate', product: 'pfsense', version: '2.8.1' }),
      ]),
    );
  });
});

describe('StaticCveResolver', () => {
  const resolver = new StaticCveResolver();

  it('matches OpenSSH regreSSHion for an affected version (exact)', () => {
    const found = resolver.match([{ part: 'a', vendor: 'openbsd', product: 'openssh', version: '9.6' }]);
    const f = found.find((c) => c.cveId === 'CVE-2024-6387');
    expect(f?.confidence).toBe('exact');
    expect(f?.severity).toBe('high');
  });

  it('does not match a patched OpenSSH version', () => {
    const found = resolver.match([{ part: 'a', vendor: 'openbsd', product: 'openssh', version: '9.9' }]);
    expect(found.find((c) => c.cveId === 'CVE-2024-6387')).toBeUndefined();
  });

  it('reports fuzzy when the version is unknown', () => {
    const found = resolver.match([{ part: 'a', vendor: 'nginx', product: 'nginx', version: null }]);
    expect(found.find((c) => c.cveId === 'CVE-2021-23017')?.confidence).toBe('fuzzy');
  });

  it('does not flag CVE-2023-6536 on pfSense 2.8.1 (FreeBSD 15 base)', () => {
    const cpes = buildCpes({
      brand: null,
      model: null,
      os: { name: 'FreeBSD (pfSense/OPNsense)', family: 'FreeBSD', accuracy: 70, source: 'inferred' },
      services: [],
      signals: { pfsenseVersion: '2.8.1-RELEASE' },
    });
    const found = resolver.match(cpes);
    expect(found.find((c) => c.cveId === 'CVE-2023-6536')).toBeUndefined();
  });

  it('still fuzzy-matches CVE-2023-6536 when FreeBSD version is unknown', () => {
    const found = resolver.match([{ part: 'o', vendor: 'freebsd', product: 'freebsd', version: null }]);
    expect(found.find((c) => c.cveId === 'CVE-2023-6536')?.confidence).toBe('fuzzy');
  });
});

describe('compareVersions', () => {
  it('orders dotted versions', () => {
    expect(compareVersions('8.4', '9.6')).toBe(-1);
    expect(compareVersions('1.21.0', '1.21.0')).toBe(0);
    expect(compareVersions('9.9', '9.8')).toBe(1);
  });
});

describe('scoreRisk', () => {
  it('weights exact CVEs, halves fuzzy, and folds high CVEs into flags', () => {
    const exact = [{ cveId: 'CVE-x', cvss: 8.1, severity: 'high' as const, summary: 's', url: 'u', cpe: 'c', confidence: 'exact' as const }];
    const fuzzy = [{ ...exact[0]!, confidence: 'fuzzy' as const }];
    expect(scoreRisk(exact, [])).toBe(25);
    expect(scoreRisk(fuzzy, [])).toBe(13); // 12.5 rounded
    expect(cvesToSecurityFlags(exact)).toHaveLength(1);
  });
});
