import { describe, it, expect } from 'vitest';
import { inferOs, type OsEvidence } from './domain/os-inference.js';

const base: OsEvidence = { services: [], signals: {}, vendor: null, hostname: null };

describe('inferOs', () => {
  it('returns null when there is no usable evidence', () => {
    expect(inferOs(base)).toBeNull();
    expect(inferOs({ ...base, services: [{ port: 80, protocol: 'tcp', state: 'open' }] })).toBeNull();
  });

  it('infers Windows from a Microsoft-IIS Server header', () => {
    const r = inferOs({ ...base, signals: { httpServer: 'Microsoft-IIS/10.0' } });
    expect(r?.os.family).toBe('Windows');
    expect(r?.os.source).toBe('inferred');
    expect(r?.os.accuracy).toBeLessThan(90); // never rivals a real nmap match
  });

  it('infers Linux and captures the distro from an SSH/HTTP banner', () => {
    const r = inferOs({
      ...base,
      services: [{ port: 22, protocol: 'tcp', state: 'open', banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1' }],
    });
    expect(r?.os.family).toBe('Linux');
    expect(r?.os.version).toMatch(/ubuntu/i);
  });

  it('infers FreeBSD from a pfSense TLS certificate subject', () => {
    const r = inferOs({ ...base, signals: { tlsSubject: 'pfSense-5f3a...' } });
    expect(r?.os.family).toBe('FreeBSD');
    expect(r?.os.name).toMatch(/pfSense/i);
  });

  it('distinguishes iOS from macOS by hostname', () => {
    expect(inferOs({ ...base, hostname: 'Johns-iPhone', vendor: 'Apple, Inc.' })?.os.family).toBe('iOS');
    expect(inferOs({ ...base, hostname: 'Marias-MacBook-Pro', vendor: 'Apple, Inc.' })?.os.family).toBe('macOS');
  });

  it('infers embedded OS from the Espressif MAC vendor as a last resort', () => {
    const r = inferOs({ ...base, vendor: 'Espressif Inc.' });
    expect(r?.os.family).toBe('RTOS');
    expect(r?.os.accuracy).toBeLessThanOrEqual(40); // lowest-confidence tier
  });

  it('prefers the highest-accuracy candidate when several match', () => {
    // IIS header (70) should beat the generic SMB+RDP port lean (45/55).
    const r = inferOs({
      ...base,
      signals: { httpServer: 'Microsoft-IIS/10.0' },
      services: [
        { port: 3389, protocol: 'tcp', state: 'open' },
        { port: 445, protocol: 'tcp', state: 'open' },
        { port: 139, protocol: 'tcp', state: 'open' },
      ],
    });
    expect(r?.os.family).toBe('Windows');
    expect(r?.os.accuracy).toBe(70);
  });
});
