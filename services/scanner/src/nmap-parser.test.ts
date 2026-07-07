import { describe, it, expect } from 'vitest';
import { parseNmapXml } from './infrastructure/nmap-xml.parser.js';
import { mergeFingerprints } from './domain/fingerprint-merge.js';

const NMAP_XML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:11:22:33" addrtype="mac" vendor="Synology"/>
    <hostnames><hostname name="nas.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.4"/></port>
      <port protocol="tcp" portid="5000"><state state="open"/><service name="http" product="nginx"/></port>
      <port protocol="tcp" portid="9999"><state state="closed"/><service name="x"/></port>
    </ports>
    <os>
      <osmatch name="Linux 5.x" accuracy="96"><osclass osfamily="Linux" osgen="5.X"/></osmatch>
      <osmatch name="Linux 4.x" accuracy="90"/>
    </os>
  </host>
</nmaprun>`;

describe('parseNmapXml', () => {
  it('extracts ip, mac vendor, hostname, open services and best OS match', () => {
    const fp = parseNmapXml(NMAP_XML);
    expect(fp).not.toBeNull();
    expect(fp!.ip).toBe('192.168.1.10');
    expect(fp!.vendorFromScan).toBe('Synology');
    expect(fp!.hostname).toBe('nas.local');
    expect(fp!.services.map((s) => s.port)).toEqual([22, 5000]); // closed port dropped
    expect(fp!.os?.family).toBe('Linux');
    expect(fp!.os?.accuracy).toBe(96); // highest-accuracy match wins
  });

  it('returns null for empty output', () => {
    expect(parseNmapXml('<nmaprun></nmaprun>')).toBeNull();
  });
});

describe('mergeFingerprints', () => {
  it('unions services and keeps the richer entry per port', () => {
    const merged = mergeFingerprints('192.168.1.10', [
      {
        ip: '192.168.1.10',
        services: [{ port: 80, protocol: 'tcp', state: 'open' }],
        os: null,
        vendorFromScan: null,
        hostname: null,
        source: 'tcp-connect',
      },
      {
        ip: '192.168.1.10',
        services: [{ port: 80, protocol: 'tcp', state: 'open', product: 'nginx', version: '1.25' }],
        os: { name: 'Linux', accuracy: 90 },
        vendorFromScan: 'Synology',
        hostname: 'nas.local',
        source: 'nmap',
      },
    ]);
    expect(merged.services).toHaveLength(1);
    expect(merged.services[0]?.product).toBe('nginx');
    expect(merged.os?.accuracy).toBe(90);
    expect(merged.source).toBe('tcp-connect+nmap');
  });
});
