import { XMLParser } from 'fast-xml-parser';
import type { OsGuess, ServiceInfo } from '@netscanner/contracts';
import type { HostFingerprint } from '../domain/deep-scanner.js';

const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });

const asArray = <T>(v: T | T[] | undefined): T[] => (v == null ? [] : Array.isArray(v) ? v : [v]);

function scriptText(script: Record<string, unknown> | undefined): string {
  if (!script) return '';
  const table = script.table;
  if (typeof script['@_output'] === 'string') return script['@_output'];
  if (typeof table === 'string') return table;
  return JSON.stringify(table ?? script);
}

function extractNmapScriptSignals(ports: unknown, hostscripts: unknown): Record<string, unknown> {
  const signals: Record<string, unknown> = {};
  for (const p of asArray<any>(ports)) {
    for (const script of asArray<any>(p.script)) {
      const id: string = script['@_id'] ?? '';
      const out = scriptText(script);
      if (!id || !out) continue;
      if (id === 'ssl-ja3') {
        const ja3 = /ja3=([a-f0-9,]+)/i.exec(out)?.[1];
        if (ja3) signals['ja3Hash'] = ja3;
      }
      if (id === 'ssl-cert') {
        const cn = /Subject:\s*.*?CN=([^,\n/]+)/i.exec(out)?.[1]?.trim();
        if (cn) signals['tlsCertCn'] = cn;
      }
      if (id === 'smb-os-discovery') {
        const os = /OS:\s*(.+)/i.exec(out)?.[1]?.trim();
        const domain = /Domain:\s*(.+)/i.exec(out)?.[1]?.trim();
        if (os) signals['smbOs'] = os;
        if (domain) signals['smbDomain'] = domain;
      }
      if (id === 'smb2-security-mode') signals['smb2Security'] = out.slice(0, 120);
      if (id === 'http-server-header') {
        const h = out.trim().split('\n')[0];
        if (h) signals['httpServer'] = h;
      }
    }
  }
  for (const script of asArray<any>(hostscripts)) {
    const id: string = script['@_id'] ?? '';
    const out = scriptText(script);
    if (id === 'nbstat' && out) signals['netbiosScan'] = out.slice(0, 200);
  }
  return signals;
}

export function parseNmapXml(xml: string): HostFingerprint | null {
  const doc = parser.parse(xml) as Record<string, any>;
  const host = doc?.nmaprun?.host;
  const h = Array.isArray(host) ? host[0] : host;
  if (!h) return null;

  const addresses = asArray<any>(h.address);
  const ipv4 = addresses.find((a) => a['@_addrtype'] === 'ipv4')?.['@_addr'] ?? '';
  const macEntry = addresses.find((a) => a['@_addrtype'] === 'mac');
  const hostname = asArray<any>(h.hostnames?.hostname)[0]?.['@_name'] ?? null;

  const services: ServiceInfo[] = asArray<any>(h.ports?.port).map((p) => {
    const svc = p.service ?? {};
    return {
      port: Number(p['@_portid']),
      protocol: (p['@_protocol'] === 'udp' ? 'udp' : 'tcp') as ServiceInfo['protocol'],
      state: (p.state?.['@_state'] ?? 'open') as ServiceInfo['state'],
      serviceName: svc['@_name'],
      product: svc['@_product'],
      version: svc['@_version'],
      banner: [svc['@_product'], svc['@_version'], svc['@_extrainfo']].filter(Boolean).join(' ') || undefined,
    };
  });

  const osmatch = asArray<any>(h.os?.osmatch).sort(
    (a, b) => Number(b['@_accuracy'] ?? 0) - Number(a['@_accuracy'] ?? 0),
  )[0];
  const osclass = osmatch ? asArray<any>(osmatch.osclass)[0] : undefined;
  const os: OsGuess | null = osmatch
    ? {
        name: osmatch['@_name'],
        family: osclass?.['@_osfamily'],
        version: osclass?.['@_osgen'],
        accuracy: Number(osmatch['@_accuracy'] ?? 0),
        source: 'nmap',
      }
    : null;

  const signals = extractNmapScriptSignals(h.ports?.port, h.hostscript?.script);

  return {
    ip: ipv4,
    services: services.filter((s) => s.state === 'open'),
    os,
    vendorFromScan: macEntry?.['@_vendor'] ?? null,
    hostname,
    source: 'nmap',
    signals: Object.keys(signals).length ? signals : undefined,
  };
}
