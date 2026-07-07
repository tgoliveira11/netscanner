import { XMLParser } from 'fast-xml-parser';
import type { OsGuess, ServiceInfo } from '@netscanner/contracts';
import type { HostFingerprint } from '../domain/deep-scanner.js';

const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });

const asArray = <T>(v: T | T[] | undefined): T[] => (v == null ? [] : Array.isArray(v) ? v : [v]);

/**
 * Parses nmap's `-oX` XML into a HostFingerprint. Kept separate from process
 * execution so it can be unit-tested against captured XML fixtures (SRP).
 */
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

  return {
    ip: ipv4,
    services: services.filter((s) => s.state === 'open'),
    os,
    vendorFromScan: macEntry?.['@_vendor'] ?? null,
    hostname,
    source: 'nmap',
  };
}
