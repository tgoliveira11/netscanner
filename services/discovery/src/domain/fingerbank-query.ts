import type { FingerprintQuery } from '../domain/fingerprint-resolver.js';

/** Build Fingerbank API payload from DHCP + passive signals (not only DHCP renew). */
export function buildFingerbankQuery(
  mac: string | null,
  hostname: string | null,
  signals: Record<string, unknown>,
  dhcp?: { fingerprint?: string; vendorClass?: string | null },
): FingerprintQuery {
  const q: FingerprintQuery = {
    mac,
    hostname,
    dhcpFingerprint: dhcp?.fingerprint ?? readStr(signals, 'dhcpFingerprint'),
    dhcpVendor: dhcp?.vendorClass ?? readStr(signals, 'dhcpVendorClass'),
    userAgents: [],
  };

  const mdnsModel = readStr(signals, 'mdnsModel') ?? readStr(signals, 'mdnsAppleModel');
  if (mdnsModel) q.userAgents!.push(`mdns-model:${mdnsModel}`);
  const httpServer = readStr(signals, 'httpServer');
  if (httpServer) q.userAgents!.push(httpServer);
  const ja3 = readStr(signals, 'ja3Hash');
  if (ja3) q.userAgents!.push(`ja3:${ja3}`);
  const osx = readStr(signals, 'mdnsOsVersion');
  if (osx) q.userAgents!.push(`osxvers:${osx}`);
  if (signals['mqttOpen']) q.userAgents!.push('mqtt-client');
  if (signals['coapOpen']) q.userAgents!.push('coap-client');

  const dhcpv6 = readStr(signals, 'ipv6Duid');
  if (dhcpv6) q.dhcpv6Fingerprint = dhcpv6;

  if (!q.userAgents!.length) delete q.userAgents;
  return q;
}

function readStr(signals: Record<string, unknown>, key: string): string | undefined {
  const v = signals[key];
  return typeof v === 'string' && v ? v : undefined;
}
