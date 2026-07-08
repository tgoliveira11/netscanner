import { describe, expect, it } from 'vitest';
import type { AppConfig } from '@netscanner/config';
import type { NetworkFingerprint, NetworkSite } from '@netscanner/contracts';
import { rankSiteMatches } from './domain/site-matcher.js';

const config = {
  SITE_MATCH_THRESHOLD: 0.85,
  SITE_AMBIGUOUS_THRESHOLD: 0.6,
  SITE_VPN_IGNORE_GEO: true,
} as AppConfig;

function site(id: string, fp: Partial<NetworkFingerprint>, name = id): NetworkSite {
  const now = new Date().toISOString();
  return {
    id,
    name,
    slug: id,
    createdAt: now,
    lastSeenAt: now,
    fingerprint: {
      gatewayIp: null,
      gatewayMac: null,
      cidrs: [],
      dnsServers: [],
      routerId: null,
      publicIp: null,
      geoLat: null,
      geoLon: null,
      geoLabel: null,
      ssids: [],
      vpnDetected: false,
      ...fp,
    },
    integrations: {},
    isDefault: false,
  };
}

describe('rankSiteMatches', () => {
  it('matches home by gateway MAC and CIDR', () => {
    const obs: NetworkFingerprint = {
      gatewayIp: '10.0.51.1',
      gatewayMac: 'aa:bb:cc:dd:ee:01',
      cidrs: ['10.0.51.0/24'],
      dnsServers: ['10.0.51.1'],
      routerId: 'pfsense-lab',
      publicIp: null,
      geoLat: null,
      geoLon: null,
      geoLabel: null,
      ssids: ['HomeWiFi'],
      vpnDetected: false,
    };
    const home = site('home', {
      gatewayIp: '10.0.51.1',
      gatewayMac: 'aa:bb:cc:dd:ee:01',
      cidrs: ['10.0.51.0/24'],
      routerId: 'pfsense-lab',
      ssids: ['HomeWiFi'],
    });
    const hotel = site('hotel', {
      gatewayIp: '192.168.0.1',
      gatewayMac: '11:22:33:44:55:66',
      cidrs: ['192.168.0.0/24'],
    });
    const ranked = rankSiteMatches(obs, [hotel, home], config);
    expect(ranked[0]?.site.id).toBe('home');
    expect(ranked[0]?.score).toBeGreaterThan(0.85);
  });

  it('ignores geo when VPN is detected', () => {
    const obs: NetworkFingerprint = {
      gatewayIp: '10.0.51.1',
      gatewayMac: 'aa:bb:cc:dd:ee:01',
      cidrs: ['10.0.51.0/24'],
      dnsServers: [],
      routerId: 'pfsense-lab',
      publicIp: '203.0.113.9',
      geoLat: -23.5,
      geoLon: -46.6,
      geoLabel: 'São Paulo',
      ssids: [],
      vpnDetected: true,
    };
    const home = site('home', {
      gatewayIp: '10.0.51.1',
      gatewayMac: 'aa:bb:cc:dd:ee:01',
      cidrs: ['10.0.51.0/24'],
      routerId: 'pfsense-lab',
      geoLat: -22.9,
      geoLon: -43.2,
      geoLabel: 'Rio',
    });
    const ranked = rankSiteMatches(obs, [home], { ...config, SITE_VPN_IGNORE_GEO: true });
    expect(ranked[0]?.score).toBeGreaterThan(0.8);
  });
});
