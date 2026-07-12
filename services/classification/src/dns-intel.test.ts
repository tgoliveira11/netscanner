import { describe, it, expect } from 'vitest';
import { analyzeDns, registrableDomain, dnsVendorHints, dnsSecurityFlags } from './domain/dns-intel.js';
import { DnsClassificationRule } from './domain/rules/dns.rule.js';

describe('registrableDomain', () => {
  it('reduces FQDNs to registrable domain', () => {
    expect(registrableDomain('a1.tuyaus.com')).toBe('tuyaus.com');
    expect(registrableDomain('device.api.ring.com')).toBe('ring.com');
    expect(registrableDomain('foo.example.co.uk')).toBe('example.co.uk');
  });
});

describe('analyzeDns', () => {
  it('categorizes and ranks queried domains', () => {
    const profile = analyzeDns([
      'a1.tuyaus.com',
      'a2.tuyaus.com',
      'device.ring.com',
      'weird.example.net',
    ]);
    const tuya = profile.topDomains.find((d) => d.domain === 'tuyaus.com');
    expect(tuya?.count).toBe(2);
    expect(tuya?.vendor).toBe('Tuya');
    expect(profile.categories).toEqual(expect.arrayContaining(['iot-cloud', 'security-cam']));
    expect(profile.externalEndpoints).toBe(3);
    expect(dnsVendorHints(profile)).toContain('Tuya');
  });

  it('categorizes Claro/Vivo CPE and Smart Life domains', () => {
    const profile = analyzeDns([
      'acs.claro.com.br',
      'cwmp.vivo.com.br',
      'a1.tuyaus.com',
      'device.smartlife.iot',
    ]);
    expect(profile.categories).toEqual(
      expect.arrayContaining(['isp-cpe', 'iot-cloud']),
    );
  });

  it('raises an info flag for IoT devices contacting many endpoints', () => {
    const domains = ['x.tuyaus.com', ...Array.from({ length: 9 }, (_, i) => `h${i}.example${i}.com`)];
    const flags = dnsSecurityFlags(analyzeDns(domains), 'iot');
    expect(flags.some((f) => f.code === 'iot-phone-home')).toBe(true);
  });

  it('does not raise iot-phone-home for phones/computers that hit Tuya (controller apps)', () => {
    const domains = ['a1.tuya.com', ...Array.from({ length: 9 }, (_, i) => `h${i}.example${i}.com`)];
    const profile = analyzeDns(domains);
    expect(dnsSecurityFlags(profile, 'phone').some((f) => f.code === 'iot-phone-home')).toBe(false);
    expect(dnsSecurityFlags(profile, 'computer').some((f) => f.code === 'iot-phone-home')).toBe(false);
    expect(dnsSecurityFlags(profile).some((f) => f.code === 'iot-phone-home')).toBe(false);
  });

  it('does not treat facebook.com as ads-tracker (normal app use)', () => {
    const profile = analyzeDns(['graph.facebook.com', 'scontent.xx.fbcdn.net', 'www.instagram.com']);
    expect(profile.categories).toContain('social');
    expect(profile.categories).not.toContain('ads-tracker');
    expect(dnsSecurityFlags(profile).some((f) => f.code === 'dns-trackers')).toBe(false);
  });

  it('still flags real ad-network / pixel domains', () => {
    const profile = analyzeDns(['pagead2.googlesyndication.com', 'connect.facebook.net']);
    expect(profile.categories).toContain('ads-tracker');
    expect(dnsSecurityFlags(profile).some((f) => f.code === 'dns-trackers')).toBe(true);
  });
});

describe('DnsClassificationRule', () => {
  const base = { ip: '192.168.1.9', mac: null, vendor: null, hostname: null, os: null, services: [] };

  it('votes camera from security-cam DNS activity', () => {
    const v = new DnsClassificationRule().evaluate({ ...base, signals: { dnsCategories: ['security-cam'] } });
    expect(v[0]?.deviceType).toBe('camera');
  });

  it('is silent without DNS categories', () => {
    expect(new DnsClassificationRule().evaluate({ ...base, signals: {} })).toEqual([]);
  });
});
