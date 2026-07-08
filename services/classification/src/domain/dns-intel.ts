import type { DnsProfile, SecurityFlag } from '@netscanner/contracts';

/** Domain pattern → vendor / service / category. Extend freely (OCP). */
interface CatalogEntry {
  match: RegExp;
  vendor?: string;
  category: string;
}

/**
 * Curated catalogue mapping the domains devices "phone home" to onto a vendor
 * and a behavioural category. Seed set covers common IoT clouds, cameras, media,
 * voice assistants, trackers/ads and infrastructure. Mirrors the OUI approach:
 * a starter table you grow over time.
 */
export const DOMAIN_CATALOG: CatalogEntry[] = [
  { match: /(^|\.)tuya(eu|us|cn)?\.com$|tuyaus\.com$/i, vendor: 'Tuya', category: 'iot-cloud' },
  { match: /(^|\.)(sonoff|coolkit|ewelink)\.(com|cc)$/i, vendor: 'Sonoff/eWeLink', category: 'iot-cloud' },
  { match: /(^|\.)(shelly|allterco)\.(cloud|com)$/i, vendor: 'Shelly', category: 'iot-cloud' },
  { match: /(^|\.)(xiaomi|mi|miio|aqara)\.com$/i, vendor: 'Xiaomi', category: 'iot-cloud' },
  { match: /(^|\.)ring\.com$/i, vendor: 'Ring', category: 'security-cam' },
  { match: /(^|\.)(wyze|hikvision|dahua|reolink|ezvizlife|foscam)\.com$/i, category: 'security-cam' },
  { match: /(^|\.)(nest|dropcam)\.com$/i, vendor: 'Google Nest', category: 'smart-home' },
  { match: /(^|\.)(plex\.tv|plex\.direct)$/i, vendor: 'Plex', category: 'media' },
  { match: /(^|\.)(netflix|nflxvideo|youtube|googlevideo|disney(plus)?|hbomax|primevideo)\.(com|net)$/i, category: 'streaming' },
  { match: /(^|\.)spotify\.com$/i, vendor: 'Spotify', category: 'media' },
  { match: /(^|\.)sonos\.com$/i, vendor: 'Sonos', category: 'voice-assistant' },
  { match: /(^|\.)(alexa|amazonalexa|avs-alexa|amazon)\.com$/i, vendor: 'Amazon', category: 'voice-assistant' },
  { match: /(^|\.)(icloud|apple|apple-dns|mzstatic|push\.apple)\.com$/i, vendor: 'Apple', category: 'apple-services' },
  { match: /(^|\.)(googlecast|google|gstatic|googleapis|googleusercontent)\.com$/i, vendor: 'Google', category: 'google-services' },
  { match: /(^|\.)(doubleclick|googlesyndication|google-analytics|scorecardresearch|adnxs|criteo|adsystem)\.(com|net)$/i, category: 'ads-tracker' },
  { match: /(^|\.)(pool\.ntp\.org|time\.(apple|google|windows|nist)\.(com|gov))$/i, category: 'ntp' },
  { match: /(^|\.)(windowsupdate|update\.microsoft|swscan\.apple|swcdn\.apple)\.com$/i, category: 'update' },
  { match: /(^|\.)(akamai|cloudfront|fastly|cloudflare|edgekey|edgesuite)\.(net|com)$/i, category: 'cdn' },
];

/** Reduce a query name to a registrable-ish domain (last two labels). */
export function registrableDomain(fqdn: string): string {
  const parts = fqdn.replace(/\.$/, '').toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  // Handle a few common 2-level public suffixes (co.uk, com.br…).
  const twoLevel = /^(co|com|net|org|gov|edu|ac)\.[a-z]{2}$/;
  const tail2 = parts.slice(-2).join('.');
  return twoLevel.test(tail2) ? parts.slice(-3).join('.') : tail2;
}

function lookup(domain: string): CatalogEntry | undefined {
  return DOMAIN_CATALOG.find((e) => e.match.test(domain));
}

/**
 * Aggregate a device's observed DNS queries into an activity profile: the top
 * registrable domains (with vendor/category), the set of categories, and how
 * many distinct external domains it contacts. Pure & deterministic.
 */
export function analyzeDns(queries: readonly string[], topN = 8): DnsProfile {
  const counts = new Map<string, number>();
  const categories = new Set<string>();
  for (const q of queries) {
    if (!q) continue;
    const reg = registrableDomain(q);
    if (!reg) continue;
    counts.set(reg, (counts.get(reg) ?? 0) + 1);
    const cat = lookup(q) ?? lookup(reg);
    if (cat) categories.add(cat.category);
  }
  const topDomains = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN)
    .map(([domain, count]) => {
      const entry = lookup(domain);
      return { domain, count, category: entry?.category, vendor: entry?.vendor };
    });
  return { topDomains, categories: [...categories], externalEndpoints: counts.size };
}

/** Vendor hints (for classification) derived from a DNS profile. */
export function dnsVendorHints(profile: DnsProfile): string[] {
  return [...new Set(profile.topDomains.map((d) => d.vendor).filter((v): v is string => !!v))];
}

/** Security findings from DNS behaviour (privacy / phone-home). */
export function dnsSecurityFlags(profile: DnsProfile): SecurityFlag[] {
  const flags: SecurityFlag[] = [];
  if (profile.categories.includes('ads-tracker')) {
    flags.push({
      code: 'dns-trackers',
      severity: 'low',
      message: 'Device contacts advertising/tracking domains.',
    });
  }
  const iotCloud = profile.categories.some((c) => c === 'iot-cloud' || c === 'security-cam');
  if (iotCloud && profile.externalEndpoints >= 8) {
    flags.push({
      code: 'iot-phone-home',
      severity: 'info',
      message: `IoT device contacts ${profile.externalEndpoints} external domains (vendor cloud).`,
    });
  }
  return flags;
}
