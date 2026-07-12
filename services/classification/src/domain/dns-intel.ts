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
  // IoT clouds
  { match: /(^|\.)tuya(eu|us|cn)?\.com$|tuyaus\.com$/i, vendor: 'Tuya', category: 'iot-cloud' },
  { match: /(^|\.)(smart[Ll]ife|airoventures)\./i, vendor: 'Smart Life', category: 'iot-cloud' },
  { match: /(^|\.)(sonoff|coolkit|ewelink)\.(com|cc)$/i, vendor: 'Sonoff/eWeLink', category: 'iot-cloud' },
  { match: /(^|\.)(shelly|allterco)\.(cloud|com)$/i, vendor: 'Shelly', category: 'iot-cloud' },
  { match: /(^|\.)(xiaomi|mi|miio|aqara)\.com$/i, vendor: 'Xiaomi', category: 'iot-cloud' },
  { match: /(^|\.)(home-assistant\.io|nabucasa\.com)$/i, vendor: 'Home Assistant', category: 'smart-home' },
  { match: /(^|\.)(tplink|tp-link|kasa|tapo)\.(com|cloud)$/i, vendor: 'TP-Link', category: 'iot-cloud' },
  { match: /(^|\.)(philips|hue)\.(com|me)$/i, vendor: 'Philips Hue', category: 'smart-home' },
  { match: /(^|\.)(smartthings|samsung)\.com$/i, vendor: 'Samsung', category: 'smart-home' },
  // Cameras / security
  { match: /(^|\.)ring\.com$/i, vendor: 'Ring', category: 'security-cam' },
  { match: /(^|\.)(wyze|hikvision|dahua|reolink|ezvizlife|foscam|amcrest)\.com$/i, category: 'security-cam' },
  { match: /(^|\.)(nest|dropcam)\.com$/i, vendor: 'Google Nest', category: 'smart-home' },
  // ISP / CPE Brazil
  { match: /(^|\.)(vivo|telefonica)\.(com\.br|com)$/i, vendor: 'Vivo', category: 'isp-cpe' },
  { match: /(^|\.)(claro|net|embratel)\.(com\.br|com)$/i, vendor: 'Claro', category: 'isp-cpe' },
  { match: /(^|\.)(compal|cbn)\./i, vendor: 'Compal', category: 'isp-cpe' },
  // Networking vendors
  { match: /(^|\.)(ui\.com|ubnt\.com|unifi-ai\.com)$/i, vendor: 'Ubiquiti', category: 'network-mgmt' },
  { match: /(^|\.)(omada|tp-link)\./i, vendor: 'TP-Link Omada', category: 'network-mgmt' },
  { match: /(^|\.)(pfsense|netgate)\.(com|org)$/i, vendor: 'Netgate', category: 'network-mgmt' },
  // Media / streaming
  { match: /(^|\.)(plex\.tv|plex\.direct)$/i, vendor: 'Plex', category: 'media' },
  { match: /(^|\.)(netflix|nflxvideo|youtube|googlevideo|disney(plus)?|hbomax|primevideo|max\.com)\.(com|net)$/i, category: 'streaming' },
  { match: /(^|\.)spotify\.com$/i, vendor: 'Spotify', category: 'media' },
  { match: /(^|\.)(roku|tiktok|bytedance)\.(com|v)$/i, category: 'streaming' },
  // Voice / assistants
  { match: /(^|\.)sonos\.com$/i, vendor: 'Sonos', category: 'voice-assistant' },
  { match: /(^|\.)(alexa|amazonalexa|avs-alexa|amazon)\.com$/i, vendor: 'Amazon', category: 'voice-assistant' },
  // Big tech
  { match: /(^|\.)(icloud|apple|apple-dns|mzstatic|push\.apple)\.com$/i, vendor: 'Apple', category: 'apple-services' },
  { match: /(^|\.)(googlecast|google|gstatic|googleapis|googleusercontent)\.com$/i, vendor: 'Google', category: 'google-services' },
  { match: /(^|\.)(microsoft|office|outlook|live|xbox)\.com$/i, vendor: 'Microsoft', category: 'microsoft-services' },
  // Gaming
  { match: /(^|\.)(playstation|sony|nintendo|xboxlive|steam|steampowered|epicgames)\.(com|net)$/i, category: 'gaming' },
  // Printers
  { match: /(^|\.)(hp|epson|canon|brother|lexmark)\.(com|net)$/i, category: 'printer' },
  // Ads / trackers (ad networks / pixels — checked before social app frontends)
  { match: /(^|\.)connect\.facebook\.(com|net)$/i, category: 'ads-tracker' },
  { match: /(^|\.)(doubleclick|googlesyndication|google-analytics|scorecardresearch|adnxs|criteo|adsystem|tiktokv)\.(com|net)$/i, category: 'ads-tracker' },
  // Social apps (primary destinations — not ad-network trackers)
  { match: /(^|\.)(facebook|fbcdn|instagram|whatsapp)\.(com|net)$/i, vendor: 'Meta', category: 'social' },
  // Infra
  { match: /(^|\.)(pool\.ntp\.org|time\.(apple|google|windows|nist)\.(com|gov))$/i, category: 'ntp' },
  { match: /(^|\.)(windowsupdate|update\.microsoft|swscan\.apple|swcdn\.apple)\.com$/i, category: 'update' },
  { match: /(^|\.)(akamai|cloudfront|fastly|cloudflare|edgekey|edgesuite)\.(net|com)$/i, category: 'cdn' },
];

/** Reduce a query name to a registrable-ish domain (last two labels). */
export function registrableDomain(fqdn: string): string {
  const parts = fqdn.replace(/\.$/, '').toLowerCase().split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
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

/** Device types for which vendor-cloud phone-home volume is a useful signal. */
const IOT_PHONE_HOME_TYPES = new Set([
  'camera',
  'smart-speaker',
  'smart-home',
  'iot',
]);

/** Security findings from DNS behaviour (privacy / phone-home). */
export function dnsSecurityFlags(
  profile: DnsProfile,
  deviceType?: string | null,
): SecurityFlag[] {
  const flags: SecurityFlag[] = [];
  if (profile.categories.includes('ads-tracker')) {
    flags.push({
      code: 'dns-trackers',
      severity: 'low',
      message: 'Device contacts advertising/tracking domains.',
    });
  }
  // Controllers (phones/Macs with Smart Life etc.) also hit iot-cloud domains —
  // only flag actual IoT endpoints, not the app that manages them.
  const iotCloud = profile.categories.some((c) => c === 'iot-cloud' || c === 'security-cam');
  if (
    iotCloud &&
    profile.externalEndpoints >= 5 &&
    deviceType != null &&
    IOT_PHONE_HOME_TYPES.has(deviceType)
  ) {
    flags.push({
      code: 'iot-phone-home',
      severity: 'info',
      message: `IoT device contacts ${profile.externalEndpoints} external domains (vendor cloud).`,
    });
  }
  return flags;
}
