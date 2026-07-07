import type { OsGuess, ServiceInfo } from '@netscanner/contracts';

/** Evidence an OS guess can be derived from when nmap -O produced nothing. */
export interface OsEvidence {
  services: readonly ServiceInfo[];
  signals: Record<string, unknown>;
  vendor: string | null;
  hostname: string | null;
}

export interface InferredOs {
  os: OsGuess;
  /** Human-readable justification, surfaced in the device's classification reasons. */
  reason: string;
}

interface Candidate {
  family: string;
  name: string;
  version?: string;
  /** Deliberately capped below nmap's typical 90+ so a real match always wins. */
  accuracy: number;
  reason: string;
}

/** Application-layer signal keys the enricher populates (see NetworkEnricher). */
const BANNER_SIGNAL_KEYS = [
  'httpServer',
  'httpTitle',
  'tlsSubject',
  'tlsIssuer',
  'upnpManufacturer',
  'upnpModel',
  'upnpFriendlyName',
  'upnpDeviceType',
  'dhcpVendorClass',
  'mdnsType',
  'ssdpServer',
  'ssdpSt',
  'netbiosName',
  'netbiosOs',
  'llmnrName',
  'snmpSysDescr',
  'snmpSysName',
  'lldpSystemName',
  'lldpChassis',
] as const;

function readSignal(signals: Record<string, unknown>, key: string): string {
  const v = signals[key];
  return typeof v === 'string' ? v : '';
}

/**
 * Best-effort OS inference from passively-collected evidence (service banners,
 * application-layer strings, characteristic ports, MAC vendor, hostname). This
 * fills the OS field only when active fingerprinting (nmap -O) yielded nothing —
 * common on firewalled hosts that never expose the open+closed port pair nmap
 * needs. Every candidate carries a modest, honest accuracy and `source:'inferred'`.
 *
 * Pure and deterministic: collects all matching candidates and returns the
 * highest-accuracy one (ties resolved by declaration order). Kept conservative
 * on purpose — a wrong OS is worse than none, and it also feeds the OS→type rule.
 */
export function inferOs(evidence: OsEvidence): InferredOs | null {
  const { services, signals, vendor, hostname } = evidence;

  const serviceBanners = services
    .map((s) => [s.serviceName, s.product, s.version, s.banner].filter(Boolean).join(' '))
    .join(' | ');
  const appLayer = BANNER_SIGNAL_KEYS.map((k) => readSignal(signals, k)).join(' | ');
  const httpServer = readSignal(signals, 'httpServer');
  // Banner/string haystack for token matching; vendor + hostname included last.
  const text = [serviceBanners, appLayer, vendor ?? '', hostname ?? ''].join(' | ');
  const host = hostname ?? '';
  const openPorts = new Set(services.filter((s) => s.state === 'open').map((s) => s.port));

  const candidates: Candidate[] = [];
  const add = (c: Candidate | null): void => {
    if (c) candidates.push(c);
  };

  // --- Windows: HTTP/IIS header, Windows OpenSSH, RDP/SMB ports ---------------
  if (/microsoft-iis/i.test(httpServer))
    add({ family: 'Windows', name: 'Windows', accuracy: 70, reason: 'HTTP Server header "Microsoft-IIS"' });
  if (/openssh[_ ]for[_ ]windows/i.test(text))
    add({ family: 'Windows', name: 'Windows', accuracy: 70, reason: 'SSH banner "OpenSSH for Windows"' });
  if (openPorts.has(3389))
    add({ family: 'Windows', name: 'Windows', accuracy: 55, reason: 'RDP (tcp/3389) open' });
  if (openPorts.has(445) && openPorts.has(139))
    add({ family: 'Windows', name: 'Windows', accuracy: 45, reason: 'SMB + NetBIOS (tcp/445+139) open' });
  if (/desktop-|-pc\b|\bwin(dows)?[\s-]?(10|11|server)/i.test(host))
    add({ family: 'Windows', name: 'Windows', accuracy: 45, reason: `Windows-style hostname "${host}"` });

  // --- Linux: distro tokens in Server header / SSH banner ---------------------
  const distro = /(ubuntu|debian|centos|red\s?hat|fedora|alpine|raspbian|gentoo|arch|suse)/i.exec(text);
  if (distro)
    add({
      family: 'Linux',
      name: 'Linux',
      version: distro[1],
      accuracy: 65,
      reason: `banner mentions "${distro[1]}"`,
    });
  else if (/\blinux\b|unix\b/i.test(text))
    add({ family: 'Linux', name: 'Linux', accuracy: 50, reason: 'banner mentions "Linux/Unix"' });

  // --- Router / appliance OSes ------------------------------------------------
  if (/openwrt|lede\b/i.test(text))
    add({ family: 'Linux', name: 'OpenWrt', accuracy: 70, reason: 'banner mentions "OpenWrt"' });
  if (/routeros|mikrotik/i.test(text))
    add({ family: 'RouterOS', name: 'MikroTik RouterOS', accuracy: 70, reason: 'banner mentions "RouterOS/MikroTik"' });
  if (/edgeos|edgerouter/i.test(text))
    add({ family: 'Linux', name: 'EdgeOS', accuracy: 65, reason: 'banner mentions "EdgeOS"' });
  if (/pfsense|opnsense/i.test(text))
    add({ family: 'FreeBSD', name: 'FreeBSD (pfSense/OPNsense)', accuracy: 70, reason: 'banner mentions "pfSense/OPNsense"' });
  if (/free\s?bsd/i.test(text))
    add({ family: 'FreeBSD', name: 'FreeBSD', accuracy: 60, reason: 'banner mentions "FreeBSD"' });
  if (/junos|juniper/i.test(text))
    add({ family: 'JunOS', name: 'Juniper JunOS', accuracy: 65, reason: 'banner mentions "JunOS/Juniper"' });

  // --- Apple: watchOS vs iOS vs macOS from hostname/ports/vendor --------------
  const isApple = /apple/i.test(vendor ?? '');
  const mdnsType = readSignal(signals, 'mdnsType');
  if (/\bwatch\b|apple[\s-]?watch/i.test(host))
    add({ family: 'watchOS', name: 'watchOS', accuracy: 55, reason: `Apple Watch hostname "${host}"` });
  else if (/iphone|ipad|ios\b/i.test(host) || openPorts.has(62078))
    add({ family: 'iOS', name: 'iOS/iPadOS', accuracy: 55, reason: openPorts.has(62078) ? 'iOS lockdownd (tcp/62078) open' : `iOS-style hostname "${host}"` });
  else if (/macbook|\bmbp\b|\bmba\b|imac|mac-?mini|mac-?pro|\bmac\b/i.test(host) || (isApple && openPorts.has(548)))
    add({ family: 'macOS', name: 'macOS', accuracy: 55, reason: openPorts.has(548) ? 'Apple vendor + AFP (tcp/548) open' : `macOS-style hostname "${host}"` });
  else if (/hometheater|appletv|apple-tv/i.test(host) && isApple)
    add({ family: 'tvOS', name: 'tvOS', accuracy: 58, reason: `Apple TV hostname "${host}"` });
  else if (mdnsType === 'raop' && isApple)
    add({ family: 'macOS', name: 'macOS', accuracy: 48, reason: 'RAOP/AirTunes mDNS (Apple)' });

  // --- Android ----------------------------------------------------------------
  if (/android|pixel|galaxy|oneplus|redmi|xiaomi/i.test(host))
    add({ family: 'Android', name: 'Android', accuracy: 50, reason: `Android-style hostname "${host}"` });

  // --- Embedded / IoT from vendor (last resort, low confidence) ---------------
  if (/espressif/i.test(vendor ?? ''))
    add({ family: 'RTOS', name: 'Embedded (ESP/FreeRTOS)', accuracy: 40, reason: 'MAC vendor Espressif (ESP32/ESP8266)' });
  else if (/tuya/i.test(vendor ?? ''))
    add({ family: 'Linux', name: 'Embedded Linux (Tuya)', accuracy: 40, reason: 'MAC vendor Tuya' });
  else if (/compal|arcadyan|technicolor|sagemcom|zte|huawei/i.test(vendor ?? '') && openPorts.has(80))
    add({ family: 'Linux', name: 'Embedded Linux (CPE)', accuracy: 38, reason: `ISP/CPE vendor "${vendor}"` });

  if (candidates.length === 0) return null;
  const best = candidates.reduce((a, b) => (b.accuracy > a.accuracy ? b : a));
  return {
    os: {
      family: best.family,
      name: best.name,
      version: best.version,
      accuracy: best.accuracy,
      source: 'inferred',
    },
    reason: `OS inferred (${best.name}): ${best.reason}`,
  };
}
