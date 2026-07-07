import type { OsGuess } from '@netscanner/contracts';
import { inferOs, type OsEvidence } from './os-inference.js';

export interface DeviceIdentity {
  brand: string | null;
  model: string | null;
}

function readSignal(signals: Record<string, unknown>, key: string): string {
  const v = signals[key];
  return typeof v === 'string' ? v : '';
}

/** Strip legal suffixes so "Apple, Inc." reads as "Apple". */
export function normalizeBrandName(name: string): string {
  return name
    .replace(/,?\s*(Inc\.?|LLC|Ltd\.?|Limited|Corporation|Co\.?,?\s*limited)$/i, '')
    .trim();
}

/**
 * Best-effort brand + model from Fingerbank, UPnP, and OUI vendor — in that order.
 */
export function resolveBrandModel(
  vendor: string | null,
  signals: Record<string, unknown>,
): DeviceIdentity {
  const fbName = readSignal(signals, 'fingerbankDevice');
  const fbPath = readSignal(signals, 'fingerbankPath');
  const upnpMfr = readSignal(signals, 'upnpManufacturer');
  const upnpModel = readSignal(signals, 'upnpModel');

  let brand: string | null = null;
  let model: string | null = null;

  if (fbPath) {
    const parts = fbPath.split('/').filter(Boolean);
    if (parts[0] === 'Hardware' && parts[1]) brand = parts[1];
  }
  if (fbName) model = fbName;
  if (!brand && upnpMfr) brand = normalizeBrandName(upnpMfr);
  if (!model && upnpModel) model = upnpModel;
  const mdnsModel = readSignal(signals, 'mdnsModel') || readSignal(signals, 'mdnsAppleModel');
  if (!model && mdnsModel) model = mdnsModel;
  const snmpDescr = readSignal(signals, 'snmpSysDescr');
  if (!model && snmpDescr) {
    const m = /^([^\s,]+)/.exec(snmpDescr)?.[1];
    if (m && m.length > 2) model = m;
  }
  if (!brand && vendor && vendor !== 'Randomized/Private MAC') {
    brand = normalizeBrandName(vendor);
  }

  return { brand, model };
}

interface OsCandidate {
  os: OsGuess;
  reason: string;
}

function pickBestOs(current: OsGuess | null, candidates: OsCandidate[]): OsGuess | null {
  if (candidates.length === 0) return current;
  const best = candidates.reduce((a, b) => ((b.os.accuracy ?? 0) > (a.os.accuracy ?? 0) ? b : a));
  if (!current) return best.os;
  const curAcc = current.accuracy ?? 0;
  const bestAcc = best.os.accuracy ?? 0;
  if (bestAcc > curAcc) {
    return { ...best.os, version: best.os.version ?? current.version };
  }
  if (!current.version && best.os.version) {
    return { ...current, version: best.os.version };
  }
  return current;
}

/**
 * Resolves OS + version from nmap, Fingerbank, DHCP vendor class, mDNS/UPnP, and
 * hostname heuristics. nmap `-O` wins on accuracy; Fingerbank and DHCP fill version
 * gaps on firewalled mobile/IoT hosts.
 */
export function resolveOs(
  nmapOs: OsGuess | null,
  evidence: OsEvidence,
): { os: OsGuess | null; extraReason: string | null } {
  const { signals, vendor, hostname } = evidence;
  const inferred = nmapOs ? null : inferOs(evidence);
  let os = nmapOs ?? inferred?.os ?? null;
  let extraReason: string | null = inferred?.reason ?? null;

  const fbName = readSignal(signals, 'fingerbankDevice');
  const fbPath = readSignal(signals, 'fingerbankPath');
  const fbVersion = readSignal(signals, 'fingerbankVersion');
  const fbText = [fbName, fbPath].filter(Boolean).join(' ');
  const dhcpVendor = readSignal(signals, 'dhcpVendorClass');
  const mdnsType = readSignal(signals, 'mdnsType');
  const mdnsOsVer = readSignal(signals, 'mdnsOsVersion');
  const host = hostname ?? '';
  const fbScore = signals['fingerbankScore'];
  const fbAcc = typeof fbScore === 'number' ? Math.min(92, fbScore) : 78;

  const candidates: OsCandidate[] = [];
  const add = (c: OsCandidate | null): void => {
    if (c) candidates.push(c);
  };

  if (/watchos|apple watch/i.test(fbText)) {
    add({
      os: { family: 'watchOS', name: 'watchOS', version: fbVersion || undefined, accuracy: fbAcc, source: 'inferred' },
      reason: `Fingerbank OS: ${fbName || fbPath}`,
    });
  } else if (/ipad/i.test(fbText)) {
    add({
      os: { family: 'iPadOS', name: 'iPadOS', version: fbVersion || undefined, accuracy: fbAcc, source: 'inferred' },
      reason: `Fingerbank OS: ${fbName || fbPath}`,
    });
  } else if (/iphone|ios\b/i.test(fbText)) {
    add({
      os: { family: 'iOS', name: 'iOS', version: fbVersion || undefined, accuracy: fbAcc, source: 'inferred' },
      reason: `Fingerbank OS: ${fbName || fbPath}`,
    });
  } else if (/apple ?tv|tvos/i.test(fbText)) {
    add({
      os: { family: 'tvOS', name: 'tvOS', version: fbVersion || undefined, accuracy: fbAcc, source: 'inferred' },
      reason: `Fingerbank OS: ${fbName || fbPath}`,
    });
  } else if (/macbook|imac|mac ?os|macos/i.test(fbText)) {
    add({
      os: { family: 'macOS', name: 'macOS', version: fbVersion || mdnsOsVer || undefined, accuracy: fbAcc, source: 'inferred' },
      reason: `Fingerbank OS: ${fbName || fbPath}`,
    });
  } else if (/android/i.test(fbText)) {
    add({
      os: { family: 'Android', name: 'Android', version: fbVersion || undefined, accuracy: fbAcc, source: 'inferred' },
      reason: `Fingerbank OS: ${fbName || fbPath}`,
    });
  } else if (/windows/i.test(fbText)) {
    add({
      os: { family: 'Windows', name: 'Windows', version: fbVersion || undefined, accuracy: fbAcc, source: 'inferred' },
      reason: `Fingerbank OS: ${fbName || fbPath}`,
    });
  }

  const android = /android-dhcp-(\d+)/i.exec(dhcpVendor);
  if (android) {
    add({
      os: { family: 'Android', name: 'Android', version: android[1], accuracy: 62, source: 'inferred' },
      reason: `DHCP vendor class "${dhcpVendor}"`,
    });
  }
  if (/dhcpcd|udhcp/i.test(dhcpVendor) && /linux/i.test(fbText)) {
    add({
      os: { family: 'Linux', name: 'Linux', accuracy: 45, source: 'inferred' },
      reason: `DHCP stack "${dhcpVendor}"`,
    });
  }

  const netbiosOs = readSignal(signals, 'netbiosOs');
  if (netbiosOs) {
    add({
      os: { family: 'Windows', name: netbiosOs, accuracy: 60, source: 'inferred' },
      reason: `NetBIOS status "${netbiosOs}"`,
    });
  }

  const snmpDescr = readSignal(signals, 'snmpSysDescr');
  if (snmpDescr) {
    const ver = /(\d+(?:\.\d+)+)/.exec(snmpDescr)?.[1];
    if (/linux/i.test(snmpDescr)) {
      add({
        os: { family: 'Linux', name: 'Linux', version: ver, accuracy: 75, source: 'inferred' },
        reason: `SNMP sysDescr "${snmpDescr.slice(0, 60)}"`,
      });
    } else if (/freebsd|pfsense|opnsense/i.test(snmpDescr)) {
      add({
        os: { family: 'FreeBSD', name: 'FreeBSD', version: ver, accuracy: 78, source: 'inferred' },
        reason: `SNMP sysDescr "${snmpDescr.slice(0, 60)}"`,
      });
    } else if (/windows/i.test(snmpDescr)) {
      add({
        os: { family: 'Windows', name: 'Windows', version: ver, accuracy: 75, source: 'inferred' },
        reason: `SNMP sysDescr "${snmpDescr.slice(0, 60)}"`,
      });
    }
  }

  const isApple = /apple/i.test(vendor ?? '') || /apple/i.test(fbText);
  if (/hometheater|appletv|apple-tv/i.test(host) && isApple) {
    add({
      os: { family: 'tvOS', name: 'tvOS', accuracy: 62, source: 'inferred' },
      reason: `Apple TV hostname "${host}"`,
    });
  }
  if (mdnsType === 'airplay' && isApple && !/iphone|ipad|macbook|mbp|mba|imac/i.test(host + fbText)) {
    add({
      os: { family: 'tvOS', name: 'tvOS', accuracy: 58, source: 'inferred' },
      reason: 'AirPlay mDNS advertisement (Apple)',
    });
  }
  if (mdnsType === 'homekit' && isApple) {
    add({
      os: { family: 'tvOS', name: 'tvOS', accuracy: 50, source: 'inferred' },
      reason: 'HomeKit mDNS (Apple hub/accessory)',
    });
  }
  if (mdnsOsVer && isApple && !os?.version) {
    add({
      os: { family: 'macOS', name: 'macOS', version: mdnsOsVer, accuracy: 70, source: 'inferred' },
      reason: `mDNS osxvers=${mdnsOsVer}`,
    });
  }

  const upnpKind = readSignal(signals, 'upnpDeviceType');
  if (/googletv|androidtv|android tv/i.test(upnpKind + fbText)) {
    add({
      os: { family: 'Android', name: 'Android TV', accuracy: 65, source: 'inferred' },
      reason: 'UPnP/Android TV device type',
    });
  }

  const before = os;
  os = pickBestOs(os, candidates);
  if (os !== before && candidates.length) {
    const winner = candidates.find((c) => c.os.family === os?.family) ?? candidates[0];
    extraReason = winner?.reason ?? extraReason;
  }

  if (os && !os.version && fbVersion) {
    os = { ...os, version: fbVersion };
  }

  return { os, extraReason };
}
