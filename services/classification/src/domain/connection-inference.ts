import { MacAddress, isOk } from '@netscanner/kernel';
import type { ConnectionType, DeviceType } from '@netscanner/contracts';

export interface ConnectionEvidence {
  mac: string | null;
  deviceType: DeviceType;
  isGateway: boolean;
  /** Set by a definitive source (switch FDB / AP association) when available. */
  authoritative?: ConnectionType | null;
}

export interface ConnectionInference {
  type: ConnectionType;
  /** Human-readable justification, surfaced in the UI so the guess is honest. */
  basis: string;
}

// Infrastructure that is essentially always cabled.
const WIRED_TYPES = new Set<DeviceType>(['router', 'switch', 'firewall', 'access-point', 'nas', 'server']);
// Devices that are essentially always wireless.
const WIFI_TYPES = new Set<DeviceType>(['phone', 'tablet', 'wearable', 'smart-speaker']);
// Predominantly (but not exclusively) wireless in homes.
const LIKELY_WIFI_TYPES = new Set<DeviceType>(['smart-home', 'iot', 'tv', 'streaming-device']);

/**
 * Infer whether a device is wired or on WiFi. Definitive truth requires the
 * switch's MAC table or the AP's association list; absent that, we combine the
 * strongest available heuristics:
 *  - a locally-administered ("randomized") MAC is a WiFi-only privacy feature →
 *    near-certain WiFi;
 *  - infrastructure (router/switch/NAS/server) is virtually always cabled;
 *  - phones/tablets/wearables/speakers are virtually always WiFi.
 * Everything genuinely ambiguous (desktop, printer, camera, console) stays
 * `unknown` rather than guessing. An `authoritative` value always wins.
 */
export function inferConnection(e: ConnectionEvidence): ConnectionInference {
  if (e.authoritative) {
    return { type: e.authoritative, basis: 'reported by switch/AP (authoritative)' };
  }
  if (e.isGateway || WIRED_TYPES.has(e.deviceType)) {
    return { type: 'wired', basis: 'infrastructure device (virtually always cabled)' };
  }
  if (e.mac) {
    const parsed = MacAddress.create(e.mac);
    if (isOk(parsed) && parsed.value.isLocallyAdministered) {
      return { type: 'wifi', basis: 'randomized/private MAC (a WiFi-only feature)' };
    }
  }
  if (WIFI_TYPES.has(e.deviceType)) {
    return { type: 'wifi', basis: 'phone/tablet/wearable/speaker (WiFi)' };
  }
  if (LIKELY_WIFI_TYPES.has(e.deviceType)) {
    return { type: 'wifi', basis: 'consumer IoT/AV device (usually WiFi)' };
  }
  return { type: 'unknown', basis: 'not determinable without switch/AP data' };
}
