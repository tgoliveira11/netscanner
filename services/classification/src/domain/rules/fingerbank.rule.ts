import type { DeviceType } from '@netscanner/contracts';
import type { ClassificationInput, ClassificationRule, RuleVerdict } from '../classification-rule.js';

/** Maps Fingerbank device names/paths to a device type. */
const PATTERNS: { match: RegExp; deviceType: DeviceType; weight: number }[] = [
  { match: /apple ?watch|watchos|wear ?os|smart ?watch|fitbit|garmin/i, deviceType: 'wearable', weight: 0.95 },
  { match: /iphone|android phone|smartphone|pixel|galaxy s|galaxy note/i, deviceType: 'phone', weight: 0.9 },
  { match: /ipad|tablet|galaxy tab/i, deviceType: 'tablet', weight: 0.9 },
  { match: /macbook|imac|mac ?mini|mac ?pro|laptop|notebook/i, deviceType: 'laptop', weight: 0.9 },
  { match: /\bpc\b|windows|desktop/i, deviceType: 'computer', weight: 0.85 },
  { match: /apple ?tv|chromecast|roku|fire ?tv|smart ?tv|shield|webos|tizen|android ?tv/i, deviceType: 'streaming-device', weight: 0.9 },
  { match: /homepod|echo|alexa|sonos|google ?home|nest ?(audio|mini)|speaker/i, deviceType: 'smart-speaker', weight: 0.9 },
  { match: /printer|laserjet|officejet/i, deviceType: 'printer', weight: 0.9 },
  { match: /camera|ip ?cam|doorbell|nvr/i, deviceType: 'camera', weight: 0.9 },
  { match: /game ?console|playstation|xbox|nintendo|switch/i, deviceType: 'game-console', weight: 0.9 },
  { match: /router|gateway|access ?point|firewall|switch/i, deviceType: 'router', weight: 0.85 },
  { match: /nas|synology|qnap/i, deviceType: 'nas', weight: 0.9 },
  { match: /thermostat|light|bulb|plug|sensor|hub|iot|esp|tuya|smart ?home/i, deviceType: 'smart-home', weight: 0.8 },
];

/**
 * Highest-authority classifier: uses the exact device identity resolved by
 * Fingerbank from the DHCP fingerprint (populated into signals by the pipeline).
 * Weighted above every heuristic so a confident external match wins.
 */
export class FingerbankRule implements ClassificationRule {
  readonly name = 'fingerbank';

  evaluate(input: ClassificationInput): RuleVerdict[] {
    const name = input.signals['fingerbankDevice'];
    const path = input.signals['fingerbankPath'];
    const text = [typeof name === 'string' ? name : '', typeof path === 'string' ? path : '']
      .filter(Boolean)
      .join(' ');
    if (!text) return [];

    for (const p of PATTERNS) {
      if (p.match.test(text)) {
        return [{ deviceType: p.deviceType, weight: p.weight, reason: `Fingerbank: ${text}` }];
      }
    }
    return [];
  }
}
