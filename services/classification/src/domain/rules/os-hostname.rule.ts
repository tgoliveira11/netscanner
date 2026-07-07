import type { DeviceType } from '@netscanner/contracts';
import type { ClassificationInput, ClassificationRule, RuleVerdict } from '../classification-rule.js';

const HOSTNAME_MAP: { match: RegExp; deviceType: DeviceType; weight: number }[] = [
  // Apple Watch first — its DHCP hostname is literally "watch"; must beat "phone".
  { match: /\bwatch\b|apple[\s-]?watch|galaxy[\s-]?watch|\bband\b/i, deviceType: 'wearable', weight: 0.8 },
  { match: /iphone|\bipad\b/i, deviceType: 'phone', weight: 0.6 },
  { match: /android|pixel|galaxy/i, deviceType: 'phone', weight: 0.6 },
  { match: /macbook|\bmbp\b|\bmba\b|imac|mac-?mini|\bmac\b/i, deviceType: 'laptop', weight: 0.65 },
  { match: /desktop-|-pc$|windows/i, deviceType: 'computer', weight: 0.5 },
  { match: /chromecast|shield|firetv|appletv|apple-tv|hometheater|roku|vizio|bravia/i, deviceType: 'streaming-device', weight: 0.7 },
  { match: /homepod|echo|alexa|nest-audio|nest-mini/i, deviceType: 'smart-speaker', weight: 0.7 },
  { match: /printer|epson|canon|brother|officejet/i, deviceType: 'printer', weight: 0.7 },
  { match: /camera|cam-|ipcam/i, deviceType: 'camera', weight: 0.6 },
  { match: /nas|synology|qnap|truenas/i, deviceType: 'nas', weight: 0.7 },
  { match: /router|gateway|fritz|unifi|openwrt/i, deviceType: 'router', weight: 0.6 },
  // IoT firmware/stack hostnames (ESP chips, lwIP stack, common IoT platforms).
  { match: /\besp[0-9a-f]{2,}|espressif|\blwip\d*\b|tuya|tasmota|shelly|sonoff|tplink-?smart/i, deviceType: 'iot', weight: 0.6 },
  { match: /amazon|echo|kindle/i, deviceType: 'smart-speaker', weight: 0.45 },
];

// A confirmed OS is a strong signal — weighted high so it overrides weaker
// vendor/MAC leans (e.g. a detected macOS host must not stay a "phone").
// Order matters: iOS/iPadOS is checked before macOS since nmap strings overlap.
const OS_MAP: { match: RegExp; deviceType: DeviceType; weight: number }[] = [
  { match: /watchos/i, deviceType: 'wearable', weight: 0.8 },
  { match: /iphone os|ipad os|ios\b/i, deviceType: 'phone', weight: 0.7 },
  { match: /android/i, deviceType: 'phone', weight: 0.7 },
  { match: /mac ?os|macos|os x/i, deviceType: 'laptop', weight: 0.7 },
  { match: /windows/i, deviceType: 'computer', weight: 0.65 },
  { match: /openwrt|edgeos|routeros|junos|dd-wrt|tomato/i, deviceType: 'router', weight: 0.6 },
  { match: /free ?bsd|open ?bsd|net ?bsd/i, deviceType: 'server', weight: 0.3 },
  { match: /linux/i, deviceType: 'computer', weight: 0.25 },
  { match: /embedded|rtos|vxworks/i, deviceType: 'iot', weight: 0.5 },
];

/** Classifies from reverse hostname and nmap OS-detection family. */
export class OsHostnameRule implements ClassificationRule {
  readonly name = 'os-hostname';

  evaluate(input: ClassificationInput): RuleVerdict[] {
    const verdicts: RuleVerdict[] = [];
    if (input.hostname) {
      for (const rule of HOSTNAME_MAP) {
        if (rule.match.test(input.hostname)) {
          verdicts.push({ deviceType: rule.deviceType, weight: rule.weight, reason: `hostname "${input.hostname}"` });
        }
      }
    }
    const osText = [input.os?.name, input.os?.family].filter(Boolean).join(' ');
    if (osText) {
      for (const rule of OS_MAP) {
        if (rule.match.test(osText)) {
          const acc = (input.os?.accuracy ?? 80) / 100;
          verdicts.push({ deviceType: rule.deviceType, weight: rule.weight * acc, reason: `OS "${osText}"` });
        }
      }
    }
    return verdicts;
  }
}
