import type { DeviceType } from '@netscanner/contracts';
import type { ClassificationInput, ClassificationRule, RuleVerdict } from '../classification-rule.js';

/** mDNS service-type / SSDP-string → device-type signals. */
const MDNS_MAP: { match: RegExp; deviceType: DeviceType; weight: number }[] = [
  { match: /googlecast/i, deviceType: 'streaming-device', weight: 0.7 },
  { match: /airplay|raop/i, deviceType: 'streaming-device', weight: 0.5 },
  { match: /ipp|printer|pdl-datastream/i, deviceType: 'printer', weight: 0.8 },
  { match: /hap|homekit/i, deviceType: 'smart-home', weight: 0.7 },
  { match: /afpovertcp|smb/i, deviceType: 'nas', weight: 0.4 },
  { match: /spotify-connect/i, deviceType: 'smart-speaker', weight: 0.6 },
  { match: /sonos/i, deviceType: 'smart-speaker', weight: 0.7 },
];

const SSDP_MAP: { match: RegExp; deviceType: DeviceType; weight: number }[] = [
  { match: /InternetGatewayDevice|router/i, deviceType: 'router', weight: 0.8 },
  { match: /MediaServer|MediaRenderer|DLNA/i, deviceType: 'streaming-device', weight: 0.5 },
  { match: /Roku/i, deviceType: 'streaming-device', weight: 0.8 },
  { match: /camera|IPCamera/i, deviceType: 'camera', weight: 0.7 },
];

export class DiscoverySignalRule implements ClassificationRule {
  readonly name = 'discovery-signal';

  evaluate(input: ClassificationInput): RuleVerdict[] {
    const verdicts: RuleVerdict[] = [];
    const mdns = JSON.stringify(input.signals['mdnsServices'] ?? '') + String(input.signals['mdnsType'] ?? '');
    for (const rule of MDNS_MAP) {
      if (rule.match.test(mdns)) {
        verdicts.push({ deviceType: rule.deviceType, weight: rule.weight, reason: `mDNS ${rule.match.source}` });
      }
    }

    const ssdp = [input.signals['ssdpServer'], input.signals['ssdpSt'], input.signals['ssdpUsn']]
      .filter(Boolean)
      .join(' ');
    for (const rule of SSDP_MAP) {
      if (rule.match.test(ssdp)) {
        verdicts.push({ deviceType: rule.deviceType, weight: rule.weight, reason: `SSDP ${rule.match.source}` });
      }
    }
    return verdicts;
  }
}
