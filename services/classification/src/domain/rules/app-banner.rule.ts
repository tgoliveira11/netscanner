import type { DeviceType } from '@netscanner/contracts';
import type { ClassificationInput, ClassificationRule, RuleVerdict } from '../classification-rule.js';

/** Matches on UPnP/HTTP/TLS strings that name a device model or role. */
const PATTERNS: { match: RegExp; deviceType: DeviceType; weight: number }[] = [
  { match: /pfsense|opnsense|mikrotik|routeros|openwrt|dd-wrt|ubnt|unifi|edgeos/i, deviceType: 'router', weight: 0.85 },
  { match: /synology|qnap|truenas|freenas|diskstation|nas/i, deviceType: 'nas', weight: 0.8 },
  { match: /ipcamera|hikvision|dahua|axis|reolink|webcam|onvif|dcs-/i, deviceType: 'camera', weight: 0.85 },
  { match: /printer|laserjet|officejet|ecosys|brother|epson|canon ink/i, deviceType: 'printer', weight: 0.85 },
  { match: /roku|shield|apple ?tv|chromecast|fire ?tv|smart ?tv|bravia|webos|tizen/i, deviceType: 'streaming-device', weight: 0.8 },
  { match: /sonos|homepod|nest ?(audio|mini)|echo|alexa/i, deviceType: 'smart-speaker', weight: 0.8 },
  { match: /plex|jellyfin|emby|media ?server|dlna/i, deviceType: 'nas', weight: 0.5 },
  { match: /hue bridge|smartthings|homekit|hubitat/i, deviceType: 'smart-home', weight: 0.8 },
];

/**
 * Classifies from application-layer banners gathered by the network enricher:
 * UPnP friendlyName/manufacturer/model, HTTP Server header + page title, and the
 * TLS certificate subject. These often reveal an exact model — the strongest
 * signal available for web-facing infrastructure and media devices.
 */
export class AppBannerRule implements ClassificationRule {
  readonly name = 'app-banner';

  evaluate(input: ClassificationInput): RuleVerdict[] {
    const haystack = [
      input.signals['upnpManufacturer'],
      input.signals['upnpModel'],
      input.signals['upnpFriendlyName'],
      input.signals['upnpDeviceType'],
      input.signals['httpServer'],
      input.signals['httpTitle'],
      input.signals['tlsSubject'],
      input.signals['tlsIssuer'],
    ]
      .filter(Boolean)
      .join(' | ');
    if (!haystack) return [];

    const verdicts: RuleVerdict[] = [];
    for (const p of PATTERNS) {
      if (p.match.test(haystack)) {
        verdicts.push({ deviceType: p.deviceType, weight: p.weight, reason: `banner ~ ${p.match.source}` });
      }
    }
    return verdicts;
  }
}
