import type { DeviceType } from '@netscanner/contracts';
import type { ClassificationInput, ClassificationRule, RuleVerdict } from '../classification-rule.js';

/** Open-port → device-type signals. */
const PORT_MAP: Record<number, [DeviceType, number, string]> = {
  9100: ['printer', 0.8, 'JetDirect print port'],
  515: ['printer', 0.7, 'LPD print port'],
  631: ['printer', 0.6, 'IPP print port'],
  32400: ['nas', 0.5, 'Plex media server'],
  548: ['nas', 0.4, 'AFP file sharing'],
  2049: ['nas', 0.5, 'NFS export'],
  554: ['camera', 0.6, 'RTSP stream'],
  1883: ['iot', 0.5, 'MQTT broker'],
  8883: ['iot', 0.5, 'MQTT/TLS'],
  62078: ['phone', 0.7, 'Apple lockdown/sync'],
  8009: ['streaming-device', 0.6, 'Chromecast'],
  3389: ['computer', 0.4, 'RDP'],
  445: ['computer', 0.3, 'SMB'],
  5900: ['computer', 0.3, 'VNC'],
};

export class PortServiceRule implements ClassificationRule {
  readonly name = 'port-service';

  evaluate(input: ClassificationInput): RuleVerdict[] {
    const verdicts: RuleVerdict[] = [];
    const openPorts = new Set(input.services.filter((s) => s.state === 'open').map((s) => s.port));

    for (const [portStr, [deviceType, weight, label]] of Object.entries(PORT_MAP)) {
      if (openPorts.has(Number(portStr))) {
        verdicts.push({ deviceType, weight, reason: `open ${portStr} (${label})` });
      }
    }

    // Many exposed services on a Linux-y host → likely a server.
    if (openPorts.size >= 5) {
      verdicts.push({ deviceType: 'server', weight: 0.3, reason: `${openPorts.size} open ports` });
    }
    return verdicts;
  }
}
