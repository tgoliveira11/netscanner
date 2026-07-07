import { MacAddress, isOk } from '@netscanner/kernel';
import type { ClassificationInput, ClassificationRule, RuleVerdict } from '../classification-rule.js';

/**
 * A locally-administered ("randomized/private") MAC is set by the OS for WiFi
 * privacy. On a consumer LAN this overwhelmingly means a modern phone or laptop
 * (iOS/Android/macOS/Windows all randomize per-network). The vendor is
 * unknowable by design, but the *class* of device is a strong inference — far
 * better than reporting "unknown". Other rules (hostname, OS, mDNS) refine it.
 */
export class RandomizedMacRule implements ClassificationRule {
  readonly name = 'randomized-mac';

  evaluate(input: ClassificationInput): RuleVerdict[] {
    if (!input.mac) return [];
    const parsed = MacAddress.create(input.mac);
    if (!isOk(parsed) || !parsed.value.isLocallyAdministered) return [];
    return [
      { deviceType: 'phone', weight: 0.35, reason: 'randomized/private WiFi MAC (privacy)' },
      { deviceType: 'laptop', weight: 0.2, reason: 'randomized/private WiFi MAC (privacy)' },
    ];
  }
}
