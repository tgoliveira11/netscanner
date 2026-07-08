import type { DeviceType } from '@netscanner/contracts';
import type { ClassificationInput, ClassificationRule, RuleVerdict } from '../classification-rule.js';

/** DNS activity category (set by the enricher) → device type. */
const CATEGORY_MAP: { category: string; deviceType: DeviceType; weight: number }[] = [
  { category: 'security-cam', deviceType: 'camera', weight: 0.7 },
  { category: 'voice-assistant', deviceType: 'smart-speaker', weight: 0.6 },
  { category: 'smart-home', deviceType: 'smart-home', weight: 0.55 },
  { category: 'iot-cloud', deviceType: 'smart-home', weight: 0.45 },
  { category: 'media', deviceType: 'streaming-device', weight: 0.4 },
  { category: 'streaming', deviceType: 'streaming-device', weight: 0.35 },
];

/**
 * Classifies from a device's DNS activity — what cloud/services it talks to
 * (e.g. contacting Tuya/Ring/Alexa domains). Signals `dnsCategories` are
 * populated by the enricher from the passively-observed query names.
 */
export class DnsClassificationRule implements ClassificationRule {
  readonly name = 'dns';

  evaluate(input: ClassificationInput): RuleVerdict[] {
    const cats = input.signals['dnsCategories'];
    if (!Array.isArray(cats) || cats.length === 0) return [];
    const set = new Set(cats.map(String));
    const verdicts: RuleVerdict[] = [];
    for (const m of CATEGORY_MAP) {
      if (set.has(m.category)) {
        verdicts.push({ deviceType: m.deviceType, weight: m.weight, reason: `DNS activity: ${m.category}` });
      }
    }
    return verdicts;
  }
}
