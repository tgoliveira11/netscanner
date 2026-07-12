import type { DeviceType } from '@netscanner/contracts';
import type { ClassificationInput, ClassificationRule, RuleVerdict } from '../classification-rule.js';

/** Tuya category codes → device type (Smart Home PaaS catalog). */
const TUYA_CATEGORY_MAP: { match: RegExp; deviceType: DeviceType; weight: number; label: string }[] = [
  { match: /^(sp|sgbj|dgnbj|hxiot)$/i, deviceType: 'camera', weight: 0.75, label: 'camera' },
  { match: /^(dj|dd|fwd|xdd|dc)$/i, deviceType: 'smart-home', weight: 0.7, label: 'light' },
  { match: /^(cz|pc|kg|tgq|clkg)$/i, deviceType: 'smart-home', weight: 0.7, label: 'plug/switch' },
  { match: /^(wk|wkf|qn|rs)$/i, deviceType: 'smart-home', weight: 0.65, label: 'climate' },
  { match: /^(mcs|pir|ywbj|gyd)$/i, deviceType: 'iot', weight: 0.6, label: 'sensor' },
  { match: /^(fs|fskg|cwysj)$/i, deviceType: 'smart-home', weight: 0.55, label: 'appliance' },
];

/**
 * Classify from Tuya cloud identity signals (`tuyaCategory` / product hints).
 * Populated by DeviceEnrichmentService when TUYA_* credentials are configured.
 */
export class TuyaClassificationRule implements ClassificationRule {
  readonly name = 'tuya';

  evaluate(input: ClassificationInput): RuleVerdict[] {
    const category = input.signals['tuyaCategory'];
    const product = input.signals['tuyaProductName'] ?? input.signals['tuyaName'];
    if (typeof category === 'string' && category) {
      for (const m of TUYA_CATEGORY_MAP) {
        if (m.match.test(category)) {
          return [
            {
              deviceType: m.deviceType,
              weight: m.weight,
              reason: `Tuya category ${category} (${m.label})`,
            },
          ];
        }
      }
      return [
        {
          deviceType: 'smart-home',
          weight: 0.5,
          reason: `Tuya category ${category}`,
        },
      ];
    }
    if (typeof product === 'string' && product) {
      return [
        {
          deviceType: 'smart-home',
          weight: 0.45,
          reason: `Tuya product "${product}"`,
        },
      ];
    }
    return [];
  }
}
