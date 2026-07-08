import type { DeviceType } from '@netscanner/contracts';
import type { ClassificationInput, ClassificationRule, RuleVerdict } from '../classification-rule.js';

/**
 * Passive TCP SYN stack fingerprint votes — complements DHCP/JA3 on firewalled hosts.
 */
export class P0fClassificationRule implements ClassificationRule {
  readonly name = 'p0f-passive';

  evaluate(input: ClassificationInput): RuleVerdict[] {
    const family = str(input.signals['p0fOsFamily']);
    const name = str(input.signals['p0fOsName']);
    const conf = num(input.signals['p0fOsConfidence']);
    if (!family && !name) return [];

    const text = [family, name].filter(Boolean).join(' ');
    const weight = Math.min(0.85, Math.max(0.35, (conf ?? 50) / 100));
    const reason = str(input.signals['p0fOsReason']) ?? `SYN stack: ${text}`;

    if (/ios|ipados/i.test(text)) {
      return [{ deviceType: 'phone', weight, reason: `p0f: ${reason}` }];
    }
    if (/iphone|android phone|pixel|galaxy/i.test(text)) {
      return [{ deviceType: 'phone', weight: weight * 0.9, reason: `p0f: ${reason}` }];
    }
    if (/macos/i.test(text)) {
      return [{ deviceType: 'laptop', weight, reason: `p0f: ${reason}` }];
    }
    if (/windows/i.test(text)) {
      return [{ deviceType: 'computer', weight, reason: `p0f: ${reason}` }];
    }
    if (/linux|android/i.test(text)) {
      return [{ deviceType: 'phone', weight: weight * 0.7, reason: `p0f: ${reason}` }];
    }
    if (/embedded|appliance/i.test(text)) {
      return [{ deviceType: 'iot', weight: weight * 0.8, reason: `p0f: ${reason}` }];
    }
    return [];
  }
}

function str(v: unknown): string | null {
  return typeof v === 'string' && v ? v : null;
}

function num(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null;
}
