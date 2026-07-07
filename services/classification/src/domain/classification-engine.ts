import type { DeviceType } from '@netscanner/contracts';
import type { ClassificationInput, ClassificationRule } from './classification-rule.js';

export interface ClassificationOutcome {
  deviceType: DeviceType;
  /** Normalized confidence in [0,1]. */
  confidence: number;
  reasons: string[];
}

/**
 * Aggregates weighted verdicts from all registered rules into a single device
 * type + confidence. Depends only on the ClassificationRule port (DIP) and is a
 * pure function of its inputs, so it is fully deterministic and unit-testable.
 */
export class ClassificationEngine {
  constructor(private readonly rules: readonly ClassificationRule[]) {}

  classify(input: ClassificationInput): ClassificationOutcome {
    const scores = new Map<DeviceType, { weight: number; reasons: string[] }>();
    let totalWeight = 0;

    for (const rule of this.rules) {
      for (const verdict of rule.evaluate(input)) {
        const bucket = scores.get(verdict.deviceType) ?? { weight: 0, reasons: [] };
        bucket.weight += verdict.weight;
        bucket.reasons.push(`${rule.name}: ${verdict.reason}`);
        scores.set(verdict.deviceType, bucket);
        totalWeight += verdict.weight;
      }
    }

    if (scores.size === 0 || totalWeight === 0) {
      return { deviceType: 'unknown', confidence: 0.1, reasons: ['no matching signals'] };
    }

    const [bestType, best] = [...scores.entries()].sort((a, b) => b[1].weight - a[1].weight)[0]!;
    // Confidence blends the winner's share of total evidence with its absolute
    // strength, so a lone weak signal stays low-confidence.
    const share = best.weight / totalWeight;
    const strength = Math.min(1, best.weight);
    const confidence = Math.round(Math.min(1, 0.5 * share + 0.5 * strength) * 100) / 100;

    return { deviceType: bestType, confidence, reasons: best.reasons };
  }
}
