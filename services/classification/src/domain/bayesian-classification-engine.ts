import type { DeviceType } from '@netscanner/contracts';
import type { ClassificationInput, ClassificationRule } from './classification-rule.js';
import type { ClassificationOutcome, IClassificationEngine } from './classification-engine.js';

/**
 * Log-odds pooling over rule verdicts — calibrated confidence from many evidence sources.
 * Each verdict weight w ∈ (0,1] is treated as P(type|evidence) and pooled independently.
 */
export class BayesianClassificationEngine implements IClassificationEngine {
  constructor(private readonly rules: readonly ClassificationRule[]) {}

  classify(input: ClassificationInput): ClassificationOutcome {
    const logOdds = new Map<DeviceType, number>();
    const reasons = new Map<DeviceType, string[]>();

    for (const rule of this.rules) {
      for (const verdict of rule.evaluate(input)) {
        const p = clamp(verdict.weight, 0.05, 0.99);
        const delta = Math.log(p / (1 - p));
        logOdds.set(verdict.deviceType, (logOdds.get(verdict.deviceType) ?? 0) + delta);
        const bucket = reasons.get(verdict.deviceType) ?? [];
        bucket.push(`${rule.name}: ${verdict.reason} (p≈${p.toFixed(2)})`);
        reasons.set(verdict.deviceType, bucket);
      }
    }

    if (logOdds.size === 0) {
      return { deviceType: 'unknown', confidence: 0.1, reasons: ['no matching signals'] };
    }

    const posteriors = softmax(logOdds);
    const [bestType, confidence] = [...posteriors.entries()].sort((a, b) => b[1] - a[1])[0]!;

    return {
      deviceType: bestType,
      confidence: Math.round(confidence * 100) / 100,
      reasons: reasons.get(bestType) ?? [],
      evidence: buildEvidenceTrail(posteriors, reasons),
    };
  }
}

export interface ClassificationEvidence {
  deviceType: DeviceType;
  posterior: number;
  reasons: string[];
}

function buildEvidenceTrail(
  posteriors: Map<DeviceType, number>,
  reasons: Map<DeviceType, string[]>,
): ClassificationEvidence[] {
  return [...posteriors.entries()]
    .filter(([, p]) => p >= 0.02)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([deviceType, posterior]) => ({
      deviceType,
      posterior: Math.round(posterior * 1000) / 1000,
      reasons: reasons.get(deviceType) ?? [],
    }));
}

function softmax(logOdds: Map<DeviceType, number>): Map<DeviceType, number> {
  const max = Math.max(...logOdds.values());
  const exp = new Map<DeviceType, number>();
  let sum = 0;
  for (const [t, lo] of logOdds) {
    const e = Math.exp(lo - max);
    exp.set(t, e);
    sum += e;
  }
  const out = new Map<DeviceType, number>();
  for (const [t, e] of exp) out.set(t, e / sum);
  return out;
}

function clamp(n: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, n));
}
