import { describe, expect, it } from 'vitest';
import { BayesianClassificationEngine } from './bayesian-classification-engine.js';
import { FingerbankRule } from './rules/fingerbank.rule.js';
import { VendorRule } from './rules/vendor.rule.js';

describe('BayesianClassificationEngine', () => {
  it('produces higher posterior for Fingerbank phone vs weak vendor hint', () => {
    const engine = new BayesianClassificationEngine([new FingerbankRule(), new VendorRule()]);
    const out = engine.classify({
      ip: '192.168.1.100',
      mac: '44:f2:1b:24:fb:60',
      vendor: 'Apple',
      hostname: 'iphone',
      os: null,
      services: [],
      gatewayIp: '192.168.1.1',
      signals: {
        fingerbankDevice: 'Apple iPhone',
        fingerbankPath: 'Hardware/Apple/iPhone',
        fingerbankScore: 72,
      },
    });
    expect(out.deviceType).toBe('phone');
    expect(out.confidence).toBeGreaterThan(0.5);
    expect(out.evidence?.[0]?.deviceType).toBe('phone');
  });
});
