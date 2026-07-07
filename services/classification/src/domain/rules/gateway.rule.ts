import type { ClassificationInput, ClassificationRule, RuleVerdict } from '../classification-rule.js';

/**
 * If the host is the subnet's default gateway, it is almost certainly the
 * router/firewall. Strong, high-confidence signal when the gateway IP is known.
 */
export class GatewayRule implements ClassificationRule {
  readonly name = 'gateway';

  evaluate(input: ClassificationInput): RuleVerdict[] {
    if (input.gatewayIp && input.ip === input.gatewayIp) {
      return [{ deviceType: 'router', weight: 0.9, reason: 'host is the default gateway' }];
    }
    return [];
  }
}
