export * from './domain/classification-rule.js';
export * from './domain/classification-engine.js';
export * from './domain/security-analyzer.js';
export * from './domain/rules/vendor.rule.js';
export * from './domain/rules/port-service.rule.js';
export * from './domain/rules/discovery-signal.rule.js';
export * from './domain/rules/os-hostname.rule.js';
export * from './domain/rules/gateway.rule.js';
export * from './domain/rules/randomized-mac.rule.js';
export * from './domain/rules/app-banner.rule.js';
export * from './domain/rules/fingerbank.rule.js';
export * from './domain/os-inference.js';
export * from './domain/connection-inference.js';
export * from './application/classify-device.use-case.js';

import type { ClassificationRule } from './domain/classification-rule.js';
import { VendorRule } from './domain/rules/vendor.rule.js';
import { PortServiceRule } from './domain/rules/port-service.rule.js';
import { DiscoverySignalRule } from './domain/rules/discovery-signal.rule.js';
import { OsHostnameRule } from './domain/rules/os-hostname.rule.js';
import { GatewayRule } from './domain/rules/gateway.rule.js';
import { RandomizedMacRule } from './domain/rules/randomized-mac.rule.js';
import { AppBannerRule } from './domain/rules/app-banner.rule.js';
import { FingerbankRule } from './domain/rules/fingerbank.rule.js';

/** Default rule set wired into the engine; extend by appending new rules (OCP). */
export function defaultRules(): ClassificationRule[] {
  return [
    new GatewayRule(),
    new VendorRule(),
    new PortServiceRule(),
    new DiscoverySignalRule(),
    new OsHostnameRule(),
    new RandomizedMacRule(),
    new AppBannerRule(),
    new FingerbankRule(),
  ];
}
