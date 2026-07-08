import type { SiteIntegrations } from '@netscanner/contracts';
import type { AppConfig } from './env-schema.js';

/** Merge per-site integration overrides onto the global agent config. */
export function mergeSiteIntegrations(base: AppConfig, overrides: SiteIntegrations): AppConfig {
  if (!overrides || Object.keys(overrides).length === 0) return base;
  return { ...base, ...overrides };
}
