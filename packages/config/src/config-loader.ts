import { EnvSchema, type AppConfig } from './env-schema.js';

let cached: AppConfig | null = null;

export function resetConfigCache(): void {
  cached = null;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  if (cached) return cached;
  cached = EnvSchema.parse(env);
  return cached;
}

export function patchLiveConfig(target: AppConfig, next: AppConfig): void {
  for (const key of Object.keys(target) as (keyof AppConfig)[]) {
    delete (target as Record<string, unknown>)[key];
  }
  Object.assign(target, next);
}
