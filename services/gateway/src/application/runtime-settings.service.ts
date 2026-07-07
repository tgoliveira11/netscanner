import type { AppConfig } from '@netscanner/config';
import {
  CONFIG_FIELDS,
  applyConfigToProcess,
  configForAdmin,
  parseConfigPatch,
  saveEnvFile,
  patchLiveConfig,
} from '@netscanner/config';
import type { Container } from '../container.js';

export interface RuntimeSettingsService {
  configPath: string;
  getConfig(): ReturnType<typeof configForAdmin>;
  getSchema(): typeof CONFIG_FIELDS;
  applyPatch(body: Record<string, unknown>): Promise<{ restartRequired: boolean; applied: string[] }>;
}

export function createRuntimeSettings(c: Container, configPath: string): RuntimeSettingsService {
  return {
    configPath,
    getConfig: () => configForAdmin(c.config),
    getSchema: () => CONFIG_FIELDS.filter((f) => !f.hidden),

    async applyPatch(body) {
      const { values, restartRequired } = parseConfigPatch(body, c.config);
      const applied = Object.keys(body).filter((k) => !k.startsWith('_'));

      patchLiveConfig(c.config, values);
      applyConfigToProcess(values);

      const persist: Record<string, string | number | boolean> = {};
      for (const field of CONFIG_FIELDS) {
        if (field.hidden) continue;
        const v = values[field.key as keyof AppConfig];
        if (v !== undefined && v !== null && v !== '') persist[field.key] = v as string | number | boolean;
      }
      saveEnvFile(configPath, persist);

      c.snmp?.setOptions({ enabled: values.SNMP_ENABLED, community: values.SNMP_COMMUNITY });
      c.backgroundWorker.reconfigure();

      return { restartRequired, applied };
    },
  };
}
