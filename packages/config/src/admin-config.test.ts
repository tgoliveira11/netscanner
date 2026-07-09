import { describe, expect, it, beforeEach } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { resetConfigCache } from './config-loader.js';
import { loadAdminConfig } from './runtime-config.js';

describe('loadAdminConfig', () => {
  beforeEach(() => resetConfigCache());

  it('prefers config.env over process environment for admin keys', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'ns-config-'));
    const file = path.join(dir, 'config.env');
    writeFileSync(file, 'PFSENSE_CONTROL_ENABLED=true\nAUTOBLOCK_ENABLED=false\nAUTOBLOCK_VLANS=LAN_GUEST\n');

    const config = loadAdminConfig(file, {
      PFSENSE_CONTROL_ENABLED: 'false',
      AUTOBLOCK_ENABLED: 'true',
      AUTOBLOCK_VLANS: 'LAN_IOT',
      AGENT_CONTROL_TOKEN: 'launch-daemon-token',
    });

    expect(config.PFSENSE_CONTROL_ENABLED).toBe(true);
    expect(config.AUTOBLOCK_ENABLED).toBe(false);
    expect(config.AUTOBLOCK_VLANS).toBe('LAN_GUEST');
    expect(config.AGENT_CONTROL_TOKEN).toBe('launch-daemon-token');
  });
});
