import type { LuciAuthMode } from './luci-client.js';

/** LuCI auth mode — Compal RSA only when scrape target kind is explicitly `compal`. */
export function resolveLuciAuthMode(input: {
  kind: 'openwrt' | 'compal';
  username?: string | null;
}): LuciAuthMode {
  if (input.kind === 'compal') return 'compal-rsa';
  return 'plain';
}
