import type { LuciAuthMode } from './luci-client.js';

/** ISP/CBN Compal CPEs use RSA LuCI login even when classified as openwrt in inventory. */
export function resolveLuciAuthMode(input: {
  kind: 'openwrt' | 'compal';
  username?: string | null;
}): LuciAuthMode {
  if (input.kind === 'compal') return 'compal-rsa';
  if (input.username?.toUpperCase().startsWith('ISP_')) return 'compal-rsa';
  return 'plain';
}
