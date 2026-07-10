import { createHash } from 'node:crypto';
import vm from 'node:vm';

/** ISP/CBN Compal LuCI username: ISP_ + last 3 MAC octets (hex, uppercase, no colons). */
export function deriveIspUsername(mac: string): string | null {
  const hex = mac.replace(/[^0-9a-fA-F]/g, '').toUpperCase();
  if (hex.length < 6) return null;
  return `ISP_${hex.slice(-6)}`;
}

interface JsEncryptLike {
  setDefaultPrivateKey(): void;
  encrypt(value: string): string | false;
}

/** Encrypt LuCI credentials with the device-bundled JSEncrypt (RSA PKCS#1 v1.5). */
export function encryptCompalLuciCredentials(
  jsEncryptSource: string,
  username: string,
  password: string,
): { encryptedUsername: string; encryptedPassword: string } {
  const sandbox: Record<string, unknown> = {
    window: {} as Record<string, unknown>,
    navigator: { appName: 'node', userAgent: 'node' },
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(jsEncryptSource, sandbox, { timeout: 5000 });

  const JSEncryptCtor = (sandbox.JSEncrypt ??
    (sandbox.window as { JSEncrypt?: new () => JsEncryptLike }).JSEncrypt) as (new () => JsEncryptLike) | undefined;
  if (!JSEncryptCtor) throw new Error('JSEncrypt not found in device jsencrypt.min.js');

  const crypt = new JSEncryptCtor();
  crypt.setDefaultPrivateKey();
  const encryptedUsername = crypt.encrypt(username);
  const encryptedPassword = crypt.encrypt(password);
  if (!encryptedUsername || !encryptedPassword) throw new Error('Compal LuCI RSA encrypt failed');

  return { encryptedUsername, encryptedPassword };
}

/** Cache key for fetched jsencrypt.min.js per device host + script hash. */
export function jsEncryptCacheKey(baseUrl: string, scriptSource: string): string {
  const host = new URL(baseUrl).hostname;
  const hash = createHash('sha256').update(scriptSource).digest('hex').slice(0, 16);
  return `${host}:${hash}`;
}

/** Parse `var wifidevs = {...};` from Compal clarostyle wireless page. */
export function parseCompalWirelessNetworkIds(html: string): string[] {
  const block = html.match(/var wifidevs\s*=\s*(\{[\s\S]*?\});/);
  if (block) {
    try {
      const obj = JSON.parse(block[1]!) as Record<string, string>;
      const ids = Object.keys(obj);
      if (ids.length) return ids;
    } catch {
      /* fall through */
    }
  }
  const poll = html.match(/wireless_status\/([a-zA-Z0-9._,]+)/);
  if (poll) {
    return poll[1]!.split(',').filter(Boolean);
  }
  return [];
}

export interface CompalWirelessStatusRow {
  id?: string;
  ifname?: string;
  ssid?: string;
  up?: boolean;
  disabled?: boolean;
  mode?: string;
  channel?: number | string;
  device?: { device?: string; up?: boolean };
  assoclist?: Record<string, { signal?: number; inactive?: number }>;
}

/** Extract JSON from Compal wireless_status response (may be bare array or HTML-wrapped on reboot). */
export function parseCompalWirelessStatusBody(body: string): unknown | null {
  const trimmed = body.trim();
  if (!trimmed) return null;
  if (/luci_username|sysauth|login-form|cbi-map/i.test(trimmed) && !trimmed.startsWith('[')) return null;

  const attempts = [trimmed];
  const arrayMatch = trimmed.match(/\[[\s\S]*\]/);
  if (arrayMatch?.[0]) attempts.push(arrayMatch[0]);
  const objectMatch = trimmed.match(/\{[\s\S]*\}/);
  if (objectMatch?.[0] && !arrayMatch) attempts.push(objectMatch[0]);

  for (const candidate of attempts) {
    try {
      return JSON.parse(candidate);
    } catch {
      /* try next */
    }
  }
  return null;
}

/** Map Compal `wireless_status` JSON array to normalized rows. */
export function parseCompalWirelessStatusJson(raw: unknown): CompalWirelessStatusRow[] {
  if (!Array.isArray(raw)) return [];
  return raw.filter((row): row is CompalWirelessStatusRow => row != null && typeof row === 'object');
}
