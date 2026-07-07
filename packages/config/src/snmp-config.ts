import type { AppConfig } from './env-schema.js';

/** Resolve SNMP v2c communities from SNMP_COMMUNITIES or SNMP_COMMUNITY. */
export function resolveSnmpCommunities(config: AppConfig): string[] {
  const raw = config.SNMP_COMMUNITIES?.trim() || config.SNMP_COMMUNITY;
  return raw
    .split(',')
    .map((c) => c.trim())
    .filter(Boolean);
}

export function parseWifiPorts(csv: string): Set<number> {
  const ports = new Set<number>();
  for (const p of csv.split(',')) {
    const n = Number.parseInt(p.trim(), 10);
    if (!Number.isNaN(n)) ports.add(n);
  }
  return ports;
}

export interface SnmpV3Config {
  user: string;
  authPass: string;
  privPass: string;
  authProto: string;
  privProto: string;
  secLevel: string;
}

export function resolveSnmpV3(config: AppConfig): SnmpV3Config | null {
  const user = config.SNMP_V3_USER?.trim();
  if (!user) return null;
  return {
    user,
    authPass: config.SNMP_V3_AUTH_PASS ?? '',
    privPass: config.SNMP_V3_PRIV_PASS ?? '',
    authProto: config.SNMP_V3_AUTH_PROTO ?? 'SHA',
    privProto: config.SNMP_V3_PRIV_PROTO ?? 'AES',
    secLevel: config.SNMP_V3_SEC_LEVEL ?? 'authPriv',
  };
}
