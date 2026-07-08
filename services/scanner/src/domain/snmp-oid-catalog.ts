/** Map common SNMP sysObjectID prefixes to hardware families. */
const OID_HINTS: { prefix: string; vendor: string; modelHint?: string; deviceType?: string }[] = [
  { prefix: '1.3.6.1.4.1.9.', vendor: 'Cisco', deviceType: 'switch' },
  { prefix: '1.3.6.1.4.1.11.', vendor: 'HPE/Aruba', deviceType: 'switch' },
  { prefix: '1.3.6.1.4.1.2011.', vendor: 'Huawei', deviceType: 'switch' },
  { prefix: '1.3.6.1.4.1.2636.', vendor: 'Juniper', deviceType: 'router' },
  { prefix: '1.3.6.1.4.1.8072.', vendor: 'Net-SNMP', modelHint: 'Linux host' },
  { prefix: '1.3.6.1.4.1.12325.', vendor: 'MikroTik', deviceType: 'router' },
  { prefix: '1.3.6.1.4.1.14988.', vendor: 'MikroTik', deviceType: 'router' },
  { prefix: '1.3.6.1.4.1.2435.', vendor: 'Brother', deviceType: 'printer' },
  { prefix: '1.3.6.1.4.1.641.', vendor: 'Lexmark', deviceType: 'printer' },
  { prefix: '1.3.6.1.4.1.1602.', vendor: 'Canon', deviceType: 'printer' },
  { prefix: '1.3.6.1.4.1.11.2.3.9.4.', vendor: 'HP', deviceType: 'printer' },
  { prefix: '1.3.6.1.4.1.6574.', vendor: 'Synology', deviceType: 'nas' },
  { prefix: '1.3.6.1.4.1.55062.', vendor: 'QNAP', deviceType: 'nas' },
];

export function resolveSnmpObjectId(oid: string | null | undefined): {
  vendor: string | null;
  modelHint: string | null;
  deviceType: string | null;
} {
  if (!oid) return { vendor: null, modelHint: null, deviceType: null };
  const norm = oid.replace(/^SNMPv2-SMI::enterprises\./, '1.3.6.1.4.1.');
  for (const row of OID_HINTS) {
    if (norm.startsWith(row.prefix)) {
      return {
        vendor: row.vendor,
        modelHint: row.modelHint ?? null,
        deviceType: row.deviceType ?? null,
      };
    }
  }
  return { vendor: null, modelHint: null, deviceType: null };
}
