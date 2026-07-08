import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { Logger } from '@netscanner/logger';

export interface SnmpWalkRow {
  oid: string;
  value: string;
}

export interface SnmpV3Config {
  user: string;
  authPass: string;
  privPass: string;
  authProto: string;
  privProto: string;
  secLevel: string;
}

/** Thin wrapper around snmpget/snmpwalk with v2c multi-community or SNMPv3. */
export class SnmpClient {
  private communities: string[];
  private v3: SnmpV3Config | null;

  constructor(
    private readonly runner: ICommandRunner,
    private readonly logger: Logger,
    communities: string | string[],
    private enabled: boolean,
    v3: SnmpV3Config | null = null,
  ) {
    this.communities = (Array.isArray(communities) ? communities : communities.split(','))
      .map((c) => c.trim())
      .filter(Boolean);
    if (!this.communities.length) this.communities = ['public'];
    this.v3 = v3;
  }

  setCommunities(communities: string | string[]): void {
    this.communities = (Array.isArray(communities) ? communities : communities.split(','))
      .map((c) => c.trim())
      .filter(Boolean);
  }

  setV3(v3: SnmpV3Config | null): void {
    this.v3 = v3;
  }

  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  async available(): Promise<boolean> {
    if (!this.enabled) return false;
    return this.runner.which('snmpget');
  }

  private v3Args(): string[] {
    const v = this.v3!;
    const args = ['-v3', '-u', v.user, '-l', v.secLevel, '-a', v.authProto, '-A', v.authPass];
    if (v.secLevel === 'authPriv') args.push('-x', v.privProto, '-X', v.privPass);
    return args;
  }

  async get(host: string, oids: string[]): Promise<string[] | null> {
    if (!this.enabled || !oids.length) return null;
    if (!(await this.available())) return null;

    const attempts: string[][] = [];
    if (this.v3?.user) attempts.push(this.v3Args());
    for (const community of this.communities) {
      attempts.push(['-v2c', '-c', community]);
    }

    for (const auth of attempts) {
      const res = await this.runner.run(
        'snmpget',
        [...auth, '-Oqv', '-t', '2', host, ...oids],
        { timeoutMs: 5000 },
      );
      if (res.code !== 0 || !res.stdout.trim()) continue;
      const lines = res.stdout
        .trim()
        .split('\n')
        .map((l) => l.replace(/^"(.*)"$/, '$1').trim())
        .filter(Boolean);
      if (lines.length) return lines;
    }
    return null;
  }

  async walk(host: string, oid: string): Promise<SnmpWalkRow[]> {
    if (!this.enabled) return [];
    if (!(await this.runner.which('snmpwalk'))) return [];

    const attempts: string[][] = [];
    if (this.v3?.user) attempts.push(this.v3Args());
    for (const community of this.communities) {
      attempts.push(['-v2c', '-c', community]);
    }

    for (const auth of attempts) {
      const res = await this.runner.run(
        'snmpwalk',
        [...auth, '-On', '-t', '3', host, oid],
        { timeoutMs: 20_000 },
      );
      if (res.code !== 0 || !res.stdout.trim()) continue;
      const rows: SnmpWalkRow[] = [];
      for (const line of res.stdout.split('\n')) {
        // snmpwalk -On: ".1.3… = STRING: \"AA BB …\"" / "INTEGER: 2" / "Hex-STRING: …"
        const m = /^(\S+)\s+=\s+(.+)$/.exec(line.trim());
        if (!m) continue;
        rows.push({ oid: m[1]!, value: normalizeSnmpWalkValue(m[2]!) });
      }
      if (rows.length) return rows;
    }
    return [];
  }

  static parseMac(value: string): string | null {
    const hex = normalizeSnmpWalkValue(value);
    const parts = hex.split(/[\s:.-]+/).filter(Boolean);
    if (parts.length !== 6) return null;
    if (!parts.every((p) => /^[0-9a-fA-F]{1,2}$/.test(p))) return null;
    return parts.map((p) => p.padStart(2, '0')).join(':').toLowerCase();
  }
}

/** Strip net-snmp type tags and surrounding quotes from a walk value. */
export function normalizeSnmpWalkValue(raw: string): string {
  let v = raw.trim();
  v = v.replace(
    /^(?:Hex-STRING|STRING|INTEGER|Gauge32|Counter(?:32|64)|Unsigned32|Timeticks|OID|IpAddress|Network Address):\s*/i,
    '',
  );
  v = v.replace(/^"(.*)"$/s, '$1').trim();
  return v;
}
