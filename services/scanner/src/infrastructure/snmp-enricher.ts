import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { Logger } from '@netscanner/logger';

export interface SnmpResult {
  sysDescr: string | null;
  sysName: string | null;
}

/**
 * Best-effort SNMP v2c sysDescr/sysName via snmpget when installed on the host.
 */
export class SnmpEnricher {
  constructor(
    private readonly runner: ICommandRunner,
    private readonly logger: Logger,
    private readonly community: string,
    private readonly enabled: boolean,
  ) {}

  async query(ip: string): Promise<SnmpResult | null> {
    if (!this.enabled) return null;
    const has = await this.runner.which('snmpget');
    if (!has) return null;

    const res = await this.runner.run(
      'snmpget',
      [
        '-v2c',
        '-c',
        this.community,
        '-Oqv',
        '-t',
        '2',
        ip,
        'SNMPv2-MIB::sysDescr.0',
        'SNMPv2-MIB::sysName.0',
      ],
      { timeoutMs: 4000 },
    );
    if (res.code !== 0 || !res.stdout.trim()) return null;

    const lines = res.stdout
      .trim()
      .split('\n')
      .map((l) => l.replace(/^"(.*)"$/, '$1').trim())
      .filter(Boolean);
    if (!lines.length) return null;

    return {
      sysDescr: lines[0] ?? null,
      sysName: lines[1] ?? lines[0] ?? null,
    };
  }

  signalsFrom(result: SnmpResult): Record<string, unknown> {
    return {
      snmpSysDescr: result.sysDescr,
      snmpSysName: result.sysName,
    };
  }
}
