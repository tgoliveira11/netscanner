import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { Logger } from '@netscanner/logger';
import type { SnmpV3Config } from './snmp-client.js';
import { SnmpClient } from './snmp-client.js';
import { resolveSnmpObjectId } from '../domain/snmp-oid-catalog.js';

export interface SnmpResult {
  sysDescr: string | null;
  sysName: string | null;
  sysObjectId: string | null;
  hrSystemUptime: string | null;
  hrDeviceStatus: string | null;
  prtGeneralPrinterName: string | null;
}

/**
 * SNMP v2c enrichment: sysDescr/sysName, HOST-RESOURCES, printer MIB.
 * Tries multiple communities when configured.
 */
export class SnmpEnricher {
  private client: SnmpClient;

  constructor(
    runner: ICommandRunner,
    logger: Logger,
    community: string | string[],
    enabled: boolean,
    v3: SnmpV3Config | null = null,
  ) {
    this.client = new SnmpClient(runner, logger, community, enabled, v3);
  }

  setOptions(opts: { enabled?: boolean; community?: string | string[]; v3?: SnmpV3Config | null }): void {
    if (opts.enabled !== undefined) this.client.setEnabled(opts.enabled);
    if (opts.community !== undefined) this.client.setCommunities(opts.community);
    if (opts.v3 !== undefined) this.client.setV3(opts.v3);
  }

  async query(ip: string): Promise<SnmpResult | null> {
    const lines = await this.client.get(ip, [
      'SNMPv2-MIB::sysDescr.0',
      'SNMPv2-MIB::sysName.0',
      'HOST-RESOURCES-MIB::hrSystemUptime.0',
      'HOST-RESOURCES-MIB::hrDeviceStatus.1',
      'SNMPv2-MIB::sysObjectID.0',
    ]);
    if (!lines?.length) return null;

    let prtName: string | null = null;
    const prt = await this.client.get(ip, ['PRINT-MIB::prtGeneralPrinterName.1']);
    if (prt?.[0]) prtName = prt[0];

    return {
      sysDescr: lines[0] ?? null,
      sysName: lines[1] ?? lines[0] ?? null,
      sysObjectId: lines[4] ?? null,
      hrSystemUptime: lines[2] ?? null,
      hrDeviceStatus: lines[3] ?? null,
      prtGeneralPrinterName: prtName,
    };
  }

  signalsFrom(result: SnmpResult): Record<string, unknown> {
    const oidHint = resolveSnmpObjectId(result.sysObjectId);
    return {
      snmpSysDescr: result.sysDescr,
      snmpSysName: result.sysName,
      snmpSysObjectId: result.sysObjectId,
      snmpOidVendor: oidHint.vendor,
      snmpOidModelHint: oidHint.modelHint,
      snmpOidDeviceType: oidHint.deviceType,
      snmpHrUptime: result.hrSystemUptime,
      snmpHrDeviceStatus: result.hrDeviceStatus,
      snmpPrinterName: result.prtGeneralPrinterName,
    };
  }
}
