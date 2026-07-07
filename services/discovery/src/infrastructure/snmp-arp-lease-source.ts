import { MacAddress, isOk } from '@netscanner/kernel';
import type { Logger } from '@netscanner/logger';
import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { IRouterLeaseSource, RouterLease } from '../domain/router-lease-source.js';

const OID_IP_NET_TO_MEDIA_PHYS = '1.3.6.1.2.1.4.22.1.2';

/**
 * Reads the gateway ARP/MAC table via SNMP ipNetToMediaTable.
 * Fragile on some home routers but common when SNMP is enabled on the gateway.
 */
export class SnmpArpLeaseSource implements IRouterLeaseSource {
  readonly name = 'snmp-arp';

  constructor(
    private readonly runner: ICommandRunner,
    private readonly logger: Logger,
    private readonly host: string,
    private readonly communities: string[],
    private readonly enabled: boolean,
  ) {}

  async getLeases(): Promise<RouterLease[]> {
    if (!this.enabled || !this.host) return [];
    if (!(await this.runner.which('snmpwalk'))) return [];

    for (const community of this.communities) {
      const res = await this.runner.run(
        'snmpwalk',
        ['-v2c', '-c', community, '-On', '-t', '3', this.host, OID_IP_NET_TO_MEDIA_PHYS],
        { timeoutMs: 15_000 },
      );
      if (res.code !== 0 || !res.stdout.trim()) continue;

      const leases: RouterLease[] = [];
      for (const line of res.stdout.split('\n')) {
        const m = /^(\S+)\s+=\s+(?:Hex-STRING:\s+)?(.+)$/.exec(line.trim());
        if (!m) continue;
        const oidParts = m[1]!.split('.');
        const ip = oidParts.slice(-4).join('.');
        const macRaw = m[2]!.replace(/Hex-STRING:\s*/i, '').trim();
        const macParts = macRaw.split(/[\s:]+/).filter(Boolean);
        if (macParts.length !== 6) continue;
        const macStr = macParts.map((p) => p.padStart(2, '0')).join(':');
        const parsed = MacAddress.create(macStr);
        if (!isOk(parsed)) continue;
        leases.push({
          ip,
          mac: parsed.value.value,
          hostname: null,
          interface: null,
          description: null,
          online: true,
        });
      }
      if (leases.length) {
        this.logger.info({ count: leases.length, host: this.host }, 'SNMP ARP leases fetched');
        return leases;
      }
    }
    return [];
  }
}
