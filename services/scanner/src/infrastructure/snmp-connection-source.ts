import type { Logger } from '@netscanner/logger';
import type { IConnectionSource, ConnectionLookup } from '@netscanner/contracts';
import type { ICommandRunner } from '@netscanner/os-abstraction';
import type { SnmpV3Config } from './snmp-client.js';
import { SnmpClient } from './snmp-client.js';

const OID_FDB_ADDR = '1.3.6.1.2.1.17.4.3.1.1';
const OID_FDB_PORT = '1.3.6.1.2.1.17.4.3.1.2';
const OID_BASE_PORT_IF = '1.3.6.1.2.1.17.4.1.1.2';
const OID_IF_DESCR = '1.3.6.1.2.1.2.2.1.2';

/** BRIDGE-MIB MAC→port→ifDescr for definitive wired/WiFi when switch exposes SNMP. */
export class SnmpConnectionSource implements IConnectionSource {
  readonly name = 'snmp-bridge';
  private readonly client: SnmpClient;
  private macToPort = new Map<string, number>();
  private portToIfName = new Map<number, string>();

  constructor(
    runner: ICommandRunner,
    logger: Logger,
    private readonly switchHost: string,
    communities: string,
    private readonly wifiPorts: Set<number>,
    enabled: boolean,
    v3: SnmpV3Config | null = null,
  ) {
    this.client = new SnmpClient(runner, logger, communities, enabled && Boolean(switchHost), v3);
  }

  async refresh(): Promise<void> {
    this.macToPort.clear();
    this.portToIfName.clear();
    if (!(await this.client.available())) return;

    const [fdbAddr, fdbPort, basePortIf, ifDescr] = await Promise.all([
      this.client.walk(this.switchHost, OID_FDB_ADDR),
      this.client.walk(this.switchHost, OID_FDB_PORT),
      this.client.walk(this.switchHost, OID_BASE_PORT_IF),
      this.client.walk(this.switchHost, OID_IF_DESCR),
    ]);

    const portByIndex = new Map<string, number>();
    for (const row of fdbPort) {
      const idx = row.oid.split('.').pop();
      if (idx) portByIndex.set(idx, Number.parseInt(row.value, 10));
    }
    for (const row of fdbAddr) {
      const idx = row.oid.split('.').pop();
      const mac = SnmpClient.parseMac(row.value);
      const port = idx ? portByIndex.get(idx) : undefined;
      if (mac && port != null) this.macToPort.set(mac, port);
    }

    const ifIndexByBridgePort = new Map<number, number>();
    for (const row of basePortIf) {
      const bridgePort = Number(row.oid.split('.').pop());
      const ifIndex = Number.parseInt(row.value, 10);
      if (!Number.isNaN(bridgePort) && !Number.isNaN(ifIndex)) {
        ifIndexByBridgePort.set(bridgePort, ifIndex);
      }
    }

    const ifNameByIndex = new Map<number, string>();
    for (const row of ifDescr) {
      const ifIndex = Number(row.oid.split('.').pop());
      if (!Number.isNaN(ifIndex)) ifNameByIndex.set(ifIndex, row.value.replace(/^"(.*)"$/, '$1'));
    }

    for (const [bridgePort, ifIndex] of ifIndexByBridgePort) {
      const name = ifNameByIndex.get(ifIndex);
      if (name) this.portToIfName.set(bridgePort, name);
    }
  }

  lookupByMac(mac: string): ConnectionLookup | null {
    const port = this.macToPort.get(mac.toLowerCase());
    if (port == null) return null;
    const ifName = this.portToIfName.get(port) ?? `port${port}`;
    const wifi =
      this.wifiPorts.has(port) || /wlan|wifi|radio|ath|dot11|air/i.test(ifName);
    return {
      type: wifi ? 'wifi' : 'wired',
      port,
      ifName,
      basis: `SNMP BRIDGE-MIB port ${port} (${ifName})`,
    };
  }
}
