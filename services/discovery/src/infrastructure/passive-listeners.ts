import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';
import { MdnsPassiveListener } from './mdns-passive-listener.js';
import { SsdpPassiveListener } from './ssdp-passive-listener.js';
import { LldpPassiveListener } from './lldp-passive-listener.js';
import type { ICommandRunner } from '@netscanner/os-abstraction';

export interface PassiveListenersOptions {
  store: IPassiveSignalStore;
  logger: Logger;
  runner?: ICommandRunner;
  iface?: string;
  lldpEnabled?: boolean;
}

/** Starts Tier-1 continuous passive listeners (mDNS, SSDP, optional LLDP). */
export class PassiveListeners {
  private mdns: MdnsPassiveListener | null = null;
  private ssdp: SsdpPassiveListener | null = null;
  private lldp: LldpPassiveListener | null = null;

  constructor(private readonly opts: PassiveListenersOptions) {}

  start(): void {
    this.mdns = new MdnsPassiveListener(this.opts.store, this.opts.logger);
    this.mdns.start();
    this.ssdp = new SsdpPassiveListener(this.opts.store, this.opts.logger);
    this.ssdp.start();
    if (this.opts.lldpEnabled && this.opts.runner && this.opts.iface) {
      this.lldp = new LldpPassiveListener(this.opts.runner, this.opts.store, this.opts.logger, this.opts.iface);
      this.lldp.start();
    }
  }

  stop(): void {
    this.mdns?.stop();
    this.ssdp?.stop();
    this.lldp?.stop();
    this.mdns = null;
    this.ssdp = null;
    this.lldp = null;
  }
}
