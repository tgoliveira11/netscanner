import type { Logger } from '@netscanner/logger';
import type { IPassiveSignalStore } from '../domain/passive-signal-store.js';
import { MdnsPassiveListener } from './mdns-passive-listener.js';
import { SsdpPassiveListener } from './ssdp-passive-listener.js';
import { LldpPassiveListener } from './lldp-passive-listener.js';
import { DnsPassiveListener } from './dns-passive-listener.js';
import { IgmpPassiveListener } from './igmp-passive-listener.js';
import { Dhcpv6PassiveListener } from './dhcpv6-passive-listener.js';
import { TcpSynPassiveListener } from './tcp-syn-passive-listener.js';
import { CdpPassiveListener } from './cdp-passive-listener.js';
import { RemoteDnsPassiveListener, type RemoteDnsPassiveListenerOptions } from './remote-dns-passive-listener.js';
import { TsharkDeepListener } from './tshark-deep-listener.js';
import { LldpdNeighborSource } from './lldpd-neighbor-source.js';
import { NetdiscoverPassiveListener } from './netdiscover-passive-listener.js';
import type { ICommandRunner } from '@netscanner/os-abstraction';

export interface PassiveListenersOptions {
  store: IPassiveSignalStore;
  logger: Logger;
  runner?: ICommandRunner;
  iface?: string;
  lldpEnabled?: boolean;
  lldpStream?: boolean;
  /** Prefer lldpctl when available; falls back to tcpdump LLDP. */
  lldpdEnabled?: boolean;
  dnsEnabled?: boolean;
  p0fEnabled?: boolean;
  cdpEnabled?: boolean;
  igmpEnabled?: boolean;
  dhcpv6Enabled?: boolean;
  tsharkDeepEnabled?: boolean;
  netdiscoverEnabled?: boolean;
  elevated?: boolean;
  /** Remote DNS sniffers (pfSense / OpenWrt bridge) for cross-VLAN query visibility. */
  remoteDns?: RemoteDnsPassiveListenerOptions[];
}

/** Starts continuous passive listeners (mDNS, SSDP, DNS, IGMP, DHCPv6, LLDP, …). */
export class PassiveListeners {
  private mdns: MdnsPassiveListener | null = null;
  private ssdp: SsdpPassiveListener | null = null;
  private lldp: LldpPassiveListener | null = null;
  private lldpd: LldpdNeighborSource | null = null;
  private dns: DnsPassiveListener | null = null;
  private p0f: TcpSynPassiveListener | null = null;
  private cdp: CdpPassiveListener | null = null;
  private igmp: IgmpPassiveListener | null = null;
  private dhcpv6: Dhcpv6PassiveListener | null = null;
  private tshark: TsharkDeepListener | null = null;
  private netdiscover: NetdiscoverPassiveListener | null = null;
  private remoteDns: RemoteDnsPassiveListener[] = [];

  constructor(private readonly opts: PassiveListenersOptions) {}

  start(): void {
    this.mdns = new MdnsPassiveListener(this.opts.store, this.opts.logger);
    this.mdns.start();
    this.ssdp = new SsdpPassiveListener(this.opts.store, this.opts.logger);
    this.ssdp.start();

    const iface = this.opts.iface ?? 'en0';
    const elevated = this.opts.elevated ?? false;

    if (this.opts.lldpdEnabled && this.opts.runner) {
      this.lldpd = new LldpdNeighborSource({
        store: this.opts.store,
        logger: this.opts.logger,
        runner: this.opts.runner,
      });
      void this.lldpd.start().then(() => {
        // tcpdump LLDP only when lldpd is unavailable
        if (this.lldpd?.active) return;
        if (this.opts.lldpEnabled && this.opts.runner && elevated) {
          this.lldp = new LldpPassiveListener({
            runner: this.opts.runner,
            store: this.opts.store,
            logger: this.opts.logger,
            iface,
            stream: this.opts.lldpStream ?? true,
          });
          this.lldp.start();
        }
      });
    } else if (this.opts.lldpEnabled && this.opts.runner && elevated) {
      this.lldp = new LldpPassiveListener({
        runner: this.opts.runner,
        store: this.opts.store,
        logger: this.opts.logger,
        iface,
        stream: this.opts.lldpStream ?? true,
      });
      this.lldp.start();
    }

    if (this.opts.dnsEnabled && elevated) {
      this.dns = new DnsPassiveListener(this.opts.store, this.opts.logger, iface);
      this.dns.start();
    }
    if (this.opts.p0fEnabled && elevated) {
      this.p0f = new TcpSynPassiveListener(this.opts.store, this.opts.logger, iface);
      this.p0f.start();
    }
    if (this.opts.cdpEnabled && elevated) {
      this.cdp = new CdpPassiveListener(this.opts.store, this.opts.logger, iface);
      this.cdp.start();
    }
    if (this.opts.igmpEnabled && elevated) {
      this.igmp = new IgmpPassiveListener(this.opts.store, this.opts.logger, iface);
      this.igmp.start();
    }
    if (this.opts.dhcpv6Enabled && elevated) {
      this.dhcpv6 = new Dhcpv6PassiveListener(this.opts.store, this.opts.logger, iface);
      this.dhcpv6.start();
    }
    if (this.opts.tsharkDeepEnabled && this.opts.runner && elevated) {
      this.tshark = new TsharkDeepListener({
        store: this.opts.store,
        logger: this.opts.logger,
        runner: this.opts.runner,
        iface,
      });
      void this.tshark.start();
    }
    if (this.opts.netdiscoverEnabled && this.opts.runner && elevated) {
      this.netdiscover = new NetdiscoverPassiveListener({
        store: this.opts.store,
        logger: this.opts.logger,
        runner: this.opts.runner,
        iface,
      });
      void this.netdiscover.start();
    }
    for (const cfg of this.opts.remoteDns ?? []) {
      const remote = new RemoteDnsPassiveListener(this.opts.store, this.opts.logger, cfg);
      remote.start();
      this.remoteDns.push(remote);
    }
  }

  stop(): void {
    this.mdns?.stop();
    this.ssdp?.stop();
    this.lldp?.stop();
    this.lldpd?.stop();
    this.dns?.stop();
    this.p0f?.stop();
    this.cdp?.stop();
    this.igmp?.stop();
    this.dhcpv6?.stop();
    this.tshark?.stop();
    this.netdiscover?.stop();
    for (const r of this.remoteDns) r.stop();
    this.remoteDns = [];
    this.mdns = null;
    this.ssdp = null;
    this.lldp = null;
    this.lldpd = null;
    this.dns = null;
    this.p0f = null;
    this.cdp = null;
    this.igmp = null;
    this.dhcpv6 = null;
    this.tshark = null;
    this.netdiscover = null;
  }
}
