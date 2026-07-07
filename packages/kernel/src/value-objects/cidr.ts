import { InvalidCidrError } from '../errors.js';
import { IpAddress } from './ip-address.js';
import { type Result, ok, err } from '../result.js';

/**
 * Value object for an IPv4 network in CIDR notation (e.g. "192.168.1.0/24").
 * Provides bounded host enumeration used by the discovery ping sweep.
 */
export class Cidr {
  private constructor(
    public readonly network: IpAddress,
    public readonly prefix: number,
  ) {}

  static create(raw: string): Result<Cidr, InvalidCidrError> {
    const [addr, prefixStr] = raw.trim().split('/');
    const prefix = Number(prefixStr);
    if (!addr || Number.isNaN(prefix) || prefix < 0 || prefix > 32) {
      return err(new InvalidCidrError(`Invalid CIDR: "${raw}"`));
    }
    const ip = IpAddress.create(addr);
    if (!ip.ok) return err(new InvalidCidrError(`Invalid CIDR address: "${raw}"`));

    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    const networkInt = (ip.value.toInt() & mask) >>> 0;
    return ok(new Cidr(IpAddress.fromInt(networkInt), prefix));
  }

  get hostCount(): number {
    const total = 2 ** (32 - this.prefix);
    return this.prefix >= 31 ? total : total - 2; // exclude network & broadcast
  }

  /** Enumerate usable host addresses. Guards against enumerating huge ranges. */
  *hosts(maxHosts = 65536): Generator<IpAddress> {
    const base = this.network.toInt();
    const total = 2 ** (32 - this.prefix);
    const start = this.prefix >= 31 ? 0 : 1;
    const end = this.prefix >= 31 ? total : total - 1;
    let emitted = 0;
    for (let i = start; i < end; i++) {
      if (emitted++ >= maxHosts) return;
      yield IpAddress.fromInt((base + i) >>> 0);
    }
  }

  contains(ip: IpAddress): boolean {
    const mask = this.prefix === 0 ? 0 : (0xffffffff << (32 - this.prefix)) >>> 0;
    return ((ip.toInt() & mask) >>> 0) === this.network.toInt();
  }

  toString(): string {
    return `${this.network.value}/${this.prefix}`;
  }
}
