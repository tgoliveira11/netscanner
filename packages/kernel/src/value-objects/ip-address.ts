import { InvalidIpAddressError } from '../errors.js';
import { type Result, ok, err } from '../result.js';

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

/** Value object for an IPv4 address with helpers for numeric conversion. */
export class IpAddress {
  private constructor(
    public readonly value: string,
    private readonly octets: readonly [number, number, number, number],
  ) {}

  static create(raw: string): Result<IpAddress, InvalidIpAddressError> {
    const match = IPV4_RE.exec(raw.trim());
    if (!match) return err(new InvalidIpAddressError(`Invalid IPv4 address: "${raw}"`));
    const octets = match.slice(1, 5).map(Number) as [number, number, number, number];
    if (octets.some((o) => o < 0 || o > 255)) {
      return err(new InvalidIpAddressError(`Octet out of range: "${raw}"`));
    }
    return ok(new IpAddress(octets.join('.'), octets));
  }

  /** Convert to unsigned 32-bit integer (host byte order). */
  toInt(): number {
    const [a, b, c, d] = this.octets;
    return ((a << 24) >>> 0) + (b << 16) + (c << 8) + d;
  }

  static fromInt(n: number): IpAddress {
    const octets: [number, number, number, number] = [
      (n >>> 24) & 0xff,
      (n >>> 16) & 0xff,
      (n >>> 8) & 0xff,
      n & 0xff,
    ];
    return new IpAddress(octets.join('.'), octets);
  }

  get isPrivate(): boolean {
    const [a, b] = this.octets;
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }

  equals(other: IpAddress): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }
}
