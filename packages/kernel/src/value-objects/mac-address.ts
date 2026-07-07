import { InvalidMacAddressError } from '../errors.js';
import { type Result, ok, err } from '../result.js';

const MAC_RE = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;

/**
 * Value object for a 48-bit MAC address. Immutable and always normalized to
 * lowercase colon-separated form so equality and OUI lookups are consistent.
 */
export class MacAddress {
  private constructor(public readonly value: string) {}

  static create(raw: string): Result<MacAddress, InvalidMacAddressError> {
    const trimmed = raw.trim();
    if (!MAC_RE.test(trimmed)) {
      return err(new InvalidMacAddressError(`Invalid MAC address: "${raw}"`));
    }
    const normalized = trimmed.toLowerCase().replace(/-/g, ':');
    return ok(new MacAddress(normalized));
  }

  /** First three octets (OUI) without separators, e.g. "aabbcc". */
  get ouiPrefix(): string {
    return this.value.split(':').slice(0, 3).join('');
  }

  /** Locally-administered / randomized MACs have the 2nd-least-significant bit set. */
  get isLocallyAdministered(): boolean {
    const firstOctet = parseInt(this.value.slice(0, 2), 16);
    return (firstOctet & 0b10) !== 0;
  }

  equals(other: MacAddress): boolean {
    return this.value === other.value;
  }

  toString(): string {
    return this.value;
  }
}
