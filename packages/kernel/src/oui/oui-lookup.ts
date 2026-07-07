import { MacAddress } from '../value-objects/mac-address.js';
import { OUI_TABLE } from './oui-data.js';

/** Port for resolving a MAC address to a hardware vendor (ISP: one method). */
export interface IVendorLookup {
  resolve(mac: MacAddress): string | undefined;
}

/**
 * In-memory OUI vendor resolver. Ships with a curated table and can be extended
 * at runtime from an IEEE `oui.csv` file, keeping the class closed for
 * modification but open for extension.
 */
export class OuiLookup implements IVendorLookup {
  private readonly table = new Map<string, string>();

  constructor(seed: Readonly<Record<string, string>> = OUI_TABLE) {
    for (const [prefix, vendor] of Object.entries(seed)) {
      this.table.set(prefix.toLowerCase(), vendor);
    }
  }

  resolve(mac: MacAddress): string | undefined {
    if (mac.isLocallyAdministered) return 'Randomized/Private MAC';
    return this.table.get(mac.ouiPrefix);
  }

  /** Merge additional prefix→vendor mappings (e.g. parsed from oui.csv). */
  merge(entries: Iterable<readonly [string, string]>): void {
    for (const [prefix, vendor] of entries) {
      this.table.set(prefix.replace(/[:-]/g, '').toLowerCase().slice(0, 6), vendor);
    }
  }

  get size(): number {
    return this.table.size;
  }
}
