/** Inputs available to identify a device via an external fingerprint database. */
export interface FingerprintQuery {
  mac: string | null;
  dhcpFingerprint?: string | null;
  dhcpVendor?: string | null;
  dhcpv6Fingerprint?: string | null;
  hostname?: string | null;
  userAgents?: string[];
}

/** A resolved device identity from an external database (Fingerbank). */
export interface FingerprintResult {
  /** Leaf device name, e.g. "iPhone" or "Apple Watch". */
  deviceName: string;
  /** Full hierarchy path, e.g. "Hardware/Apple/iPhone/iPhone 15". */
  devicePath: string | null;
  version: string | null;
  /** Confidence score returned by the provider (0–100+). */
  score: number | null;
}

/**
 * Port for an external device-fingerprint database (DIP). Implemented by the
 * Fingerbank cloud client. Kept behind an interface so it is optional and
 * swappable, and so the pipeline never hard-depends on a third-party service.
 */
export interface IDeviceFingerprintResolver {
  resolve(query: FingerprintQuery): Promise<FingerprintResult | null>;
}
