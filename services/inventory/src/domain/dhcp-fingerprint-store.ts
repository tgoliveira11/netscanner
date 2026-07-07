/** Persisted DHCP fingerprint (mirrors discovery DhcpFingerprint + timestamps). */
export interface StoredDhcpFingerprint {
  mac: string;
  fingerprint: string;
  vendorClass: string | null;
  hostname: string | null;
  capturedAt: string;
}

/** Port for durable DHCP fingerprint storage (survives agent restarts). */
export interface IDhcpFingerprintStore {
  save(fp: StoredDhcpFingerprint): Promise<void>;
  loadAll(): Promise<StoredDhcpFingerprint[]>;
}
