/** Read-only cloud identity for a LAN device (e.g. Tuya / Smart Life). */
export interface CloudDeviceIdentity {
  deviceId: string;
  name: string;
  productName: string | null;
  category: string | null;
  mac: string | null;
  ip: string | null;
  online: boolean | null;
}

/**
 * Durable catalog store (SQLite) so Tuya/Smart Life identities survive restarts
 * and API refreshes can stay infrequent.
 */
export interface ICloudDeviceIdentityCatalogStore {
  loadAll(): Promise<CloudDeviceIdentity[]>;
  /** Replace the full catalog atomically (removals from the cloud are dropped). */
  replaceAll(rows: readonly CloudDeviceIdentity[]): Promise<void>;
}

/**
 * Optional cloud catalog that maps MAC/IP → friendly product identity.
 * Implementations must never send control commands to devices.
 */
export interface ICloudDeviceIdentitySource {
  lookupByMac(mac: string): CloudDeviceIdentity | null;
  lookupByIp(ip: string): CloudDeviceIdentity | null;
  /** Load previously persisted catalog into memory (no network). */
  hydrate?(): Promise<number>;
  /** Refresh remote catalog; returns number of devices indexed. */
  refresh(): Promise<number>;
  size(): number;
}
