export type DevicePolicyKind = 'route' | 'dns' | 'dest';

export interface DevicePolicyRow {
  id: string;
  siteId: string;
  deviceId: string;
  kind: DevicePolicyKind;
  value: string;
  updatedAt: string;
  createdAt: string;
}

export interface IDevicePolicyRepository {
  list(kind?: DevicePolicyKind): Promise<DevicePolicyRow[]>;
  listForDevice(deviceId: string): Promise<DevicePolicyRow[]>;
  setValues(deviceId: string, siteId: string, kind: 'dns' | 'dest', values: string[]): Promise<void>;
  setRoute(deviceId: string, siteId: string, gatewayName: string | null): Promise<void>;
}
