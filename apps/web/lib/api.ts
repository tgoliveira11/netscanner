import type {
  Device,
  HealthResponse,
  ScanSession,
  ScanType,
  UpdateDeviceRequest,
} from '@netscanner/contracts';

/** Thin typed REST client. Requests go through Next's /api rewrite to the gateway. */
async function json<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

export const api = {
  health: () => fetch('/api/health').then((r) => json<HealthResponse>(r)),

  interfaces: () =>
    fetch('/api/network/interfaces').then((r) =>
      json<{ interfaces: { name: string; cidr: string }[]; primaryCidr: string | null }>(r),
    ),

  listDevices: () => fetch('/api/devices').then((r) => json<{ devices: Device[]; total: number }>(r)),

  latestScan: () => fetch('/api/scans').then((r) => json<{ scan: ScanSession | null }>(r)),

  startScan: (body: { cidr?: string; scanType: ScanType }) =>
    fetch('/api/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<{ scan: ScanSession }>(r)),

  updateDevice: (id: string, body: UpdateDeviceRequest) =>
    fetch(`/api/devices/${id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<{ device: Device }>(r)),

  exportUrl: (format: 'json' | 'csv') => `/api/export?format=${format}`,
};
