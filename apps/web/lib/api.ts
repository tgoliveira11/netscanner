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

  adminObservability: () => fetch('/api/admin/observability').then((r) => json<AdminObservability>(r)),

  adminLogs: (tail = 200) =>
    fetch(`/api/admin/logs?tail=${tail}`).then((r) => json<AdminLogsResponse>(r)),

  adminConfig: () => fetch('/api/admin/config').then((r) => json<AdminConfigResponse>(r)),

  adminUpdateConfig: (body: Record<string, unknown>) =>
    fetch('/api/admin/config', {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<AdminConfigPatchResponse>(r)),

  agentRestart: () =>
    fetch('/api/admin/restart', { method: 'POST' }).then((r) => json<{ ok: boolean; restarting: boolean }>(r)),
};

export interface ConfigFieldSchema {
  key: string;
  label: string;
  description: string;
  type: 'string' | 'number' | 'boolean' | 'secret';
  group: string;
  restartRequired: boolean;
}

export interface AdminObservability {
  version: string;
  uptimeSec: number;
  pid: number;
  nodeVersion: string;
  cwd: string;
  configPath: string;
  capabilities: { nmap: boolean; elevated: boolean };
  background: Record<string, unknown>;
  inventory: { deviceCount: number };
  scans: { latest: unknown; active: unknown };
  interfaces: { name: string; cidr: string }[];
  primaryCidr: string | null;
  dhcpFingerprints: unknown[];
  passiveSample: unknown[];
  router: { configured: boolean; source?: string };
}

export interface AdminLogLine {
  at: string | null;
  levelLabel: string;
  msg: string;
  raw: Record<string, unknown>;
}

export interface AdminLogsResponse {
  memory: AdminLogLine[];
  file: AdminLogLine[];
}

export interface AdminConfigResponse {
  schema: ConfigFieldSchema[];
  values: Record<string, string | number | boolean | null>;
  configPath: string;
}

export interface AdminConfigPatchResponse {
  ok: boolean;
  values: Record<string, string | number | boolean | null>;
  restartRequired: boolean;
  applied: string[];
}
