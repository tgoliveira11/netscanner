import type {
  Device,
  HealthResponse,
  ScanSession,
  ScanType,
  SpeedTestReport,
  SpeedTestResult,
  TopologyResponse,
  UpdateDeviceRequest,
  ActiveSiteResponse,
  NetworkSite,
  UpdateSiteRequest,
} from '@netscanner/contracts';

/** Agent API base — same-origin on :4000 bundle; :4000 when Next dev runs on :3000. */
export function apiBase(): string {
  if (process.env.NEXT_PUBLIC_API_URL) return process.env.NEXT_PUBLIC_API_URL.replace(/\/$/, '');
  if (typeof window === 'undefined') return 'http://127.0.0.1:4000';
  if (window.location.port === '3000') {
    return `${window.location.protocol}//${window.location.hostname}:4000`;
  }
  return window.location.origin;
}

function apiUrl(path: string): string {
  return `${apiBase()}${path.startsWith('/') ? path : `/${path}`}`;
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function sleep(ms: number): Promise<void> {
  await new Promise((r) => setTimeout(r, ms));
}

async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  return fetch(apiUrl(path), init);
}

/** Restart agent; POST only acknowledges shutdown — always poll until /api/health responds. */
async function agentRestart(): Promise<{ ok: boolean; restarting: boolean }> {
  try {
    await apiFetch('/api/admin/restart', { method: 'POST' });
  } catch {
    /* server closes the socket during exit */
  }

  await sleep(500);
  for (let i = 0; i < 45; i++) {
    await sleep(1000);
    try {
      const res = await apiFetch('/api/health', { cache: 'no-store' });
      if (res.ok) return { ok: true, restarting: true };
    } catch {
      /* agent still starting */
    }
  }
  throw new Error('Agent não respondeu após o restart (aguardou 45s). Use: sudo netscanner-ctl restart');
}

export const api = {
  health: () => apiFetch('/api/health').then((r) => json<HealthResponse>(r)),

  interfaces: () =>
    apiFetch('/api/network/interfaces').then((r) =>
      json<{
        interfaces: { name: string; cidr: string }[];
        primaryCidr: string | null;
        scanCidrs: string[];
      }>(r),
    ),

  listDevices: () => apiFetch('/api/devices').then((r) => json<{ devices: Device[]; total: number }>(r)),

  topology: (opts?: { since?: string }) => {
    const qs = opts?.since ? `?since=${encodeURIComponent(opts.since)}` : '';
    return apiFetch(`/api/topology${qs}`).then((r) => json<TopologyResponse>(r));
  },

  relations: () =>
    apiFetch('/api/relations').then((r) =>
      json<{
        edges: { from: string; to: string; kind: string; label: string; bytes?: number }[];
        externalContacts: { deviceId: string; domain: string; vendor?: string }[];
        dnsLog: { at: string; deviceId: string; deviceLabel: string; message: string }[];
      }>(r),
    ),

  latestScan: () => apiFetch('/api/scans').then((r) => json<{ scan: ScanSession | null }>(r)),

  startScan: (body: { cidr?: string; allCidrs?: boolean; scanType: ScanType }) =>
    apiFetch('/api/scans', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then(async (r) => {
      if (!r.ok) {
        const err = (await r.json().catch(() => null)) as { error?: string } | null;
        throw new Error(err?.error ?? `${r.status} ${r.statusText}`);
      }
      return json<{ scan: ScanSession }>(r);
    }),

  updateDevice: (id: string, body: UpdateDeviceRequest) =>
    apiFetch(`/api/devices/${id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<{ device: Device }>(r)),

  exportUrl: (format: 'json' | 'csv') => apiUrl(`/api/export?format=${format}`),

  adminObservability: () => apiFetch('/api/admin/observability').then((r) => json<AdminObservability>(r)),

  adminLogs: (tail = 200) => apiFetch(`/api/admin/logs?tail=${tail}`).then((r) => json<AdminLogsResponse>(r)),

  adminConfig: () => apiFetch('/api/admin/config').then((r) => json<AdminConfigResponse>(r)),

  adminWireless: () => apiFetch('/api/admin/wireless').then((r) => json<AdminWirelessResponse>(r)),

  adminUpdateConfig: (body: Record<string, unknown>) =>
    apiFetch('/api/admin/config', {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<AdminConfigPatchResponse>(r)),

  agentRestart,

  speedTestReport: (days = 30) =>
    apiFetch(`/api/speed-tests/report?days=${days}`).then((r) => json<SpeedTestReport>(r)),

  runSpeedTest: () =>
    apiFetch('/api/speed-tests/run', { method: 'POST' }).then(async (r) => {
      if (!r.ok) {
        const err = (await r.json().catch(() => null)) as { error?: string } | null;
        throw new Error(err?.error ?? `${r.status} ${r.statusText}`);
      }
      return json<{ result: SpeedTestResult }>(r);
    }),

  listSites: () => apiFetch('/api/sites').then((r) => json<{ sites: NetworkSite[] }>(r).then((b) => b.sites)),

  activeSite: () => apiFetch('/api/sites/active').then((r) => json<ActiveSiteResponse>(r)),

  refreshSite: () =>
    apiFetch('/api/sites/refresh', { method: 'POST' }).then((r) => json<ActiveSiteResponse>(r)),

  confirmSite: (siteId: string) =>
    apiFetch('/api/sites/confirm', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ siteId }),
    }).then((r) => json<ActiveSiteResponse>(r)),

  lockSite: (siteId: string | null) =>
    apiFetch('/api/sites/lock', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ siteId }),
    }).then((r) => json<ActiveSiteResponse>(r)),

  updateSite: (id: string, patch: UpdateSiteRequest) =>
    apiFetch(`/api/sites/${id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(patch),
    }).then((r) => json<{ site: NetworkSite }>(r).then((b) => b.site)),
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
  capabilities: { nmap: boolean; elevated: boolean; nmapOffReason?: 'disabled-by-config' | 'not-in-path' };
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

export interface AdminWirelessSsid {
  device: string;
  ifname: string;
  ssid: string;
  up: boolean;
  mode?: string;
  channel?: number | string;
  disabled?: boolean;
}

export interface AdminWirelessRouter {
  url: string;
  host: string;
  ok: boolean;
  error?: string;
  wifiCapable: boolean;
  radioCount: number;
  ssids: AdminWirelessSsid[];
}

export interface AdminWirelessResponse {
  configured: boolean;
  count?: number;
  transmitting?: number;
  routers: AdminWirelessRouter[];
}

export type { SpeedTestReport, SpeedTestResult, ActiveSiteResponse, NetworkSite } from '@netscanner/contracts';
