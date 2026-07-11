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
  PingResponse,
  TracerouteResponse,
  DnsLookupResponse,
  PortScanResponse,
  WifiScanResponse,
  CameraScanResponse,
  ControlStatus,
  ControlBootstrap,
  ControlVerifyResult,
  PolicyAuditEntry,
  CompalAdminResponse,
  CompalActionResponse,
  CompalStreamEvent,
  CompalDoneEvent,
  CpeAccessListResponse,
  CpeAccessOpenRequest,
  CpeAccessOpenResponse,
  DhcpReservationRequest,
  BandwidthLimitRequest,
  ParentalScheduleRequest,
  RoutePolicyRequest,
  RouteOption,
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
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? `${res.status} ${res.statusText}`);
  }
  return res.json() as Promise<T>;
}

async function sleep(ms: number): Promise<void> {
  await new Promise((r) => setTimeout(r, ms));
}

async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  return fetch(apiUrl(path), init);
}

async function readNdjsonStream<T>(
  res: Response,
  onLine: (line: T) => void,
): Promise<void> {
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(body.error ?? `${res.status} ${res.statusText}`);
  }
  const reader = res.body?.getReader();
  if (!reader) throw new Error('No response body');
  const dec = new TextDecoder();
  let buf = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let nl = buf.indexOf('\n');
    while (nl >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (line) onLine(JSON.parse(line) as T);
      nl = buf.indexOf('\n');
    }
  }
  const tail = buf.trim();
  if (tail) onLine(JSON.parse(tail) as T);
}

async function compalActionStream(
  path: string,
  body: Record<string, unknown>,
  onEvent: (event: CompalStreamEvent) => void,
): Promise<CompalDoneEvent> {
  let result: CompalDoneEvent | undefined;
  const res = await apiFetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/x-ndjson' },
    body: JSON.stringify(body),
  });
  await readNdjsonStream<CompalStreamEvent>(res, (event) => {
    onEvent(event);
    if (event.type === 'done') result = event;
  });
  if (result === undefined) throw new Error('Compal action ended without result');
  if (!result.ok) throw new Error(result.message ?? 'Compal action failed');
  return result;
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
  throw new Error('Agent did not respond after restart (waited 45s). Try: sudo netscanner-ctl restart');
}

export const api = {
  health: () => apiFetch('/api/health').then((r) => json<HealthResponse>(r)),

  getClusterStatus: () => apiFetch('/api/cluster/status').then((r) => json(r)),

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

  adminCompal: () => apiFetch('/api/admin/compal').then((r) => json<CompalAdminResponse>(r)),

  adminCpeList: () => apiFetch('/api/admin/cpe').then((r) => json<CpeAccessListResponse>(r)),

  adminCpeOpen: (body: CpeAccessOpenRequest) =>
    apiFetch('/api/admin/cpe/open', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<CpeAccessOpenResponse>(r)),

  adminCpeClose: (id: string) =>
    apiFetch(`/api/admin/cpe/${encodeURIComponent(id)}`, { method: 'DELETE' }).then((r) =>
      json<{ ok: boolean }>(r),
    ),

  adminCpeRearmLogin: (id: string) =>
    apiFetch(`/api/admin/cpe/${encodeURIComponent(id)}/rearm-login`, { method: 'POST' }).then((r) =>
      json<{ ok: boolean }>(r),
    ),

  adminPfSenseGateways: () =>
    apiFetch('/api/admin/pfsense/gateways').then((r) => json<PfSenseGatewaysResponse>(r)),

  adminCompalMesh: (
    baseUrl: string,
    enabled: boolean,
    onEvent?: (event: CompalStreamEvent) => void,
  ): Promise<CompalActionResponse> =>
    compalActionStream(
      '/api/admin/compal/mesh',
      { baseUrl, enabled },
      onEvent ?? (() => undefined),
    ).then((done) => ({
      ok: done.ok,
      url: done.url,
      meshEnabled: done.meshEnabled,
      message: done.message,
    })),

  adminCompalReboot: (
    baseUrl: string,
    onEvent?: (event: CompalStreamEvent) => void,
  ): Promise<CompalActionResponse> =>
    compalActionStream('/api/admin/compal/reboot', { baseUrl }, onEvent ?? (() => undefined)).then(
      (done) => ({
        ok: done.ok,
        url: done.url,
        message: done.message,
      }),
    ),

  adminUpdateConfig: (body: Record<string, unknown>) =>
    apiFetch('/api/admin/config', {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<AdminConfigPatchResponse>(r)),

  agentRestart,

  speedTestReport: (days = 90, limit = 2000, wanGateway?: string) => {
    const params = new URLSearchParams({ days: String(days), limit: String(limit) });
    if (wanGateway) params.set('wanGateway', wanGateway);
    return apiFetch(`/api/speed-tests/report?${params}`).then((r) => json<SpeedTestReport>(r));
  },

  runSpeedTest: (target: 'agent' | 'wan-all' = 'agent') =>
    apiFetch('/api/speed-tests/run', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ target }),
    }).then(async (r) => {
      if (!r.ok) {
        const err = (await r.json().catch(() => null)) as { error?: string } | null;
        throw new Error(err?.error ?? `${r.status} ${r.statusText}`);
      }
      if (target === 'wan-all') {
        return json<{ results: SpeedTestResult[] }>(r);
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

  diagnosticsPing: (ip: string, count = 3) =>
    apiFetch('/api/diagnostics/ping', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ip, count }),
    }).then((r) => json<PingResponse>(r)),

  diagnosticsTraceroute: (ip: string, maxHops = 20) =>
    apiFetch('/api/diagnostics/traceroute', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ip, maxHops }),
    }).then((r) => json<TracerouteResponse>(r)),

  diagnosticsDns: (name: string, type: 'A' | 'AAAA' | 'PTR' | 'CNAME' | 'MX' = 'A', server?: string) =>
    apiFetch('/api/diagnostics/dns', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name, type, server }),
    }).then((r) => json<DnsLookupResponse>(r)),

  diagnosticsPortScan: (ip: string, depth: 'quick' | 'standard' = 'quick') =>
    apiFetch('/api/diagnostics/port-scan', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ip, depth }),
    }).then((r) => json<PortScanResponse>(r)),

  diagnosticsWifi: () => apiFetch('/api/diagnostics/wifi').then((r) => json<WifiScanResponse>(r)),

  diagnosticsCameraScan: (body: { cidr?: string; travelMode?: boolean } = {}) =>
    apiFetch('/api/diagnostics/camera-scan', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<CameraScanResponse>(r)),

  controlBootstrap: () => apiFetch('/api/control/bootstrap').then((r) => json<ControlBootstrap>(r)),

  controlVerify: () => apiFetch('/api/control/verify').then((r) => json<ControlVerifyResult>(r)),

  controlBootstrapApply: () =>
    apiFetch('/api/control/bootstrap', { method: 'POST' }).then((r) => json<ControlBootstrap>(r)),

  controlStatus: (deviceId: string) =>
    apiFetch(`/api/control/status/${encodeURIComponent(deviceId)}`).then((r) => json<ControlStatus>(r)),

  controlBlock: (body: { deviceId?: string; ip?: string; mac?: string; reason?: string }) =>
    apiFetch('/api/control/block', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<{ entry: PolicyAuditEntry }>(r)),

  controlUnblock: (body: { deviceId?: string; ip?: string; mac?: string }) =>
    apiFetch('/api/control/unblock', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<{ entry: PolicyAuditEntry }>(r)),

  controlPause: (body: { deviceId?: string; ip?: string; mac?: string; durationMs?: number }) =>
    apiFetch('/api/control/pause', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<{ entry: PolicyAuditEntry }>(r)),

  controlDhcpReserve: (body: DhcpReservationRequest) =>
    apiFetch('/api/control/dhcp/reserve', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<{ entry: PolicyAuditEntry }>(r)),

  controlBandwidth: (body: BandwidthLimitRequest) =>
    apiFetch('/api/control/bandwidth', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<{ entry: PolicyAuditEntry }>(r)),

  controlAudit: (limit = 50) =>
    apiFetch(`/api/control/audit?limit=${limit}`).then((r) => json<{ entries: PolicyAuditEntry[] }>(r)),

  controlParentalList: () =>
    apiFetch('/api/control/parental').then((r) => json<{ schedules: ParentalScheduleRow[] }>(r)),

  controlParentalCreate: (body: ParentalScheduleRequest) =>
    apiFetch('/api/control/parental', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<{ schedule: ParentalScheduleRow }>(r)),

  controlDnsBlock: (body: { deviceId?: string; ip?: string; mac?: string; domain: string }) =>
    apiFetch('/api/control/dns-block', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<{ entry: PolicyAuditEntry }>(r)),

  controlDnsUnblock: (body: { deviceId?: string; ip?: string; mac?: string; domain: string }) =>
    apiFetch('/api/control/dns-unblock', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<{ entry: PolicyAuditEntry }>(r)),

  controlDestBlock: (body: { deviceId?: string; ip?: string; mac?: string; destination: string }) =>
    apiFetch('/api/control/dest-block', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<{ entry: PolicyAuditEntry }>(r)),

  controlDestUnblock: (body: { deviceId?: string; ip?: string; mac?: string; destination: string }) =>
    apiFetch('/api/control/dest-unblock', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then((r) => json<{ entry: PolicyAuditEntry }>(r)),

  controlRoute: (body: RoutePolicyRequest, signal?: AbortSignal) =>
    apiFetch('/api/control/route', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
      signal,
    }).then((r) => json<{ entry: PolicyAuditEntry }>(r)),

  controlRouteOptions: () =>
    apiFetch('/api/control/route-options').then((r) => json<{ options: RouteOption[] }>(r)),
};

export interface ParentalScheduleRow {
  id: string;
  name: string;
  deviceIds: string[];
  weekdays: number[];
  startTime: string;
  endTime: string;
  enabled: boolean;
  pfsenseScheduleId: string | null;
}

export interface ConfigFieldSchema {
  key: string;
  label: string;
  description: string;
  help?: string;
  type: 'string' | 'number' | 'boolean' | 'secret' | 'multiline';
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

export interface PfSenseGatewayRow {
  name: string | null;
  gateway: string | null;
  srcip: string | null;
  monitor: string | null;
  status: string | null;
  delay: number | null;
  loss: number | null;
  interface: string | null;
  isDefault?: boolean;
  description?: string | null;
}

export interface PfSenseGatewaysResponse {
  configured: boolean;
  fetchedAt?: string;
  version?: string | null;
  hostname?: string | null;
  system?: {
    platform: string | null;
    uptime: string | null;
    version: string | null;
    hostname: string | null;
    domain: string | null;
  } | null;
  defaultGateway?: { ipv4: string | null; ipv6: string | null } | null;
  gatewayGroups?: Array<{
    name: string;
    description?: string | null;
    members: Array<{ name: string; tier: number; status?: string | null }>;
  }>;
  gatewayGroupInsights?: Array<{
    group: string;
    description: string | null;
    preferredGateway: string | null;
    preferredTier: number | null;
    activeGateway: string | null;
    activeStateCount: number;
    members: Array<{ name: string; tier: number; status?: string | null }>;
  }>;
  gateways?: PfSenseGatewayRow[];
  interfaces?: Array<{
    name: string | null;
    descr: string | null;
    ipaddr: string | null;
    subnet: string | null;
    vlan: string | null;
    hwif: string | null;
    mac: string | null;
    status: string | null;
  }>;
  vpnClients?: Array<{
    name: string;
    type: 'openvpn' | 'wireguard';
    status: string | null;
    virtualAddress: string | null;
    remoteHost: string | null;
    interface: string | null;
    enabled: boolean;
  }>;
  egress?: Array<{
    gateway: string;
    interface: string;
    stateCount: number;
    bytesOut: number;
  }>;
  stateCount?: number;
}

export type { SpeedTestReport, SpeedTestResult, ActiveSiteResponse, NetworkSite } from '@netscanner/contracts';
