import { create } from 'zustand';
import type { CompalAdminResponse, ControlBootstrap, PolicyAuditEntry } from '@netscanner/contracts';
import {
  api,
  type AdminWirelessResponse,
  type ParentalScheduleRow,
  type PfSenseGatewaysResponse,
} from './api';

const PFSENSE_MS = 30_000;
const WIRELESS_MS = 60_000;
/** Tick for post-action Compal watch windows (mesh/reboot). */
const COMPAL_WATCH_MS = 10_000;
/** Slow recovery check when an AP is offline — not a login hammer. */
const COMPAL_OFFLINE_MS = 90_000;
const CONTROL_MS = 60_000;

/** Explicit post-action windows only (mesh toggle / reboot). */
const compalWatchUrls = new Map<string, number>();
let compalInFlight = false;
let lastCompalOfflinePollAt = 0;

function watchDeadlineActive(url: string): boolean {
  const deadline = compalWatchUrls.get(url);
  if (!deadline) return false;
  if (Date.now() >= deadline) {
    compalWatchUrls.delete(url);
    return false;
  }
  return true;
}

/** After mesh/reboot: stop early once the AP is back and mesh is readable. */
function pruneCompalWatchWindows(data: CompalAdminResponse): void {
  for (const d of data.devices) {
    if (!watchDeadlineActive(d.url)) continue;
    if (d.ok && d.meshEnabled != null) {
      compalWatchUrls.delete(d.url);
    }
  }
}

/** True while this AP has an active post-action watch window. */
export function compalDeviceNeedsWatch(d: { url: string }): boolean {
  return watchDeadlineActive(d.url);
}

function compalNeedsFastPoll(data: CompalAdminResponse | null): boolean {
  return Boolean(data?.configured && data.devices.some((d) => watchDeadlineActive(d.url)));
}

function compalNeedsOfflinePoll(data: CompalAdminResponse | null): boolean {
  if (!data?.configured) return false;
  if (!data.devices.some((d) => !d.ok)) return false;
  return Date.now() - lastCompalOfflinePollAt >= COMPAL_OFFLINE_MS;
}

interface BackgroundDataState {
  started: boolean;
  timers: ReturnType<typeof setInterval>[];

  pfsense: PfSenseGatewaysResponse | null;
  pfsenseLoading: boolean;
  pfsenseRefreshing: boolean;
  pfsenseError: string | null;

  wireless: AdminWirelessResponse | null;
  wirelessLoading: boolean;
  wirelessRefreshing: boolean;

  compal: CompalAdminResponse | null;
  compalLoading: boolean;
  compalRefreshing: boolean;
  compalError: string | null;
  compalAutoPolling: boolean;

  controlBoot: ControlBootstrap | null;
  controlAudit: PolicyAuditEntry[];
  controlSchedules: ParentalScheduleRow[];
  controlBootLoading: boolean;
  controlAuditLoading: boolean;
  controlSchedulesLoading: boolean;
  controlError: string | null;

  watchCompalDevice: (url: string, durationMs?: number) => void;
  refreshPfSense: (opts?: { silent?: boolean }) => Promise<void>;
  refreshWireless: (opts?: { silent?: boolean }) => Promise<void>;
  refreshCompal: (opts?: { silent?: boolean }) => Promise<void>;
  refreshControl: (opts?: { silent?: boolean }) => Promise<void>;
  start: () => void;
  stop: () => void;
}

export const useBackgroundDataStore = create<BackgroundDataState>((set, get) => ({
  started: false,
  timers: [],

  pfsense: null,
  pfsenseLoading: false,
  pfsenseRefreshing: false,
  pfsenseError: null,

  wireless: null,
  wirelessLoading: false,
  wirelessRefreshing: false,

  compal: null,
  compalLoading: false,
  compalRefreshing: false,
  compalError: null,
  compalAutoPolling: false,

  controlBoot: null,
  controlAudit: [],
  controlSchedules: [],
  controlBootLoading: false,
  controlAuditLoading: false,
  controlSchedulesLoading: false,
  controlError: null,

  watchCompalDevice: (url, durationMs = 180_000) => {
    compalWatchUrls.set(url, Date.now() + durationMs);
    set({ compalAutoPolling: true });
  },

  refreshPfSense: async ({ silent } = {}) => {
    const hasData = get().pfsense != null;
    if (!silent && !hasData) set({ pfsenseLoading: true });
    else if (!silent && hasData) set({ pfsenseRefreshing: true });
    try {
      set({ pfsense: await api.adminPfSenseGateways(), pfsenseError: null });
    } catch (e) {
      set({ pfsenseError: e instanceof Error ? e.message : String(e) });
    } finally {
      set({ pfsenseLoading: false, pfsenseRefreshing: false });
    }
  },

  refreshWireless: async ({ silent } = {}) => {
    const hasData = get().wireless != null;
    if (!silent && !hasData) set({ wirelessLoading: true });
    else if (!silent && hasData) set({ wirelessRefreshing: true });
    try {
      set({ wireless: await api.adminWireless() });
    } catch {
      /* wireless probe is slow — optional */
    } finally {
      set({ wirelessLoading: false, wirelessRefreshing: false });
    }
  },

  refreshCompal: async ({ silent } = {}) => {
    if (compalInFlight) return;
    compalInFlight = true;
    const hasData = get().compal != null;
    // Silent background polls must not flash the Refresh button.
    if (!silent && !hasData) set({ compalLoading: true });
    else if (!silent && hasData) set({ compalRefreshing: true });
    try {
      const data = await api.adminCompal();
      pruneCompalWatchWindows(data);
      if (data.devices.some((d) => !d.ok)) lastCompalOfflinePollAt = Date.now();
      set({
        compal: data,
        compalError: silent ? get().compalError : null,
        compalAutoPolling: compalNeedsFastPoll(data) || data.devices.some((d) => !d.ok),
      });
    } catch (e) {
      if (!silent) set({ compalError: e instanceof Error ? e.message : String(e) });
    } finally {
      compalInFlight = false;
      set({ compalLoading: false, compalRefreshing: false });
    }
  },

  refreshControl: async ({ silent } = {}) => {
    const s = get();
    if (!silent) {
      if (!s.controlBoot) set({ controlBootLoading: true });
      if (!s.controlAudit.length) set({ controlAuditLoading: true });
      if (!s.controlSchedules.length) set({ controlSchedulesLoading: true });
    }
    const errors: string[] = [];
    const [bootRes, auditRes, parentalRes] = await Promise.allSettled([
      api.controlBootstrap(),
      api.controlAudit(30),
      api.controlParentalList(),
    ]);
    if (bootRes.status === 'fulfilled') set({ controlBoot: bootRes.value, controlBootLoading: false });
    else {
      errors.push(bootRes.reason instanceof Error ? bootRes.reason.message : String(bootRes.reason));
      set({ controlBootLoading: false });
    }
    if (auditRes.status === 'fulfilled') set({ controlAudit: auditRes.value.entries, controlAuditLoading: false });
    else {
      errors.push(auditRes.reason instanceof Error ? auditRes.reason.message : String(auditRes.reason));
      set({ controlAuditLoading: false });
    }
    if (parentalRes.status === 'fulfilled') {
      set({ controlSchedules: parentalRes.value.schedules, controlSchedulesLoading: false });
    } else {
      errors.push(parentalRes.reason instanceof Error ? parentalRes.reason.message : String(parentalRes.reason));
      set({ controlSchedulesLoading: false });
    }
    set({ controlError: errors.length ? errors.join(' · ') : null });
  },

  start: () => {
    if (get().started || typeof window === 'undefined') return;
    set({ started: true });

    const { refreshPfSense, refreshWireless, refreshCompal, refreshControl } = get();
    void refreshPfSense();
    void refreshWireless();
    void refreshCompal();
    void refreshControl();

    const timers = [
      setInterval(() => void get().refreshPfSense({ silent: true }), PFSENSE_MS),
      setInterval(() => void get().refreshWireless({ silent: true }), WIRELESS_MS),
      setInterval(() => void get().refreshControl({ silent: true }), CONTROL_MS),
      // Compal: idle when all APs are up. Fast poll only in post-action windows;
      // offline APs get a slow recovery check (~90s), not a 10s login storm.
      setInterval(() => {
        const data = get().compal;
        const fast = compalNeedsFastPoll(data);
        const offline = compalNeedsOfflinePoll(data);
        if (fast || offline) {
          set({ compalAutoPolling: true });
          void get().refreshCompal({ silent: true });
        } else {
          const anyOffline = Boolean(data?.devices.some((d) => !d.ok));
          set({ compalAutoPolling: anyOffline || fast });
        }
      }, COMPAL_WATCH_MS),
    ];
    set({ timers });
  },

  stop: () => {
    for (const t of get().timers) clearInterval(t);
    set({ started: false, timers: [], compalAutoPolling: false });
  },
}));
