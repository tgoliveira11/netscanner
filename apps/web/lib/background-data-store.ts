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
const COMPAL_MS = 30_000;
const CONTROL_MS = 60_000;

const compalWatchUrls = new Map<string, number>();
const compalPrevDevices = new Map<string, { ok: boolean; mesh: boolean | null }>();

function compalShouldWatch(d: { url: string; ok: boolean; meshEnabled: boolean | null }): boolean {
  if (!d.ok) return true;
  const deadline = compalWatchUrls.get(d.url);
  if (!deadline) return false;
  if (Date.now() >= deadline) {
    compalWatchUrls.delete(d.url);
    return false;
  }
  if (d.meshEnabled != null) {
    compalWatchUrls.delete(d.url);
    return false;
  }
  return true;
}

export function compalDeviceNeedsWatch(d: {
  url: string;
  ok: boolean;
  meshEnabled: boolean | null;
}): boolean {
  return compalShouldWatch(d);
}

function compalNeedsFastPoll(data: CompalAdminResponse | null): boolean {
  return Boolean(data?.configured && data.devices.some(compalShouldWatch));
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
  },

  refreshPfSense: async ({ silent } = {}) => {
    const hasData = get().pfsense != null;
    if (!silent && !hasData) set({ pfsenseLoading: true });
    else if (hasData) set({ pfsenseRefreshing: true });
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
    else if (hasData) set({ wirelessRefreshing: true });
    try {
      set({ wireless: await api.adminWireless() });
    } catch {
      /* wireless probe is slow — optional */
    } finally {
      set({ wirelessLoading: false, wirelessRefreshing: false });
    }
  },

  refreshCompal: async ({ silent } = {}) => {
    const hasData = get().compal != null;
    if (!silent && !hasData) set({ compalLoading: true });
    else if (hasData) set({ compalRefreshing: true });
    try {
      const data = await api.adminCompal();
      for (const d of data.devices) {
        const prev = compalPrevDevices.get(d.url);
        if (prev && !prev.ok && d.ok && d.meshEnabled == null) {
          compalWatchUrls.set(d.url, Date.now() + 120_000);
        }
        compalPrevDevices.set(d.url, { ok: d.ok, mesh: d.meshEnabled });
      }
      set({
        compal: data,
        compalError: silent ? get().compalError : null,
        compalAutoPolling: compalNeedsFastPoll(data),
      });
    } catch (e) {
      if (!silent) set({ compalError: e instanceof Error ? e.message : String(e) });
    } finally {
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
      setInterval(() => void get().refreshCompal({ silent: true }), COMPAL_MS),
      setInterval(() => void get().refreshControl({ silent: true }), CONTROL_MS),
      setInterval(() => {
        if (compalNeedsFastPoll(get().compal)) {
          set({ compalAutoPolling: true });
          void get().refreshCompal({ silent: true });
        } else {
          set({ compalAutoPolling: false });
        }
      }, 5_000),
    ];
    set({ timers });
  },

  stop: () => {
    for (const t of get().timers) clearInterval(t);
    set({ started: false, timers: [], compalAutoPolling: false });
  },
}));
