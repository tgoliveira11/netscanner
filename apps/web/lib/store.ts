'use client';

import { create } from 'zustand';
import { io, type Socket } from 'socket.io-client';
import type { Device, DomainEvent, ScanSession } from '@netscanner/contracts';
import { api, apiBase } from './api';
import { useTopologyStore } from './topology-store';

export interface AlertItem {
  id: string;
  kind: 'new' | 'changed' | 'security';
  message: string;
  deviceId: string;
  at: string;
}

const PRESENCE_CHANGE = /^came online$|^went offline$/;
const IP_CHANGE = /^ip: /;

/** Changes that should not surface in the alerts bell (still on device timeline). */
function alertableChanges(changes: string[]): string[] {
  return changes.filter((c) => !PRESENCE_CHANGE.test(c) && !IP_CHANGE.test(c));
}

interface StoreState {
  devices: Record<string, Device>;
  scan: ScanSession | null;
  alerts: AlertItem[];
  connected: boolean;
  bootstrapping: boolean;
  capabilities: { nmap: boolean; elevated: boolean; nmapOffReason?: 'disabled-by-config' | 'not-in-path' } | null;
  selectedId: string | null;
  bootstrap: () => Promise<void>;
  connect: () => void;
  select: (id: string | null) => void;
  applyDevice: (device: Device) => void;
  clearAlerts: () => void;
}

const API_URL = typeof window !== 'undefined' ? apiBase() : 'http://127.0.0.1:4000';
let socket: Socket | null = null;

/** Coalesce WS fan-out so DeviceTable/StatsBar don't re-render on every host event. */
const EVENT_FLUSH_MS = 120;

type PendingBatch = {
  scan?: ScanSession | null;
  scanPatch?: Partial<ScanSession>;
  devices: Map<string, Device>;
  offlineIds: Set<string>;
  alerts: AlertItem[];
  invalidateTopology: boolean;
};

let pending: PendingBatch | null = null;
let flushTimer: ReturnType<typeof setTimeout> | null = null;
let batchSet: ((fn: (s: StoreState) => Partial<StoreState>) => void) | null = null;

function ensurePending(): PendingBatch {
  if (!pending) {
    pending = {
      devices: new Map(),
      offlineIds: new Set(),
      alerts: [],
      invalidateTopology: false,
    };
  }
  return pending;
}

function scheduleFlush(set: (fn: (s: StoreState) => Partial<StoreState>) => void): void {
  batchSet = set;
  if (flushTimer != null) return;
  flushTimer = setTimeout(flushPending, EVENT_FLUSH_MS);
}

function flushPending(): void {
  flushTimer = null;
  const batch = pending;
  const set = batchSet;
  pending = null;
  batchSet = null;
  if (!batch || !set) return;

  set((s) => {
    let devices = s.devices;
    let dirty = false;

    if (batch.devices.size || batch.offlineIds.size) {
      dirty = true;
      devices = { ...s.devices };
      for (const device of batch.devices.values()) {
        devices = withDevice(devices, device);
      }
      for (const id of batch.offlineIds) {
        if (batch.devices.has(id)) continue;
        const d = devices[id];
        if (d) devices[id] = { ...d, isOnline: false };
      }
    }

    const next: Partial<StoreState> = {};
    if (dirty) next.devices = devices;
    if (batch.scan !== undefined) next.scan = batch.scan;
    else if (batch.scanPatch && s.scan) next.scan = { ...s.scan, ...batch.scanPatch };
    if (batch.alerts.length) next.alerts = [...batch.alerts, ...s.alerts].slice(0, 50);
    return next;
  });

  if (batch.invalidateTopology) {
    useTopologyStore.getState().invalidateStructure();
  }
}

export const useStore = create<StoreState>((set, get) => ({
  devices: {},
  scan: null,
  alerts: [],
  connected: false,
  bootstrapping: true,
  capabilities: null,
  selectedId: null,

  bootstrap: async () => {
    set({ bootstrapping: true });
    try {
      const [{ devices }, { scan }, health] = await Promise.all([
        api.listDevices(),
        api.latestScan(),
        api.health().catch(() => null),
      ]);
      set((s) => {
        // Never wipe a warm inventory with an empty/transient response (agent restart).
        const nextDevices =
          devices.length > 0 || Object.keys(s.devices).length === 0
            ? Object.fromEntries(devices.map((d) => [d.id, d]))
            : s.devices;
        return {
          devices: nextDevices,
          scan: scan ?? s.scan,
          capabilities: health?.capabilities ?? s.capabilities,
        };
      });
    } catch {
      /* agent may be restarting — keep last good snapshot */
    } finally {
      set({ bootstrapping: false });
    }
  },

  connect: () => {
    if (socket) return;
    socket = io(API_URL, {
      path: '/socket.io',
      transports: ['polling', 'websocket'],
      reconnection: true,
      reconnectionAttempts: Infinity,
    });
    socket.on('connect', () => set({ connected: true }));
    socket.on('disconnect', () => set({ connected: false }));
    socket.on('domain-event', (event: DomainEvent) => handleEvent(event, set));
  },

  select: (id) => set({ selectedId: id }),
  applyDevice: (device) => set((s) => ({ devices: withDevice(s.devices, device) })),
  clearAlerts: () => set({ alerts: [] }),
}));

/**
 * Insert/replace a device, dropping any stale entry for the same IP that carries
 * a different id (e.g. after the DB was reset and records got new UUIDs). Keeps
 * the live view free of duplicates without depending on the DB id being stable.
 */
function withDevice(devices: Record<string, Device>, device: Device): Record<string, Device> {
  const next: Record<string, Device> = {};
  for (const [id, d] of Object.entries(devices)) {
    if (d.ip === device.ip && id !== device.id) continue;
    next[id] = d;
  }
  next[device.id] = device;
  return next;
}

/** Reduces the backend event stream into store state — the UI is a projection. */
function handleEvent(
  event: DomainEvent,
  set: (fn: (s: StoreState) => Partial<StoreState>) => void,
): void {
  const batch = ensurePending();

  switch (event.type) {
    case 'scan.started':
    case 'scan.progress':
      batch.scan = event.payload;
      break;
    case 'scan.completed':
      batch.scan = event.payload;
      batch.invalidateTopology = true;
      break;
    case 'scan.failed':
      batch.scanPatch = { status: 'failed', error: event.payload.error };
      break;
    case 'device.classified':
    case 'device.changed':
    case 'device.online':
      batch.devices.set(event.payload.device.id, event.payload.device);
      if (event.type === 'device.changed') {
        const notable = alertableChanges(event.payload.changes);
        if (notable.length) {
          batch.alerts.push({
            id: `${event.payload.device.id}-chg-${Date.now()}`,
            kind: 'changed',
            message: `${event.payload.device.ip} changed: ${notable.join('; ')}`,
            deviceId: event.payload.device.id,
            at: new Date().toISOString(),
          });
        }
      }
      break;
    case 'device.new':
      batch.devices.set(event.payload.device.id, event.payload.device);
      batch.alerts.push({
        id: `${event.payload.device.id}-new-${Date.now()}`,
        kind: 'new',
        message: `New device: ${event.payload.device.hostname ?? event.payload.device.ip} (${event.payload.device.deviceType})`,
        deviceId: event.payload.device.id,
        at: new Date().toISOString(),
      });
      // Topology refresh waits for scan.completed — mid-scan force rebuilds freeze the UI.
      break;
    case 'device.offline': {
      const device = event.payload.device;
      if (device) {
        batch.devices.set(device.id, { ...device, isOnline: false });
      } else {
        batch.offlineIds.add(event.payload.deviceId);
      }
      break;
    }
    case 'device.anomaly':
      if (event.payload.code === 'NEW_EXTERNAL_DEST' || event.payload.code === 'DEVICE_OFFLINE') break;
      batch.devices.set(event.payload.device.id, event.payload.device);
      batch.alerts.push({
        id: `${event.payload.device.id}-anom-${event.payload.code}-${Date.now()}`,
        kind: 'security',
        message: event.payload.message,
        deviceId: event.payload.device.id,
        at: new Date().toISOString(),
      });
      break;
  }

  scheduleFlush(set);
}
