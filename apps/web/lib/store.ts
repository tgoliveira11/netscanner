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

function isPresenceOnlyChange(changes: string[]): boolean {
  return changes.length > 0 && changes.every((c) => PRESENCE_CHANGE.test(c));
}

interface StoreState {
  devices: Record<string, Device>;
  scan: ScanSession | null;
  alerts: AlertItem[];
  connected: boolean;
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

export const useStore = create<StoreState>((set, get) => ({
  devices: {},
  scan: null,
  alerts: [],
  connected: false,
  capabilities: null,
  selectedId: null,

  bootstrap: async () => {
    try {
      const [{ devices }, { scan }, health] = await Promise.all([
        api.listDevices(),
        api.latestScan(),
        api.health().catch(() => null),
      ]);
      set({
        devices: Object.fromEntries(devices.map((d) => [d.id, d])),
        scan,
        capabilities: health?.capabilities ?? null,
      });
    } catch {
      /* agent may be restarting */
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
    socket.on('domain-event', (event: DomainEvent) => handleEvent(event, set, get));
  },

  select: (id) => set({ selectedId: id }),
  applyDevice: (device) => set((s) => ({ devices: withDevice(s.devices, device) })),
  clearAlerts: () => set({ alerts: [] }),
}));

function pushAlert(set: (fn: (s: StoreState) => Partial<StoreState>) => void, alert: AlertItem) {
  set((s) => ({ alerts: [alert, ...s.alerts].slice(0, 50) }));
}

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
  _get: () => StoreState,
): void {
  switch (event.type) {
    case 'scan.started':
    case 'scan.progress':
      set(() => ({ scan: event.payload }));
      break;
    case 'scan.completed':
      set(() => ({ scan: event.payload }));
      useTopologyStore.getState().invalidateStructure();
      break;
    case 'scan.failed':
      set((s) => ({ scan: s.scan ? { ...s.scan, status: 'failed', error: event.payload.error } : s.scan }));
      break;
    case 'device.classified':
      set((s) => ({ devices: withDevice(s.devices, event.payload.device) }));
      break;
    case 'device.new':
      set((s) => ({ devices: withDevice(s.devices, event.payload.device) }));
      useTopologyStore.getState().invalidateStructure();
      pushAlert(set, {
        id: `${event.payload.device.id}-new-${Date.now()}`,
        kind: 'new',
        message: `New device: ${event.payload.device.hostname ?? event.payload.device.ip} (${event.payload.device.deviceType})`,
        deviceId: event.payload.device.id,
        at: new Date().toISOString(),
      });
      break;
    case 'device.changed':
      set((s) => ({ devices: withDevice(s.devices, event.payload.device) }));
      if (!isPresenceOnlyChange(event.payload.changes)) {
        pushAlert(set, {
          id: `${event.payload.device.id}-chg-${Date.now()}`,
          kind: 'changed',
          message: `${event.payload.device.ip} changed: ${event.payload.changes.join('; ')}`,
          deviceId: event.payload.device.id,
          at: new Date().toISOString(),
        });
      }
      break;
    case 'device.offline': {
      const device = event.payload.device;
      set((s) => {
        if (device) return { devices: withDevice(s.devices, { ...device, isOnline: false }) };
        const d = s.devices[event.payload.deviceId];
        return d ? { devices: { ...s.devices, [d.id]: { ...d, isOnline: false } } } : {};
      });
      break;
    }
    case 'device.online':
      set((s) => ({ devices: withDevice(s.devices, event.payload.device) }));
      break;
    case 'device.anomaly':
      if (event.payload.code === 'NEW_EXTERNAL_DEST' || event.payload.code === 'DEVICE_OFFLINE') break;
      set((s) => ({ devices: withDevice(s.devices, event.payload.device) }));
      pushAlert(set, {
        id: `${event.payload.device.id}-anom-${event.payload.code}-${Date.now()}`,
        kind: 'security',
        message: event.payload.message,
        deviceId: event.payload.device.id,
        at: new Date().toISOString(),
      });
      break;
  }
}
