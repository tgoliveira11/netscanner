'use client';

import { create } from 'zustand';
import { io, type Socket } from 'socket.io-client';
import type { Device, DomainEvent, ScanSession } from '@netscanner/contracts';
import { api } from './api';

export interface AlertItem {
  id: string;
  kind: 'new' | 'changed' | 'security';
  message: string;
  deviceId: string;
  at: string;
}

interface StoreState {
  devices: Record<string, Device>;
  scan: ScanSession | null;
  alerts: AlertItem[];
  connected: boolean;
  capabilities: { nmap: boolean; elevated: boolean } | null;
  selectedId: string | null;
  bootstrap: () => Promise<void>;
  connect: () => void;
  select: (id: string | null) => void;
  applyDevice: (device: Device) => void;
  clearAlerts: () => void;
}

/**
 * Resolve the agent API/WebSocket base URL:
 *  - explicit NEXT_PUBLIC_API_URL wins;
 *  - agent bundle: same-origin (dashboard served by the gateway on :4000);
 *  - split dev: the Next dev server is on :3000 while the API is on :4000.
 */
function resolveApiUrl(): string {
  if (process.env.NEXT_PUBLIC_API_URL) return process.env.NEXT_PUBLIC_API_URL;
  if (typeof window === 'undefined') return 'http://localhost:4000';
  if (window.location.port === '3000') {
    return `${window.location.protocol}//${window.location.hostname}:4000`;
  }
  return window.location.origin;
}

const API_URL = resolveApiUrl();
let socket: Socket | null = null;

export const useStore = create<StoreState>((set, get) => ({
  devices: {},
  scan: null,
  alerts: [],
  connected: false,
  capabilities: null,
  selectedId: null,

  bootstrap: async () => {
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
  },

  connect: () => {
    if (socket) return;
    socket = io(API_URL, { path: '/socket.io', transports: ['websocket', 'polling'] });
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
    case 'scan.completed':
      set(() => ({ scan: event.payload }));
      break;
    case 'scan.failed':
      set((s) => ({ scan: s.scan ? { ...s.scan, status: 'failed', error: event.payload.error } : s.scan }));
      break;
    case 'device.classified':
      set((s) => ({ devices: withDevice(s.devices, event.payload.device) }));
      break;
    case 'device.new':
      set((s) => ({ devices: withDevice(s.devices, event.payload.device) }));
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
      pushAlert(set, {
        id: `${event.payload.device.id}-chg-${Date.now()}`,
        kind: 'changed',
        message: `${event.payload.device.ip} changed: ${event.payload.changes.join('; ')}`,
        deviceId: event.payload.device.id,
        at: new Date().toISOString(),
      });
      break;
    case 'device.offline':
      set((s) => {
        const d = s.devices[event.payload.deviceId];
        return d ? { devices: { ...s.devices, [d.id]: { ...d, isOnline: false } } } : {};
      });
      break;
  }
}
