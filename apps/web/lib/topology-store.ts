import { create } from 'zustand';
import type { Device, TopologyResponse } from '@netscanner/contracts';
import { api } from './api';
import {
  layoutFromCache,
  mergeLayoutPositions,
  type CachedLayout,
  type LayoutResult,
  type NodePos,
} from './topology-layout';

const POLL_MS = 60_000;

export interface ViewTransform {
  scale: number;
  panX: number;
  panY: number;
}

interface TopologyState {
  topology: TopologyResponse | null;
  layout: CachedLayout | null;
  view: ViewTransform;
  viewInitialized: boolean;
  loading: boolean;
  refreshing: boolean;
  pollTimer: ReturnType<typeof setInterval> | null;
  subscribers: number;
  backgroundPolling: boolean;
  fetchTopology: (opts?: { force?: boolean }) => Promise<void>;
  applyLayout: (computed: LayoutResult) => void;
  setView: (view: ViewTransform | ((cur: ViewTransform) => ViewTransform)) => void;
  markViewInitialized: () => void;
  resetViewState: () => void;
  subscribePage: () => () => void;
  startBackgroundPolling: () => void;
  stopBackgroundPolling: () => void;
  invalidateStructure: () => void;
}

/** Single-flight + generation so overlapping polls cannot apply a stale empty graph. */
let fetchGeneration = 0;
let inFlight: Promise<void> | null = null;
let pendingForce = false;

function isEmptyTopology(res: TopologyResponse): boolean {
  return !res.gatewayId || res.nodes.length === 0;
}

function shouldKeepPrevious(prev: TopologyResponse | null, res: TopologyResponse): boolean {
  if (!prev || prev.nodes.length === 0) return false;
  return isEmptyTopology(res);
}

export const useTopologyStore = create<TopologyState>((set, get) => ({
  topology: null,
  layout: null,
  view: { scale: 1, panX: 0, panY: 0 },
  viewInitialized: false,
  loading: false,
  refreshing: false,
  pollTimer: null,
  subscribers: 0,
  backgroundPolling: false,

  fetchTopology: async ({ force } = {}) => {
    if (force) pendingForce = true;
    if (inFlight) return inFlight;

    const run = async (): Promise<void> => {
      const gen = ++fetchGeneration;
      const wantForce = pendingForce;
      pendingForce = false;
      const { topology } = get();
      const isInitial = !topology;
      set({ loading: isInitial, refreshing: !isInitial });
      try {
        const since = !wantForce && topology?.revision ? topology.revision : undefined;
        const res = await api.topology(since ? { since } : undefined);
        if (gen !== fetchGeneration) return;
        if (res.unchanged) return;

        const prev = get().topology;
        // Never let a transient empty rebuild wipe a good graph (gateway flicker / race).
        if (shouldKeepPrevious(prev, res)) return;

        // Keep layout + pan/zoom across gateway UUID churn — mergeLayoutPositions
        // adds newcomers and drops gone ids. Only clear when the user resets view.
        set({ topology: res });
      } catch {
        /* agent may be restarting — keep last good snapshot */
      } finally {
        if (gen === fetchGeneration) {
          set({ loading: false, refreshing: false });
        }
        inFlight = null;
        if (pendingForce) {
          void get().fetchTopology({ force: true });
        }
      }
    };

    inFlight = run();
    return inFlight;
  },

  applyLayout: (computed) => {
    if (computed.nodes.length === 0) return;
    set((s) => ({ layout: mergeLayoutPositions(s.layout, computed) }));
  },

  setView: (view) => {
    set((s) => ({
      view: typeof view === 'function' ? view(s.view) : view,
    }));
  },

  markViewInitialized: () => set({ viewInitialized: true }),

  resetViewState: () => set({ viewInitialized: false, layout: null }),

  invalidateStructure: () => {
    void get().fetchTopology({ force: true });
  },

  subscribePage: () => {
    const state = get();
    const next = state.subscribers + 1;
    set({ subscribers: next });

    if (!state.topology) {
      void get().fetchTopology({ force: true });
    } else {
      void get().fetchTopology();
    }

    return () => {
      set({ subscribers: Math.max(0, get().subscribers - 1) });
    };
  },

  startBackgroundPolling: () => {
    if (get().backgroundPolling || typeof window === 'undefined') return;
    set({ backgroundPolling: true });
    if (!get().topology) void get().fetchTopology({ force: true });
    if (!get().pollTimer) {
      const pollTimer = setInterval(() => void get().fetchTopology(), POLL_MS);
      set({ pollTimer });
    }
  },

  stopBackgroundPolling: () => {
    const timer = get().pollTimer;
    if (timer) clearInterval(timer);
    set({ backgroundPolling: false, pollTimer: null });
  },
}));

/**
 * Build render nodes from cached positions + live device records.
 * If the computed tree is briefly empty (devices not hydrated yet), keep the
 * last good layout instead of painting a blank canvas.
 */
export function buildRenderLayout(
  layout: CachedLayout | null,
  computed: LayoutResult,
  devices?: Record<string, Device>,
): LayoutResult {
  if (!layout) return computed;

  if (computed.nodes.length === 0) {
    if (devices && Object.keys(layout.positions).length > 0) {
      const cached = layoutFromCache(layout, devices);
      if (cached.nodes.length > 0) {
        return {
          nodes: cached.nodes,
          edges: computed.edges,
          width: layout.width,
          height: layout.height,
        };
      }
    }
    return computed;
  }

  const byId = new Map(computed.nodes.map((n) => [n.device.id, n]));
  const nodes: NodePos[] = [];
  for (const [id, pos] of Object.entries(layout.positions)) {
    const fromComputed = byId.get(id);
    if (!fromComputed) continue;
    nodes.push({
      device: fromComputed.device,
      x: pos.x,
      y: pos.y,
      role: pos.role,
    });
  }
  // Newcomers not yet in cache — append from computed so they appear immediately.
  for (const node of computed.nodes) {
    if (!(node.device.id in layout.positions)) nodes.push(node);
  }
  return {
    nodes,
    edges: computed.edges,
    width: Math.max(layout.width, computed.width),
    height: Math.max(layout.height, computed.height),
  };
}
