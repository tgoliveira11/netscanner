import { create } from 'zustand';
import type { TopologyResponse } from '@netscanner/contracts';
import { api } from './api';
import {
  layoutVlanTree,
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
    const { topology, loading } = get();
    if (loading) return;
    const isInitial = !topology;
    set({ loading: isInitial, refreshing: !isInitial });
    try {
      const since = !force && topology?.revision ? topology.revision : undefined;
      const res = await api.topology(since ? { since } : undefined);
      if (res.unchanged) return;

      const prevGateway = topology?.gatewayId ?? null;
      set({ topology: res });
      if (prevGateway !== res.gatewayId) {
        set({ layout: null, viewInitialized: false });
      }
    } catch {
      /* agent may be restarting */
    } finally {
      set({ loading: false, refreshing: false });
    }
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

/** Build render nodes from cached positions + live device records. */
export function buildRenderLayout(
  layout: CachedLayout | null,
  computed: LayoutResult,
): LayoutResult {
  if (!layout) return computed;
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
  return {
    nodes,
    edges: computed.edges,
    width: layout.width,
    height: layout.height,
  };
}
