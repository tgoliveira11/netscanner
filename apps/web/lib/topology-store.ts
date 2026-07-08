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
  pollTimer: ReturnType<typeof setInterval> | null;
  subscribers: number;
  fetchTopology: (opts?: { force?: boolean }) => Promise<void>;
  applyLayout: (computed: LayoutResult) => void;
  setView: (view: ViewTransform | ((cur: ViewTransform) => ViewTransform)) => void;
  markViewInitialized: () => void;
  resetViewState: () => void;
  subscribePage: () => () => void;
  invalidateStructure: () => void;
}

export const useTopologyStore = create<TopologyState>((set, get) => ({
  topology: null,
  layout: null,
  view: { scale: 1, panX: 0, panY: 0 },
  viewInitialized: false,
  loading: false,
  pollTimer: null,
  subscribers: 0,

  fetchTopology: async ({ force } = {}) => {
    const { topology, loading } = get();
    if (loading) return;
    set({ loading: true });
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
      set({ loading: false });
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

    if (!state.pollTimer) {
      const pollTimer = setInterval(() => {
        if (get().subscribers > 0) void get().fetchTopology();
      }, POLL_MS);
      set({ pollTimer });
    }

    return () => {
      const subs = Math.max(0, get().subscribers - 1);
      set({ subscribers: subs });
      if (subs === 0 && get().pollTimer) {
        clearInterval(get().pollTimer!);
        set({ pollTimer: null });
      }
    };
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
