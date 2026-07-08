import type { Device, TopologyEdge, TopologyNodeRole, TopologyResponse, TopologyVlan } from '@netscanner/contracts';

export interface NodePos {
  device: Device;
  x: number;
  y: number;
  role: TopologyNodeRole | 'unknown';
}

export interface LayoutResult {
  nodes: NodePos[];
  edges: TopologyEdge[];
  width: number;
  height: number;
}

export interface CachedNodePos {
  x: number;
  y: number;
  role: TopologyNodeRole | 'unknown';
}

export interface CachedLayout {
  positions: Record<string, CachedNodePos>;
  width: number;
  height: number;
}

const PAD_X = 48;
const LAYER_DY = 96;
const TOP_Y = 48;
const MIN_WIDTH = 780;
const WAN_NODE_GAP_PX = 200;

function resolveDeviceFallbackVlan(device: Device | undefined): string {
  if (!device) return 'zzz';
  const iface = device.signals?.pfsenseInterface ?? device.signals?.routerInterface;
  if (typeof iface === 'string') return iface;
  return device.ip;
}

function resolveCollapsedGatewayId(gatewayId: string, list: Device[]): string | null {
  if (list.some((d) => d.id === gatewayId)) return gatewayId;
  return (
    list.find(
      (d) =>
        (d.deviceType === 'firewall' || d.deviceType === 'router') &&
        Array.isArray(d.signals?.infrastructureIps) &&
        (d.signals.infrastructureIps as string[]).length > 1,
    )?.id ?? null
  );
}

/** Preserve positions for existing nodes; only assign layout for newcomers. */
export function mergeLayoutPositions(
  cached: CachedLayout | null,
  computed: LayoutResult,
): CachedLayout {
  if (!cached) {
    return {
      positions: Object.fromEntries(
        computed.nodes.map((n) => [n.device.id, { x: n.x, y: n.y, role: n.role }]),
      ),
      width: computed.width,
      height: computed.height,
    };
  }

  const positions = { ...cached.positions };
  for (const node of computed.nodes) {
    if (!(node.device.id in positions)) {
      positions[node.device.id] = { x: node.x, y: node.y, role: node.role };
    }
  }
  const ids = new Set(computed.nodes.map((n) => n.device.id));
  for (const id of Object.keys(positions)) {
    if (!ids.has(id)) delete positions[id];
  }
  return {
    positions,
    width: Math.max(cached.width, computed.width),
    height: Math.max(cached.height, computed.height),
  };
}

export function layoutFromCache(
  cached: CachedLayout,
  devices: Record<string, Device>,
): LayoutResult {
  const nodes: NodePos[] = [];
  for (const [id, pos] of Object.entries(cached.positions)) {
    const device = devices[id];
    if (!device) continue;
    nodes.push({ device, x: pos.x, y: pos.y, role: pos.role });
  }
  return { nodes, edges: [], width: cached.width, height: cached.height };
}

export function layoutVlanTree(list: Device[], topology: TopologyResponse | null): LayoutResult {
  const edges = topology?.edges ?? [];
  let gatewayId = topology?.gatewayId ?? null;
  const metaById = new Map((topology?.nodes ?? []).map((n) => [n.id, n]));
  const byId = new Map(list.map((d) => [d.id, d]));

  if (gatewayId && !byId.has(gatewayId)) {
    gatewayId = resolveCollapsedGatewayId(gatewayId, list) ?? gatewayId;
  }

  if (!gatewayId || !byId.has(gatewayId)) {
    return { nodes: [], edges: [], width: MIN_WIDTH, height: 200 };
  }

  const childrenOf = new Map<string, string[]>();
  const parentsOf = new Map<string, string[]>();
  for (const edge of edges) {
    let from = edge.from;
    let to = edge.to;
    if (!byId.has(from)) from = resolveCollapsedGatewayId(from, list) ?? from;
    if (!byId.has(to)) to = resolveCollapsedGatewayId(to, list) ?? to;
    if (!byId.has(from) || !byId.has(to)) continue;
    const group = childrenOf.get(to) ?? [];
    if (!group.includes(from)) group.push(from);
    childrenOf.set(to, group);
    const parents = parentsOf.get(from) ?? [];
    if (!parents.includes(to)) parents.push(to);
    parentsOf.set(from, parents);
  }

  const roleRank = (id: string) => {
    const role = metaById.get(id)?.role;
    if (role === 'wan') return -1;
    if (role === 'wired-router') return 0;
    if (role === 'wifi-ap') return 1;
    return 2;
  };
  const vlanOf = (id: string) => {
    const edge = edges.find((e) => e.from === id);
    return edge?.vlan ?? resolveDeviceFallbackVlan(byId.get(id));
  };
  const sortKids = (ids: string[]) =>
    [...ids].sort((a, b) => {
      const rr = roleRank(a) - roleRank(b);
      if (rr !== 0) return rr;
      const va = vlanOf(a).localeCompare(vlanOf(b));
      if (va !== 0) return va;
      return (byId.get(a)?.ip ?? a).localeCompare(byId.get(b)?.ip ?? b);
    });

  const visited = new Set<string>();
  const wanFromParents = sortKids(
    (parentsOf.get(gatewayId) ?? []).filter((id) => metaById.get(id)?.role === 'wan'),
  ).filter((id) => byId.has(id));
  const wanFromNodes = (topology?.nodes ?? [])
    .filter((n) => n.role === 'wan' && byId.has(n.id))
    .map((n) => n.id);
  const wanParents = [...new Set([...wanFromParents, ...wanFromNodes])];

  const gatewayKids = sortKids(childrenOf.get(gatewayId) ?? []).filter(
    (id) => metaById.get(id)?.role !== 'wan',
  );

  type ColumnGroup = { rootId: string; leafIds: string[] };
  const groups: ColumnGroup[] = gatewayKids.map((rootId) => {
    const leafIds = sortKids(childrenOf.get(rootId) ?? []).filter((id) => id !== gatewayId);
    return { rootId, leafIds };
  });

  let cursor = 0;
  const groupSpans: { rootId: string; start: number; width: number; leafIds: string[] }[] = [];
  for (const group of groups) {
    const width = Math.max(1, group.leafIds.length || 1);
    groupSpans.push({ rootId: group.rootId, start: cursor, width, leafIds: group.leafIds });
    cursor += width + 0.35;
  }
  const wanColumns = Math.max(1, wanParents.length);
  const totalColumns = Math.max(1, cursor, wanColumns);
  const wanRowPx =
    wanParents.length <= 1 ? 160 : (wanParents.length - 1) * WAN_NODE_GAP_PX + 160;
  const width = Math.max(
    MIN_WIDTH,
    PAD_X * 2 + Math.max(totalColumns, 4) * 100,
    wanRowPx + PAD_X * 2,
  );
  const innerWidth = width - PAD_X * 2;
  const pxFromPct = (pct: number) => PAD_X + (pct / 100) * innerWidth;
  const pctFromPx = (px: number) => (innerWidth <= 0 ? 50 : ((px - PAD_X) / innerWidth) * 100);

  const positions = new Map<string, { x: number; y: number }>();
  const wanOffset = wanParents.length > 0 ? LAYER_DY + (wanParents.length > 1 ? 20 : 0) : 0;

  positions.set(gatewayId, { x: 50, y: TOP_Y + wanOffset });
  visited.add(gatewayId);

  if (wanParents.length > 0) {
    const gwPx = pxFromPct(50);
    if (wanParents.length === 1) {
      positions.set(wanParents[0]!, { x: 50, y: TOP_Y });
      visited.add(wanParents[0]!);
    } else {
      const spanPx = (wanParents.length - 1) * WAN_NODE_GAP_PX;
      wanParents.forEach((wanId, i) => {
        const px = gwPx - spanPx / 2 + i * WAN_NODE_GAP_PX;
        positions.set(wanId, {
          x: Math.max(6, Math.min(94, pctFromPx(px))),
          y: TOP_Y,
        });
        visited.add(wanId);
      });
    }
  }

  for (const span of groupSpans) {
    const mid = ((span.start + span.width / 2) / totalColumns) * 100;
    positions.set(span.rootId, { x: mid, y: TOP_Y + wanOffset + LAYER_DY });
    visited.add(span.rootId);

    if (span.leafIds.length === 0) continue;
    span.leafIds.forEach((leafId, i) => {
      if (visited.has(leafId)) return;
      const x = ((span.start + i + 0.5) / totalColumns) * 100;
      positions.set(leafId, { x, y: TOP_Y + wanOffset + LAYER_DY * 2 });
      visited.add(leafId);
      const grand = sortKids(childrenOf.get(leafId) ?? []).filter((id) => !visited.has(id));
      grand.forEach((gid, gi) => {
        const gx = ((span.start + i + (gi + 1) / (grand.length + 1)) / totalColumns) * 100;
        positions.set(gid, { x: gx, y: TOP_Y + wanOffset + LAYER_DY * 3 });
        visited.add(gid);
      });
    });
  }

  const maxDepth = [...positions.values()].reduce((m, p) => Math.max(m, p.y), TOP_Y);
  const scaleX = (pct: number) => PAD_X + (pct / 100) * innerWidth;

  const nodes: NodePos[] = [];
  for (const [id, pos] of positions) {
    const device = byId.get(id);
    if (!device) continue;
    nodes.push({
      device,
      x: scaleX(pos.x),
      y: pos.y,
      role: metaById.get(id)?.role ?? 'unknown',
    });
  }

  const height = maxDepth + 64;
  return { nodes, edges, width, height };
}

export function vlanColorMap(vlans: TopologyVlan[]): Map<string, string> {
  const VLAN_COLORS = [
    '#38bdf8',
    '#34d399',
    '#a78bfa',
    '#fbbf24',
    '#f472b6',
    '#fb923c',
    '#2dd4bf',
    '#818cf8',
  ];
  const map = new Map<string, string>();
  vlans.forEach((v, i) => map.set(v.id, VLAN_COLORS[i % VLAN_COLORS.length]!));
  map.set('unknown', '#475569');
  return map;
}

export function edgeStroke(
  edge: TopologyEdge,
  online: boolean,
  colors: Map<string, string>,
): { stroke: string; dash?: string; width: number } {
  if (!online) return { stroke: '#1b2438', width: 0.7 };
  const color = edge.vlan ? (colors.get(edge.vlan) ?? '#64748b') : '#64748b';
  if (edge.kind === 'wifi') return { stroke: color, dash: '3 3', width: 0.9 };
  return { stroke: color, width: 1.1 };
}
