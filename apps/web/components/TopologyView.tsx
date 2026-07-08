'use client';

import { useEffect, useMemo, useState } from 'react';
import type { Device, TopologyEdge, TopologyNodeRole, TopologyResponse, TopologyVlan } from '@netscanner/contracts';
import { api } from '../lib/api';
import { useStore } from '../lib/store';
import { deviceMeta, topologyNodeIcon } from '../lib/device-ui';

interface NodePos {
  device: Device;
  x: number;
  y: number;
  role: TopologyNodeRole | 'unknown';
}

const PAD_X = 48;
const LAYER_DY = 96;
const TOP_Y = 48;
const MIN_WIDTH = 780;

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

function vlanColorMap(vlans: TopologyVlan[]): Map<string, string> {
  const map = new Map<string, string>();
  vlans.forEach((v, i) => map.set(v.id, VLAN_COLORS[i % VLAN_COLORS.length]!));
  map.set('unknown', '#475569');
  return map;
}

function edgeStroke(
  edge: TopologyEdge,
  online: boolean,
  colors: Map<string, string>,
): { stroke: string; dash?: string; width: number } {
  if (!online) return { stroke: '#1b2438', width: 0.7 };
  const color = edge.vlan ? (colors.get(edge.vlan) ?? '#64748b') : '#64748b';
  if (edge.kind === 'wifi') return { stroke: color, dash: '3 3', width: 0.9 };
  return { stroke: color, width: 1.1 };
}

/**
 * Layout: gateway (top) → infra + APs by VLAN columns → clients under each AP/infra.
 * Prefer parent→child tree from edges rather than flat tier buckets so VLANs stay grouped.
 */
function layoutVlanTree(
  list: Device[],
  topology: TopologyResponse | null,
): { nodes: NodePos[]; edges: TopologyEdge[]; width: number; height: number } {
  const edges = topology?.edges ?? [];
  const gatewayId = topology?.gatewayId ?? null;
  const metaById = new Map((topology?.nodes ?? []).map((n) => [n.id, n]));
  const byId = new Map(list.map((d) => [d.id, d]));

  if (!gatewayId || !byId.has(gatewayId)) {
    return { nodes: [], edges: [], width: MIN_WIDTH, height: 200 };
  }

  const childrenOf = new Map<string, string[]>();
  for (const edge of edges) {
    if (!byId.has(edge.from) || !byId.has(edge.to)) continue;
    const group = childrenOf.get(edge.to) ?? [];
    if (!group.includes(edge.from)) group.push(edge.from);
    childrenOf.set(edge.to, group);
  }

  // Sort children: wired-router first, then wifi-ap, then by VLAN then IP.
  const roleRank = (id: string) => {
    const role = metaById.get(id)?.role;
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

  type LayoutRow = { id: string; depth: number; column: number };
  const rows: LayoutRow[] = [];
  const visited = new Set<string>();

  // Breadth-first with column slots per VLAN group under gateway children.
  const gatewayKids = sortKids(childrenOf.get(gatewayId) ?? []);
  rows.push({ id: gatewayId, depth: 0, column: 0 });
  visited.add(gatewayId);

  // Assign each infra/AP a column span based on its clients.
  type ColumnGroup = { rootId: string; leafIds: string[] };
  const groups: ColumnGroup[] = gatewayKids.map((rootId) => {
    const leafIds = sortKids(childrenOf.get(rootId) ?? []).filter((id) => !visited.has(id));
    return { rootId, leafIds };
  });

  // Also attach any direct gateway children that are endpoints (wired LAN clients).
  // Already in gatewayKids if edges point to gateway.

  let cursor = 0;
  const groupSpans: { rootId: string; start: number; width: number; leafIds: string[] }[] = [];
  for (const group of groups) {
    const width = Math.max(1, group.leafIds.length || 1);
    groupSpans.push({ rootId: group.rootId, start: cursor, width, leafIds: group.leafIds });
    cursor += width + 0.35; // gap between VLAN columns
  }
  const totalColumns = Math.max(1, cursor);

  // Place gateway centered
  const positions = new Map<string, { x: number; y: number }>();
  positions.set(gatewayId, { x: 50, y: TOP_Y });

  for (const span of groupSpans) {
    const mid = ((span.start + span.width / 2) / totalColumns) * 100;
    positions.set(span.rootId, { x: mid, y: TOP_Y + LAYER_DY });
    visited.add(span.rootId);

    if (span.leafIds.length === 0) continue;
    span.leafIds.forEach((leafId, i) => {
      const x = ((span.start + i + 0.5) / totalColumns) * 100;
      positions.set(leafId, { x, y: TOP_Y + LAYER_DY * 2 });
      visited.add(leafId);
      // rare: grandchildren
      const grand = sortKids(childrenOf.get(leafId) ?? []).filter((id) => !visited.has(id));
      grand.forEach((gid, gi) => {
        const gx = ((span.start + i + (gi + 1) / (grand.length + 1)) / totalColumns) * 100;
        positions.set(gid, { x: gx, y: TOP_Y + LAYER_DY * 3 });
        visited.add(gid);
      });
    });
  }

  const maxDepth = [...positions.values()].reduce((m, p) => Math.max(m, p.y), TOP_Y);
  const width = Math.max(MIN_WIDTH, PAD_X * 2 + Math.max(totalColumns, 4) * 100);
  const scaleX = (pct: number) => PAD_X + (pct / 100) * (width - PAD_X * 2);

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

function resolveDeviceFallbackVlan(device: Device | undefined): string {
  if (!device) return 'zzz';
  const iface = device.signals?.pfsenseInterface ?? device.signals?.routerInterface;
  if (typeof iface === 'string') return iface;
  return device.ip;
}

function nodeIcon(role: TopologyNodeRole | 'unknown', device: Device): string {
  if (role !== 'unknown' && role !== 'endpoint') return topologyNodeIcon(role);
  return deviceMeta(device.deviceType).icon;
}

export function TopologyView() {
  const devices = useStore((s) => s.devices);
  const select = useStore((s) => s.select);
  const [topology, setTopology] = useState<TopologyResponse | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      setLoading(true);
      api
        .topology()
        .then((t) => {
          if (!cancelled) setTopology(t);
        })
        .catch(() => undefined)
        .finally(() => {
          if (!cancelled) setLoading(false);
        });
    };
    load();
    const timer = setInterval(load, 60_000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  const layout = useMemo(() => layoutVlanTree(Object.values(devices), topology), [devices, topology]);
  const { nodes, edges, width, height } = layout;
  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.device.id, n])), [nodes]);
  const vlans = topology?.vlans ?? [];
  const colors = useMemo(() => vlanColorMap(vlans), [vlans]);
  const wiredCount = edges.filter((e) => e.kind === 'wired').length;
  const wifiCount = edges.filter((e) => e.kind === 'wifi').length;

  return (
    <div className="card flex min-h-[640px] flex-col p-4">
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-slate-200">Topology</h3>
        <span className="text-xs text-muted">
          {loading
            ? 'Updating…'
            : `${nodes.length} nodes · ${wiredCount} wired · ${wifiCount} wifi`}
        </span>
      </div>

      {vlans.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-edge bg-panelup px-3 py-2">
          <span className="text-[10px] font-semibold uppercase tracking-wide text-muted">VLANs</span>
          {vlans.map((v) => (
            <div key={v.id} className="flex items-center gap-1.5 text-xs text-slate-300">
              <span
                className="inline-block h-0.5 w-8 rounded-full"
                style={{ backgroundColor: colors.get(v.id) ?? '#64748b' }}
              />
              {v.label}
            </div>
          ))}
          <div className="ml-auto flex items-center gap-3 text-[10px] text-muted">
            <span className="inline-flex items-center gap-1">
              <span className="inline-block h-px w-6 bg-slate-400" /> wired
            </span>
            <span className="inline-flex items-center gap-1">
              <span
                className="inline-block h-px w-6 border-t border-dashed border-slate-400"
              />{' '}
              wifi
            </span>
          </div>
        </div>
      )}

      <div className="min-h-[600px] w-full flex-1 overflow-x-auto">
        {nodes.length === 0 ? (
          <p className="py-16 text-center text-sm text-muted">
            No topology yet — wait for pfSense leases and a scan, then refresh.
          </p>
        ) : (
          <svg
            viewBox={`0 0 ${width} ${height}`}
            className="h-full min-h-[600px] w-full"
            style={{ minWidth: width }}
            preserveAspectRatio="xMinYMid meet"
          >
            {edges.map((edge) => {
              const from = nodeById.get(edge.from);
              const to = nodeById.get(edge.to);
              if (!from || !to) return null;
              const online = from.device.isOnline && to.device.isOnline;
              const midY = (from.y + to.y) / 2;
              const style = edgeStroke(edge, online, colors);
              return (
                <g key={`${edge.from}-${edge.to}-${edge.kind}`}>
                  <line
                    x1={from.x}
                    y1={from.y}
                    x2={to.x}
                    y2={to.y}
                    stroke={style.stroke}
                    strokeWidth={style.width}
                    strokeDasharray={style.dash}
                    opacity={online ? 0.75 : 0.28}
                  />
                  {(edge.ssid || (edge.label && !['wired', 'uplink', 'infra', 'lan', 'wifi'].includes(edge.label))) && (
                    <text x={(from.x + to.x) / 2} y={midY - 4} textAnchor="middle" fontSize={8} fill="#64748b">
                      {edge.ssid ?? edge.label}
                    </text>
                  )}
                </g>
              );
            })}

            {nodes.map(({ device, x, y, role }) => {
              const isGateway = role === 'gateway';
              const isAp = role === 'wifi-ap';
              const isInfra = role === 'wired-router';
              const isRouter = isGateway || isAp || isInfra || device.deviceType === 'router';
              const r = isGateway ? 22 : isRouter ? 17 : 12;
              const icon = nodeIcon(role, device);
              const label = isGateway
                ? device.hostname || 'pfSense'
                : device.hostname || device.ip;
              return (
                <g key={device.id} className="cursor-pointer" onClick={() => select(device.id)}>
                  <circle
                    cx={x}
                    cy={y}
                    r={r}
                    fill={isGateway ? '#0c4a6e' : isAp ? '#1a1430' : isInfra ? '#0f1f1a' : '#131a2a'}
                    stroke={
                      device.isOnline
                        ? isGateway
                          ? '#38bdf8'
                          : isAp
                            ? '#a78bfa'
                            : isInfra
                              ? '#34d399'
                              : '#64748b'
                        : '#243049'
                    }
                    strokeWidth={isGateway ? 2.5 : isRouter ? 2 : 1}
                  />
                  <text x={x} y={y + (isRouter ? 5 : 4)} textAnchor="middle" fontSize={isRouter ? 14 : 11}>
                    {icon}
                  </text>
                  <text x={x} y={y + r + 13} textAnchor="middle" fontSize={9} fill="#94a3b8">
                    {label.length > 18 ? `${label.slice(0, 16)}…` : label}
                  </text>
                  {!isGateway && (
                    <text x={x} y={y + r + 24} textAnchor="middle" fontSize={8} fill="#475569">
                      {device.ip}
                    </text>
                  )}
                </g>
              );
            })}
          </svg>
        )}
      </div>
      <p className="mt-2 text-center text-xs text-muted">
        pfSense → infra / WiFi APs by VLAN · solid = wired · dashed = wifi · line color = VLAN
      </p>
    </div>
  );
}
