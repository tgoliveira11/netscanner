'use client';

import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { TopologyEdge, TopologyNodeRole } from '@netscanner/contracts';
import { useStore } from '../lib/store';
import { deviceMeta, topologyNodeIcon } from '../lib/device-ui';
import {
  edgeStroke,
  layoutVlanTree,
  vlanColorMap,
  type NodePos,
} from '../lib/topology-layout';
import { buildRenderLayout, useTopologyStore, type ViewTransform } from '../lib/topology-store';

const MIN_ZOOM = 0.25;
const MAX_ZOOM = 2.5;
const ZOOM_STEP = 1.18;

function clampZoom(scale: number): number {
  return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, scale));
}

function viewCenteredOnGateway(
  gateway: NodePos | undefined,
  graphWidth: number,
  graphHeight: number,
  viewportWidth: number,
  viewportHeight: number,
): ViewTransform {
  if (!gateway || viewportWidth <= 0 || viewportHeight <= 0) {
    return { scale: 1, panX: 0, panY: 0 };
  }
  const fitScale = Math.min(
    (viewportWidth * 0.9) / graphWidth,
    (viewportHeight * 0.82) / graphHeight,
    1.15,
  );
  const scale = clampZoom(Math.max(0.4, fitScale));
  return {
    scale,
    panX: viewportWidth / 2 - gateway.x * scale,
    panY: viewportHeight / 2 - gateway.y * scale,
  };
}

function nodeIcon(role: TopologyNodeRole | 'unknown', device: import('@netscanner/contracts').Device): string {
  if (role !== 'unknown' && role !== 'endpoint') return topologyNodeIcon(role);
  return deviceMeta(device.deviceType).icon;
}

function nodeRadius(role: TopologyNodeRole | 'unknown', device: import('@netscanner/contracts').Device): number {
  const isWan = role === 'wan';
  const isGateway = role === 'gateway';
  const isAp = role === 'wifi-ap';
  const isInfra = role === 'wired-router';
  const isRouter = isWan || isGateway || isAp || isInfra || device.deviceType === 'router';
  return isGateway || isWan ? 22 : isRouter ? 17 : 12;
}

function nodeDisplayLabel(
  role: TopologyNodeRole | 'unknown',
  device: import('@netscanner/contracts').Device,
): string {
  if (role === 'wan') {
    return (
      device.hostname ||
      (typeof device.signals?.pfsenseInterface === 'string'
        ? `Modem ${device.signals.pfsenseInterface}`
        : 'Modem')
    );
  }
  if (role === 'gateway') return device.hostname || 'pfSense';
  return device.hostname || device.ip;
}

/** Vertical extent of a node's caption block below the circle (for collision checks). */
function nodeCaptionBottom(y: number, r: number, showIp: boolean): number {
  return y + r + (showIp ? 32 : 18);
}

function nodeCaptionTop(y: number, r: number): number {
  return y + r + 6;
}

function truncateLabel(text: string, max = 18): string {
  return text.length > max ? `${text.slice(0, max - 2)}…` : text;
}

export function TopologyView({ fullPage = false }: { fullPage?: boolean }) {
  const devices = useStore((s) => s.devices);
  const select = useStore((s) => s.select);
  const topology = useTopologyStore((s) => s.topology);
  const layoutCache = useTopologyStore((s) => s.layout);
  const loading = useTopologyStore((s) => s.loading);
  const view = useTopologyStore((s) => s.view);
  const viewInitialized = useTopologyStore((s) => s.viewInitialized);
  const setView = useTopologyStore((s) => s.setView);
  const applyLayout = useTopologyStore((s) => s.applyLayout);
  const markViewInitialized = useTopologyStore((s) => s.markViewInitialized);

  const viewportRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<{ x: number; y: number; panX: number; panY: number } | null>(null);
  const dragActiveRef = useRef(false);
  const autoCenteredRef = useRef(false);
  const [isDragging, setIsDragging] = useState(false);

  useEffect(() => useTopologyStore.getState().subscribePage(), []);

  useEffect(() => {
    if (!viewInitialized) autoCenteredRef.current = false;
  }, [viewInitialized]);

  const deviceList = useMemo(() => Object.values(devices), [devices]);
  const computed = useMemo(() => layoutVlanTree(deviceList, topology), [deviceList, topology]);
  const layoutRevision = topology?.revision ?? 'none';

  useEffect(() => {
    if (!topology || computed.nodes.length === 0) return;
    applyLayout(computed);
    // Re-layout only when graph structure changes (revision), not on presence updates.
    // eslint-disable-next-line react-hooks/exhaustive-deps -- computed derived from revision + device count
  }, [layoutRevision, deviceList.length, applyLayout, topology]);

  const { nodes: rawNodes, edges, width, height } = useMemo(
    () => buildRenderLayout(layoutCache, computed),
    [layoutCache, computed],
  );

  const nodes = useMemo(() => {
    const seen = new Set<string>();
    return rawNodes.filter((n) => {
      if (seen.has(n.device.id)) return false;
      seen.add(n.device.id);
      return true;
    });
  }, [rawNodes]);

  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.device.id, n])), [nodes]);
  const gatewayNode = useMemo(
    () =>
      nodes.find((n) => n.role === 'gateway') ??
      (topology?.gatewayId ? nodeById.get(topology.gatewayId) : undefined),
    [nodes, topology?.gatewayId, nodeById],
  );
  const vlans = topology?.vlans ?? [];
  const colors = useMemo(() => vlanColorMap(vlans), [vlans]);
  const wiredCount = edges.filter((e: TopologyEdge) => e.kind === 'wired').length;
  const wifiCount = edges.filter((e: TopologyEdge) => e.kind === 'wifi').length;

  const centerOnGateway = useCallback(() => {
    const vp = viewportRef.current;
    if (!vp || !gatewayNode) return;
    setView(viewCenteredOnGateway(gatewayNode, width, height, vp.clientWidth, vp.clientHeight));
    markViewInitialized();
    autoCenteredRef.current = true;
  }, [gatewayNode, width, height, setView, markViewInitialized]);

  // Auto-center only once when the graph first becomes visible — never on layout/size updates.
  useLayoutEffect(() => {
    if (viewInitialized || autoCenteredRef.current || nodes.length === 0) return;
    const vp = viewportRef.current;
    const gw = gatewayNode;
    if (!vp || !gw) return;
    autoCenteredRef.current = true;
    markViewInitialized();
    setView(viewCenteredOnGateway(gw, width, height, vp.clientWidth, vp.clientHeight));
  }, [viewInitialized, nodes.length, gatewayNode?.device.id, markViewInitialized, setView]);

  const zoomBy = useCallback(
    (factor: number, anchorX?: number, anchorY?: number) => {
      const vp = viewportRef.current;
      if (!vp) return;
      setView((cur) => {
        const nextScale = clampZoom(cur.scale * factor);
        const ax = anchorX ?? vp.clientWidth / 2;
        const ay = anchorY ?? vp.clientHeight / 2;
        const ratio = nextScale / cur.scale;
        return {
          scale: nextScale,
          panX: ax - (ax - cur.panX) * ratio,
          panY: ay - (ay - cur.panY) * ratio,
        };
      });
    },
    [setView],
  );

  useEffect(() => {
    const blockSelect = (e: Event) => {
      if (dragRef.current) e.preventDefault();
    };
    document.addEventListener('selectstart', blockSelect);
    return () => document.removeEventListener('selectstart', blockSelect);
  }, []);

  const edgeLabels = useMemo(() => {
    const labels: { key: string; x: number; y: number; text: string }[] = [];
    const occupied: { x: number; y: number }[] = [];

    for (const n of nodes) {
      const r = nodeRadius(n.role, n.device);
      const label = nodeDisplayLabel(n.role, n.device);
      const showIp =
        n.role !== 'gateway' &&
        Boolean(n.device.hostname) &&
        n.device.ip !== label &&
        n.device.ip !== n.device.hostname;
      occupied.push({ x: n.x, y: nodeCaptionTop(n.y, r) });
      if (showIp) occupied.push({ x: n.x, y: nodeCaptionBottom(n.y, r, true) });
    }

    const tooClose = (x: number, y: number) =>
      occupied.some((o) => Math.hypot(o.x - x, o.y - y) < 14);

    for (const edge of edges) {
      const from = nodeById.get(edge.from);
      const to = nodeById.get(edge.to);
      if (!from || !to) continue;

      const text =
        edge.kind === 'wifi' && edge.ssid
          ? edge.ssid
          : edge.label === 'mac-sharing'
            ? 'mac-sharing'
            : null;
      if (!text) continue;

      const fromR = nodeRadius(from.role, from.device);
      const toR = nodeRadius(to.role, to.device);
      const fromLabel = nodeDisplayLabel(from.role, from.device);
      const toLabel = nodeDisplayLabel(to.role, to.device);
      if (text === fromLabel || text === toLabel) continue;

      // SSID / link caption sits just above the client circle (from), clear of node labels below.
      const clientAboveParent = from.y < to.y;
      let x = from.x;
      let y = clientAboveParent ? from.y + fromR + 34 : from.y - fromR - 4;

      if (tooClose(x, y)) {
        const midX = (from.x + to.x) / 2;
        const midY = (from.y + to.y) / 2;
        const toShowIp =
          Boolean(to.device.hostname) &&
          to.device.ip !== toLabel &&
          to.device.ip !== to.device.hostname;
        const parentBottom = nodeCaptionBottom(to.y, toR, toShowIp);
        y = Math.max(midY, parentBottom + 10);
        x = midX;
      }
      if (tooClose(x, y)) continue;

      labels.push({
        key: `${edge.from}-${edge.to}-${text}`,
        x,
        y,
        text,
      });
      occupied.push({ x, y });
    }
    return labels;
  }, [edges, nodeById, nodes]);

  const onWheel = useCallback(
    (e: React.WheelEvent) => {
      e.preventDefault();
      const rect = viewportRef.current?.getBoundingClientRect();
      if (!rect) return;
      const factor = e.deltaY > 0 ? 1 / ZOOM_STEP : ZOOM_STEP;
      zoomBy(factor, e.clientX - rect.left, e.clientY - rect.top);
    },
    [zoomBy],
  );

  const onPointerDown = useCallback(
    (e: React.PointerEvent) => {
      if (e.button !== 0) return;
      e.preventDefault();
      window.getSelection()?.removeAllRanges();
      dragRef.current = { x: e.clientX, y: e.clientY, panX: view.panX, panY: view.panY };
      dragActiveRef.current = false;
      setIsDragging(false);
      (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    },
    [view.panX, view.panY],
  );

  const onPointerMove = useCallback((e: React.PointerEvent) => {
    const drag = dragRef.current;
    if (!drag) return;
    const dx = e.clientX - drag.x;
    const dy = e.clientY - drag.y;
    if (!dragActiveRef.current && Math.hypot(dx, dy) < 4) return;
    if (!dragActiveRef.current) window.getSelection()?.removeAllRanges();
    dragActiveRef.current = true;
    e.preventDefault();
    setIsDragging(true);
    setView((cur) => ({
      ...cur,
      panX: drag.panX + dx,
      panY: drag.panY + dy,
    }));
  }, [setView]);

  const onPointerUp = useCallback(() => {
    dragRef.current = null;
    dragActiveRef.current = false;
    setIsDragging(false);
  }, []);

  return (
    <div className={`card flex flex-col p-4 ${fullPage ? 'min-h-[calc(100vh-8rem)]' : 'min-h-[640px]'}`}>
      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <h3 className="text-sm font-semibold text-slate-200">Topology</h3>
        <div className="flex flex-wrap items-center gap-2">
          {nodes.length > 0 && (
            <div className="flex items-center gap-1">
              <button
                type="button"
                className="btn btn-ghost px-2 py-1 text-xs"
                onClick={() => zoomBy(1 / ZOOM_STEP)}
                title="Zoom out"
                aria-label="Zoom out"
              >
                −
              </button>
              <span className="min-w-[3rem] text-center text-[10px] text-muted">
                {Math.round(view.scale * 100)}%
              </span>
              <button
                type="button"
                className="btn btn-ghost px-2 py-1 text-xs"
                onClick={() => zoomBy(ZOOM_STEP)}
                title="Zoom in"
                aria-label="Zoom in"
              >
                +
              </button>
              <button
                type="button"
                className="btn btn-ghost px-2 py-1 text-xs"
                onClick={centerOnGateway}
                title="Center on pfSense"
              >
                Center
              </button>
            </div>
          )}
          <span className="text-xs text-muted">
            {loading
              ? 'Updating…'
              : `${nodes.length} nodes · ${wiredCount} wired · ${wifiCount} wifi`}
          </span>
        </div>
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

      <div
        ref={viewportRef}
        className={`topology-canvas relative w-full flex-1 overflow-hidden rounded-lg border border-edge bg-base/40 select-none touch-none ${
          fullPage ? 'min-h-[calc(100vh-12rem)]' : 'min-h-[600px]'
        } ${isDragging ? 'topology-panning cursor-grabbing' : 'cursor-grab'}`}
        onWheel={onWheel}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerUp}
        onPointerCancel={onPointerUp}
        onDragStart={(e) => e.preventDefault()}
      >
        {nodes.length === 0 ? (
          <p className="py-16 text-center text-sm text-muted">
            {loading && !topology
              ? 'Loading topology…'
              : 'No topology yet — devices appear from pfSense leases and inventory; no scan required.'}
          </p>
        ) : (
          <div
            className="topology-canvas select-none"
            style={{
              transform: `translate(${view.panX}px, ${view.panY}px) scale(${view.scale})`,
              transformOrigin: '0 0',
              width,
              height,
            }}
          >
            <svg
              width={width}
              height={height}
              viewBox={`0 0 ${width} ${height}`}
              className="select-none"
              onDragStart={(e) => e.preventDefault()}
            >
            {edges.map((edge) => {
              const from = nodeById.get(edge.from);
              const to = nodeById.get(edge.to);
              if (!from || !to) return null;
              const parentOnline = to.device.isOnline;
              const childOnline = from.device.isOnline;
              const style = edgeStroke(edge, parentOnline && childOnline, colors);
              const opacity = !parentOnline ? 0.28 : childOnline ? 0.75 : 0.52;
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
                    opacity={opacity}
                  />
                </g>
              );
            })}

            {edgeLabels.map(({ key, x, y, text }) => (
              <text
                key={key}
                x={x}
                y={y}
                textAnchor="middle"
                fontSize={8}
                fill="#64748b"
                pointerEvents="none"
              >
                {text}
              </text>
            ))}

            {nodes.map(({ device, x, y, role }) => {
              const isWan = role === 'wan';
              const isGateway = role === 'gateway';
              const isAp = role === 'wifi-ap';
              const isInfra = role === 'wired-router';
              const isRouter = isWan || isGateway || isAp || isInfra || device.deviceType === 'router';
              const r = nodeRadius(role, device);
              const icon = nodeIcon(role, device);
              const label = nodeDisplayLabel(role, device);
              const showIp =
                !isGateway &&
                Boolean(device.hostname) &&
                device.ip !== label &&
                device.ip !== device.hostname;
              const nameY = y + r + 16;
              const ipY = y + r + 28;
              return (
                <g key={device.id}>
                  <circle
                    cx={x}
                    cy={y}
                    r={r}
                    className="cursor-pointer"
                    onPointerDown={(e) => e.stopPropagation()}
                    onClick={() => select(device.id)}
                    fill={
                      isWan
                        ? '#1a1208'
                        : isGateway
                          ? '#0c4a6e'
                          : isAp
                            ? '#1a1430'
                            : isInfra
                              ? '#0f1f1a'
                              : '#131a2a'
                    }
                    stroke={
                      device.isOnline
                        ? isWan
                          ? '#fb923c'
                          : isGateway
                            ? '#38bdf8'
                            : isAp
                              ? '#a78bfa'
                              : isInfra
                                ? '#34d399'
                                : '#64748b'
                        : '#243049'
                    }
                    strokeWidth={isGateway || isWan ? 2.5 : isRouter ? 2 : 1}
                  />
                  <text
                    x={x}
                    y={y + (isRouter ? 5 : 4)}
                    textAnchor="middle"
                    dominantBaseline="middle"
                    fontSize={isRouter ? 14 : 11}
                    pointerEvents="none"
                  >
                    {icon}
                  </text>
                  <text
                    x={x}
                    y={nameY}
                    textAnchor="middle"
                    dominantBaseline="hanging"
                    fontSize={9}
                    fill="#94a3b8"
                    pointerEvents="none"
                  >
                    {truncateLabel(label)}
                  </text>
                  {showIp && (
                    <text
                      x={x}
                      y={ipY}
                      textAnchor="middle"
                      dominantBaseline="hanging"
                      fontSize={8}
                      fill="#475569"
                      pointerEvents="none"
                    >
                      {device.ip}
                    </text>
                  )}
                </g>
              );
            })}
            </svg>
          </div>
        )}
      </div>
      <p className="mt-2 text-center text-xs text-muted">
        Scroll to zoom · drag to pan · Center refocuses pfSense · solid = wired · dashed = wifi
      </p>
    </div>
  );
}
