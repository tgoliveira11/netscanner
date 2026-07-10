'use client';

import { useMemo, useState } from 'react';
import type { SpeedTestResult } from '@netscanner/contracts';

const SERIES_COLORS = ['#38bdf8', '#34d399', '#fbbf24', '#f87171', '#a78bfa', '#fb7185'];

function seriesKey(s: SpeedTestResult): string {
  if (s.testKind === 'wan' && s.wanGateway) return `WAN · ${s.wanGateway}`;
  if (s.egressRoute && s.egressRoute !== 'unknown') {
    const gw = s.egressGateway ? ` (${s.egressGateway})` : '';
    const label = s.egressRoute === 'vpn' ? 'VPN' : s.egressRoute === 'lb' ? 'LB' : 'WAN';
    return `Agent · ${label}${gw}`;
  }
  if (s.egressGateway) return `Agent · ${s.egressGateway}`;
  return 'Agent (default route)';
}

function fmtMbps(v: number | null | undefined): string {
  if (v == null) return '—';
  return `${v.toFixed(1)} Mbps`;
}

export function SpeedTestChart({ samples }: { samples: SpeedTestResult[] }) {
  const allSeries = useMemo(() => [...new Set(samples.map(seriesKey))], [samples]);
  const [hidden, setHidden] = useState<Set<string>>(new Set());

  const visibleSeries = allSeries.filter((n) => !hidden.has(n));
  const withDownload = samples.filter((s) => s.downloadMbps != null && visibleSeries.includes(seriesKey(s)));

  const toggleSeries = (name: string) => {
    setHidden((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  if (withDownload.length < 2) {
    return (
      <p className="rounded-lg border border-edge bg-panelup px-3 py-4 text-xs text-muted">
        Need at least 2 download samples for the chart (check series filters).
      </p>
    );
  }

  const chronological = [...withDownload].sort(
    (a, b) => Date.parse(a.measuredAt) - Date.parse(b.measuredAt),
  );
  const bySeries = new Map<string, SpeedTestResult[]>();
  for (const s of chronological) {
    const key = seriesKey(s);
    const list = bySeries.get(key) ?? [];
    list.push(s);
    bySeries.set(key, list);
  }

  const width = 640;
  const height = 220;
  const pad = { l: 48, r: 12, t: 12, b: 28 };
  const innerW = width - pad.l - pad.r;
  const innerH = height - pad.t - pad.b;
  const tMin = Date.parse(chronological[0]!.measuredAt);
  const tMax = Date.parse(chronological[chronological.length - 1]!.measuredAt);
  const tSpan = Math.max(tMax - tMin, 60_000);
  const yMax = Math.max(10, ...withDownload.map((s) => s.downloadMbps ?? 0)) * 1.1;

  const x = (t: number) => pad.l + ((t - tMin) / tSpan) * innerW;
  const y = (v: number) => pad.t + innerH - (v / yMax) * innerH;

  const gridY = [0, 0.25, 0.5, 0.75, 1].map((f) => ({
    v: yMax * f,
    py: y(yMax * f),
  }));

  return (
    <div className="space-y-2">
      <div className="text-[10px] uppercase text-muted">Download Mbps — over time</div>
      <div className="overflow-x-auto rounded-lg border border-edge bg-panelup p-2">
        <svg viewBox={`0 0 ${width} ${height}`} className="h-auto w-full min-w-[20rem]" role="img" aria-label="Speed test chart">
          {gridY.map((g) => (
            <g key={g.v}>
              <line x1={pad.l} y1={g.py} x2={width - pad.r} y2={g.py} stroke="currentColor" className="text-edge" strokeWidth={1} />
              <text x={pad.l - 6} y={g.py + 3} textAnchor="end" className="fill-muted text-[9px]">
                {Math.round(g.v)}
              </text>
            </g>
          ))}
          {visibleSeries.map((name, idx) => {
            const pts = bySeries.get(name) ?? [];
            if (pts.length < 1) return null;
            const d = pts
              .map((s, i) => `${i === 0 ? 'M' : 'L'} ${x(Date.parse(s.measuredAt))} ${y(s.downloadMbps ?? 0)}`)
              .join(' ');
            const color = SERIES_COLORS[idx % SERIES_COLORS.length];
            return (
              <g key={name}>
                <path d={d} fill="none" stroke={color} strokeWidth={2} strokeLinejoin="round" />
                {pts.map((s) => (
                  <circle key={s.id} cx={x(Date.parse(s.measuredAt))} cy={y(s.downloadMbps ?? 0)} r={3} fill={color}>
                    <title>{`${name} · ${new Date(s.measuredAt).toLocaleString()} · ${fmtMbps(s.downloadMbps)}`}</title>
                  </circle>
                ))}
              </g>
            );
          })}
        </svg>
      </div>
      <ul className="flex flex-wrap gap-3 text-[11px] text-muted">
        {allSeries.map((name, idx) => {
          const off = hidden.has(name);
          const color = SERIES_COLORS[idx % SERIES_COLORS.length];
          return (
            <li key={name}>
              <button
                type="button"
                onClick={() => toggleSeries(name)}
                className={`flex items-center gap-1.5 rounded px-1 py-0.5 hover:bg-panelup ${off ? 'opacity-40 line-through' : ''}`}
              >
                <span className="inline-block h-2 w-2 rounded-full" style={{ background: color }} />
                {name}
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
