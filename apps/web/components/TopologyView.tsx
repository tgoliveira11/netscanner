'use client';

import { useMemo } from 'react';
import { useStore } from '../lib/store';
import { deviceMeta } from '../lib/device-ui';

/**
 * Radial network map: the gateway/router sits at the center with all other
 * devices arranged around it. A lightweight SVG projection of the inventory.
 */
export function TopologyView() {
  const devices = useStore((s) => s.devices);
  const select = useStore((s) => s.select);

  const { center, nodes, size } = useMemo(() => {
    const list = Object.values(devices);
    const gateway = list.find((d) => d.deviceType === 'router') ?? null;
    const others = list.filter((d) => d.id !== gateway?.id);
    const dim = 640;
    const cx = dim / 2;
    const cy = dim / 2;
    const radius = Math.min(220, 80 + others.length * 8);
    const positioned = others.map((d, i) => {
      const angle = (i / Math.max(1, others.length)) * Math.PI * 2;
      return { device: d, x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) };
    });
    return { center: gateway, nodes: positioned, size: { dim, cx, cy } };
  }, [devices]);

  return (
    <div className="card flex h-full min-h-[480px] flex-col p-4">
      <h3 className="mb-2 text-sm font-semibold text-slate-200">Topology</h3>
      <svg viewBox={`0 0 ${size.dim} ${size.dim}`} className="mx-auto h-auto w-full flex-1" preserveAspectRatio="xMidYMid meet">
        {nodes.map(({ device, x, y }) => (
          <line
            key={`l-${device.id}`}
            x1={size.cx}
            y1={size.cy}
            x2={x}
            y2={y}
            stroke={device.isOnline ? '#243049' : '#1b2438'}
            strokeWidth={1}
          />
        ))}
        {nodes.map(({ device, x, y }) => (
          <g key={device.id} className="cursor-pointer" onClick={() => select(device.id)}>
            <circle cx={x} cy={y} r={16} fill="#1b2438" stroke={device.isOnline ? '#34d399' : '#243049'} />
            <text x={x} y={y + 5} textAnchor="middle" fontSize={15}>
              {deviceMeta(device.deviceType).icon}
            </text>
          </g>
        ))}
        <g className="cursor-pointer" onClick={() => center && select(center.id)}>
          <circle cx={size.cx} cy={size.cy} r={26} fill="#131a2a" stroke="#38bdf8" strokeWidth={2} />
          <text x={size.cx} y={size.cy + 7} textAnchor="middle" fontSize={22}>
            {center ? deviceMeta(center.deviceType).icon : '🛜'}
          </text>
        </g>
      </svg>
      <p className="text-center text-xs text-muted">
        {center ? `Gateway: ${center.ip}` : 'Gateway not yet identified'} · {nodes.length} devices
      </p>
    </div>
  );
}
