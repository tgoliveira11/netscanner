'use client';

import { useMemo } from 'react';
import { useStore } from '../lib/store';

function Stat({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div className="card flex-1 p-4">
      <div className="text-xs uppercase tracking-wide text-muted">{label}</div>
      <div className={`mt-1 text-2xl font-semibold ${tone ?? 'text-slate-100'}`}>{value}</div>
    </div>
  );
}

/** Live counters + scan progress bar, all driven by the store projection. */
export function StatsBar() {
  const devices = useStore((s) => s.devices);
  const scan = useStore((s) => s.scan);

  const { total, online } = useMemo(() => {
    const list = Object.values(devices);
    return { total: list.length, online: list.filter((d) => d.isOnline).length };
  }, [devices]);

  const progress =
    scan && scan.hostsTotal > 0 ? Math.round((scan.devicesClassified / scan.hostsTotal) * 100) : 0;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-3">
        <Stat label="Devices" value={total} />
        <Stat label="Online" value={online} tone="text-good" />
        <Stat label="Discovered" value={scan?.hostsDiscovered ?? 0} />
        <Stat label="Classified" value={scan?.devicesClassified ?? 0} />
        <Stat
          label="Scan status"
          value={scan?.status ?? 'idle'}
          tone={scan?.status === 'failed' ? 'text-bad' : 'text-accent'}
        />
      </div>
      {scan && (scan.status === 'discovering' || scan.status === 'fingerprinting') && (
        <div className="card p-3">
          <div className="mb-1 flex justify-between text-xs text-muted">
            <span>{scan.status === 'discovering' ? 'Discovering hosts…' : 'Fingerprinting…'}</span>
            <span>{progress}%</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-panelup">
            <div className="h-full bg-accent transition-all" style={{ width: `${Math.max(5, progress)}%` }} />
          </div>
        </div>
      )}
    </div>
  );
}
