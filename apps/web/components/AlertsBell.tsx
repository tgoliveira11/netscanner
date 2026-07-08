'use client';

import { useState, useRef, useEffect } from 'react';
import { useStore, type AlertItem } from '../lib/store';

function alertBadgeClass(kind: AlertItem['kind']): string {
  switch (kind) {
    case 'new':
      return 'bg-good/15 text-good';
    case 'security':
      return 'bg-bad/15 text-bad';
    default:
      return 'bg-warn/15 text-warn';
  }
}

/** Compact alerts dropdown for the header (keeps main grid full-width). */
export function AlertsBell() {
  const alerts = useStore((s) => s.alerts);
  const select = useStore((s) => s.select);
  const clear = useStore((s) => s.clearAlerts);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, []);

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="btn btn-ghost relative flex items-center gap-1.5"
        aria-expanded={open}
      >
        <span aria-hidden>🔔</span>
        Alerts
        {alerts.length > 0 && (
          <span className="badge bg-warn/20 text-warn">{alerts.length}</span>
        )}
      </button>
      {open && (
        <div className="absolute right-0 z-50 mt-2 w-80 max-h-[min(420px,70vh)] overflow-auto rounded-xl border border-edge bg-panel p-2 shadow-xl">
          <div className="mb-2 flex items-center justify-between px-1">
            <span className="text-xs font-semibold text-slate-300">Scan alerts</span>
            {alerts.length > 0 && (
              <button type="button" onClick={clear} className="text-xs text-muted hover:text-accent">
                clear
              </button>
            )}
          </div>
          <div className="space-y-1.5">
            {alerts.map((a) => (
              <button
                key={a.id}
                type="button"
                onClick={() => {
                  select(a.deviceId);
                  setOpen(false);
                }}
                className="block w-full rounded-lg border border-edge bg-panelup px-3 py-2 text-left text-xs hover:border-accent"
              >
                <span className={`badge mr-2 ${alertBadgeClass(a.kind)}`}>
                  {a.kind}
                </span>
                <span className="text-slate-200">{a.message}</span>
                <div className="mt-0.5 text-[10px] text-muted">{new Date(a.at).toLocaleTimeString()}</div>
              </button>
            ))}
            {alerts.length === 0 && (
              <p className="px-2 py-4 text-center text-xs text-muted">No alerts yet.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
