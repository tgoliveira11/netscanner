'use client';

import { useStore } from '../lib/store';

/** Live feed of new/changed-device alerts raised during scans. */
export function AlertsPanel() {
  const alerts = useStore((s) => s.alerts);
  const select = useStore((s) => s.select);
  const clear = useStore((s) => s.clearAlerts);

  return (
    <div className="card flex h-full flex-col p-4">
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-200">Alerts</h3>
        {alerts.length > 0 && (
          <button onClick={clear} className="text-xs text-muted hover:text-accent">
            clear
          </button>
        )}
      </div>
      <div className="flex-1 space-y-2 overflow-auto">
        {alerts.map((a) => (
          <button
            key={a.id}
            onClick={() => select(a.deviceId)}
            className="block w-full rounded-lg border border-edge bg-panelup px-3 py-2 text-left text-xs hover:border-accent"
          >
            <span
              className={`badge mr-2 ${a.kind === 'new' ? 'bg-good/15 text-good' : 'bg-warn/15 text-warn'}`}
            >
              {a.kind}
            </span>
            <span className="text-slate-200">{a.message}</span>
            <div className="mt-0.5 text-[10px] text-muted">{new Date(a.at).toLocaleTimeString()}</div>
          </button>
        ))}
        {alerts.length === 0 && (
          <div className="py-6 text-center text-xs text-muted">
            No alerts. New devices found during a scan appear here.
          </div>
        )}
      </div>
    </div>
  );
}
