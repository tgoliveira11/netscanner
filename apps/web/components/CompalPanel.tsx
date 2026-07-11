'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import type { CompalAdminDevice, CompalStep, CompalStreamEvent } from '@netscanner/contracts';
import { api, apiBase } from '../lib/api';
import { useBackgroundDataStore, compalDeviceNeedsWatch } from '../lib/background-data-store';
import { LoadingSpinner } from './LoadingSpinner';

type Activity = {
  id: string;
  host: string;
  url: string;
  action: string;
  steps: CompalStep[];
  running: boolean;
  ok: boolean | null;
};

function stepTone(level: CompalStep['level']): string {
  switch (level) {
    case 'success':
      return 'text-good';
    case 'warn':
      return 'text-warn';
    case 'error':
      return 'text-bad';
    default:
      return 'text-slate-300';
  }
}

function stepIcon(level: CompalStep['level'], running: boolean, isLast: boolean): string {
  if (running && isLast) return '◌';
  switch (level) {
    case 'success':
      return '✓';
    case 'error':
      return '✕';
    case 'warn':
      return '!';
    default:
      return '·';
  }
}

export function CompalPanel() {
  const data = useBackgroundDataStore((s) => s.compal);
  const loading = useBackgroundDataStore((s) => s.compalLoading);
  const refreshing = useBackgroundDataStore((s) => s.compalRefreshing);
  const error = useBackgroundDataStore((s) => s.compalError);
  const autoPolling = useBackgroundDataStore((s) => s.compalAutoPolling);
  const refresh = useBackgroundDataStore((s) => s.refreshCompal);
  const watchDevice = useBackgroundDataStore((s) => s.watchCompalDevice);
  const [busyUrl, setBusyUrl] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [activity, setActivity] = useState<Activity | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [activity?.steps.length]);

  const pushStep = useCallback((step: CompalStep) => {
    setActivity((prev) => (prev ? { ...prev, steps: [...prev.steps, step] } : prev));
  }, []);

  const runAction = async (
    host: string,
    url: string,
    action: string,
    run: (onEvent: (event: CompalStreamEvent) => void) => Promise<unknown>,
  ) => {
    setBusyUrl(url);
    setActionError(null);
    setActivity({
      id: `${Date.now()}`,
      host,
      url,
      action,
      steps: [{ level: 'info', message: `Starting: ${action}`, at: new Date().toISOString() }],
      running: true,
      ok: null,
    });
    try {
      await run((event) => {
        if (event.type === 'step') pushStep(event);
        if (event.type === 'done') {
          pushStep({
            level: event.ok ? 'success' : 'error',
            message: event.message ?? (event.ok ? 'Done' : 'Failed'),
            at: new Date().toISOString(),
          });
          setActivity((prev) =>
            prev ? { ...prev, running: false, ok: event.ok } : prev,
          );
        }
      });
      watchDevice(url);
      await refresh();
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      pushStep({ level: 'error', message: msg, at: new Date().toISOString() });
      setActivity((prev) => (prev ? { ...prev, running: false, ok: false } : prev));
      setActionError(msg);
    } finally {
      setBusyUrl(null);
    }
  };

  const setMesh = (host: string, baseUrl: string, enabled: boolean) =>
    void runAction(host, baseUrl, enabled ? 'Enable mesh' : 'Disable mesh', (onEvent) =>
      api.adminCompalMesh(baseUrl, enabled, onEvent),
    );

  const reboot = (host: string, baseUrl: string) => {
    if (!window.confirm(`Reboot ${host}? Wi‑Fi will be offline for ~1–2 min.`)) return;
    void runAction(host, baseUrl, 'Reboot', (onEvent) => api.adminCompalReboot(baseUrl, onEvent));
  };

  if (loading && !data) {
    return (
      <section className="space-y-2">
        <h2 className="text-sm font-semibold text-slate-200">Compal APs</h2>
        <LoadingSpinner label="Loading Compal…" />
      </section>
    );
  }

  if (!data?.configured) {
    return (
      <section className="space-y-2">
        <h2 className="text-sm font-semibold text-slate-200">Compal APs</h2>
        <p className="text-xs text-muted">
          Add Compal targets to ROUTER_SCRAPE_TARGETS (kind=compal) to manage mesh and reboot from here.
        </p>
      </section>
    );
  }

  return (
    <>
      <section className="space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">Compal APs</h2>
            <p className="text-xs text-muted">Mesh, per-radio SSIDs, reboot, and uptime (LuCI Compal/CBN).</p>
          </div>
          <button
            type="button"
            onClick={() => void refresh()}
            disabled={refreshing}
            className="btn btn-ghost text-xs"
          >
            {refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
        {autoPolling && (
          <p className="text-xs text-muted">
            Watching after an action or a slow offline recovery check — idle once all APs stay online.
          </p>
        )}
        {(error || actionError) && !activity?.running && (
          <p className="text-xs text-bad">{actionError ?? error}</p>
        )}
        <div className="grid gap-3 md:grid-cols-2">
          {data.devices.map((d) => {
            const busy = busyUrl === d.url;
            const pollingThis = autoPolling && compalDeviceNeedsWatch(d);
            return (
              <div key={d.url} className="rounded-lg border border-edge bg-panelup p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div>
                    <div className="text-sm font-medium text-slate-200">{d.host}</div>
                    <div className="text-xs text-muted">{d.url}</div>
                  </div>
                  <span
                    className={`badge ${
                      !d.ok
                        ? 'bg-bad/20 text-bad'
                        : d.meshEnabled == null
                          ? 'bg-panel text-muted'
                          : d.meshEnabled
                            ? 'bg-warn/20 text-warn'
                            : 'bg-good/20 text-good'
                    }`}
                  >
                    {!d.ok ? 'offline' : d.meshEnabled == null ? 'mesh unknown' : d.meshEnabled ? 'mesh on' : 'mesh off'}
                  </span>
                </div>
                {d.ok && d.uptimeLabel && (
                  <p className="mt-1 text-xs text-slate-300">
                    Up for <span className="font-medium text-slate-100">{d.uptimeLabel}</span>
                    {d.localtime ? <span className="text-muted"> · AP clock: {d.localtime}</span> : null}
                  </p>
                )}
                {!d.ok && (
                  <p className="mt-1 text-xs text-bad">
                    {d.error ?? 'unreachable'}
                    {autoPolling ? ' — reconnecting…' : ''}
                  </p>
                )}
                {d.ok && d.meshEnabled == null && (
                  <p className="mt-1 text-xs text-muted">
                    Mesh unavailable on this AP
                    {pollingThis ? ' — waiting after action…' : ' — try Refresh if you expect it.'}
                  </p>
                )}
                {d.ok && d.ssidRows.length > 0 && (
                  <ul className="mt-2 space-y-1 text-xs text-slate-300">
                    {d.ssidRows.map((s) => (
                      <li key={`${s.device}-${s.ifname}-${s.ssid}`}>
                        <span className={s.up && !s.disabled ? 'text-good' : 'text-muted'}>
                          {s.up && !s.disabled ? '●' : '○'}
                        </span>{' '}
                        <span className="font-medium">{s.ssid || '(hidden)'}</span>
                        <span className="text-muted">
                          {' '}
                          · {s.device} ch={s.channel ?? '—'} {s.mode ?? ''}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
                {d.ok && d.ssidRows.length === 0 && d.ssids.length > 0 && (
                  <ul className="mt-2 space-y-1 text-xs text-slate-300">
                    {d.ssids.map((ssid) => (
                      <li key={ssid}>
                        <span className="text-muted">○</span> <span className="font-medium">{ssid}</span>
                      </li>
                    ))}
                  </ul>
                )}
                {d.ok && d.ssidRows.length === 0 && d.ssids.length === 0 && (
                  <p className="mt-2 text-xs text-muted">No active SSIDs detected.</p>
                )}
                <div className="mt-3 flex flex-wrap gap-2">
                  <a
                    href={`${apiBase()}/api/admin/compal/open-ui?baseUrl=${encodeURIComponent(d.url)}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn btn-ghost text-xs"
                    title="Open LuCI on the AP (same network SSO, no proxy)"
                  >
                    Open UI
                  </a>
                  <button
                    type="button"
                    disabled={!d.ok || busy}
                    onClick={() => setMesh(d.host, d.url, false)}
                    className="btn btn-ghost text-xs"
                  >
                    {busy ? '…' : 'Disable mesh'}
                  </button>
                  <button
                    type="button"
                    disabled={!d.ok || busy}
                    onClick={() => setMesh(d.host, d.url, true)}
                    className="btn btn-ghost text-xs"
                  >
                    Enable mesh
                  </button>
                  <button
                    type="button"
                    disabled={!d.ok || busy}
                    onClick={() => reboot(d.host, d.url)}
                    className="btn btn-ghost text-xs text-warn"
                  >
                    Reboot
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {activity && (
        <div className="fixed inset-x-4 bottom-4 z-50 mx-auto max-w-2xl rounded-xl border border-edge bg-panel shadow-2xl md:inset-x-auto md:right-6 md:left-auto">
          <div className="flex items-center justify-between gap-2 border-b border-edge px-4 py-3">
            <div>
              <div className="text-sm font-semibold text-slate-100">{activity.action}</div>
              <div className="text-xs text-muted">
                {activity.host} · {activity.running ? 'running…' : activity.ok ? 'done' : 'failed'}
              </div>
            </div>
            {!activity.running && (
              <button
                type="button"
                className="btn btn-ghost text-xs"
                onClick={() => setActivity(null)}
              >
                Close
              </button>
            )}
          </div>
          <div ref={logRef} className="max-h-64 overflow-y-auto px-4 py-3 font-mono text-xs">
            {activity.steps.map((s, i) => {
              const isLast = i === activity.steps.length - 1;
              return (
                <div key={`${s.at}-${i}`} className={`flex gap-2 py-0.5 ${stepTone(s.level)}`}>
                  <span className="w-4 shrink-0 text-center opacity-70">
                    {stepIcon(s.level, activity.running, isLast)}
                  </span>
                  <span className="shrink-0 text-muted">
                    {new Date(s.at).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                  </span>
                  <span>{s.message}</span>
                </div>
              );
            })}
            {activity.running && (
              <div className="mt-2 flex items-center gap-2 text-muted">
                <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-warn" />
                Aguardando resposta do AP…
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
