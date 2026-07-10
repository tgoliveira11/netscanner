'use client';

import { useState } from 'react';
import type { ControlVerifyResult } from '@netscanner/contracts';
import { api } from '../lib/api';
import { useBackgroundDataStore } from '../lib/background-data-store';
import { useStore } from '../lib/store';
import { LoadingSpinner } from './LoadingSpinner';

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

export function NetworkControlPanel() {
  const deviceMap = useStore((s) => s.devices);
  const devices = Object.values(deviceMap);
  const boot = useBackgroundDataStore((s) => s.controlBoot);
  const audit = useBackgroundDataStore((s) => s.controlAudit);
  const schedules = useBackgroundDataStore((s) => s.controlSchedules);
  const bootLoading = useBackgroundDataStore((s) => s.controlBootLoading);
  const auditLoading = useBackgroundDataStore((s) => s.controlAuditLoading);
  const schedulesLoading = useBackgroundDataStore((s) => s.controlSchedulesLoading);
  const error = useBackgroundDataStore((s) => s.controlError);
  const refresh = useBackgroundDataStore((s) => s.refreshControl);
  const [verify, setVerify] = useState<ControlVerifyResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [name, setName] = useState('Kids bedtime');
  const [deviceId, setDeviceId] = useState('');
  const [weekdays, setWeekdays] = useState<number[]>([0, 1, 2, 3, 4, 5, 6]);
  const [startTime, setStartTime] = useState('22:00');
  const [endTime, setEndTime] = useState('07:00');

  const runVerify = async () => {
    setBusy(true);
    try {
      setVerify(await api.controlVerify());
      await refresh({ silent: true });
      setActionError(null);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const bootstrap = async () => {
    setBusy(true);
    try {
      await api.controlBootstrapApply();
      await refresh();
      setActionError(null);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const createSchedule = async () => {
    if (!deviceId) return;
    setBusy(true);
    try {
      await api.controlParentalCreate({
        name,
        deviceIds: [deviceId],
        weekdays,
        startTime,
        endTime,
        enabled: true,
      });
      await refresh({ silent: true });
      setActionError(null);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const toggleDay = (d: number) => {
    setWeekdays((prev) => (prev.includes(d) ? prev.filter((x) => x !== d) : [...prev, d].sort()));
  };

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-slate-200">Network control (pfSense)</h2>
        <div className="flex flex-wrap gap-2">
          <button type="button" disabled={busy} onClick={() => void runVerify()} className="btn btn-ghost text-xs">
            {busy ? '…' : 'Verify rules'}
          </button>
          <button type="button" disabled={busy} onClick={() => void bootstrap()} className="btn btn-ghost text-xs">
            {busy ? '…' : boot?.ready ? 'Re-check bootstrap' : 'Bootstrap aliases'}
          </button>
        </div>
      </div>
      {(error || actionError) && <p className="text-xs text-bad">{actionError ?? error}</p>}
      {bootLoading && !boot ? (
        <LoadingSpinner label="Loading control status…" className="py-4" />
      ) : (
        boot && (
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-lg border border-edge bg-panelup px-3 py-2 text-xs">
            <div className="text-muted">Ready</div>
            <div className={boot.ready ? 'text-good' : 'text-warn'}>{boot.ready ? 'Yes' : 'No'}</div>
          </div>
          {Object.entries(boot.aliases).map(([k, v]) => (
            <div key={k} className="rounded-lg border border-edge bg-panelup px-3 py-2 text-xs">
              <div className="text-muted">{k}</div>
              <div>{v ? '✓' : '—'}</div>
            </div>
          ))}
        </div>
        )
      )}
      {boot?.message && <p className="text-xs text-muted">{boot.message}</p>}

      {verify && (
        <div className="card space-y-2 p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-semibold uppercase text-muted">Rule verification</h3>
            <span className={`text-xs font-medium ${verify.ok ? 'text-good' : 'text-bad'}`}>
              {verify.ok ? 'All critical checks passed' : 'Issues found'}
            </span>
          </div>
          <p className="text-[10px] text-muted">
            Ran {new Date(verify.ranAt).toLocaleString()} — includes alias write round-trip test
          </p>
          <ul className="max-h-56 space-y-1 overflow-auto text-xs">
            {verify.checks.map((c) => (
              <li key={c.id} className="flex gap-2 rounded border border-edge/50 bg-panelup px-2 py-1">
                <span
                  className={
                    c.status === 'pass'
                      ? 'text-good'
                      : c.status === 'warn'
                        ? 'text-warn'
                        : c.status === 'skip'
                          ? 'text-muted'
                          : 'text-bad'
                  }
                >
                  {c.status === 'pass' ? '✓' : c.status === 'warn' ? '!' : c.status === 'skip' ? '–' : '✗'}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="text-slate-200">{c.label}</span>
                  {c.detail && <span className="block text-[10px] text-muted">{c.detail}</span>}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="card space-y-2 p-4">
        <h3 className="text-xs font-semibold uppercase text-muted">Parental schedule</h3>
        <div className="grid gap-2 sm:grid-cols-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Schedule name"
            className="rounded-lg border border-edge bg-panelup px-3 py-2 text-xs"
          />
          <select
            value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}
            className="rounded-lg border border-edge bg-panelup px-3 py-2 text-xs"
          >
            <option value="">Select device…</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.label ?? d.hostname ?? d.ip}
              </option>
            ))}
          </select>
          <input
            type="time"
            value={startTime}
            onChange={(e) => setStartTime(e.target.value)}
            className="rounded-lg border border-edge bg-panelup px-3 py-2 text-xs"
          />
          <input
            type="time"
            value={endTime}
            onChange={(e) => setEndTime(e.target.value)}
            className="rounded-lg border border-edge bg-panelup px-3 py-2 text-xs"
          />
        </div>
        <div className="flex flex-wrap gap-1">
          {WEEKDAYS.map((label, i) => (
            <button
              key={label}
              type="button"
              onClick={() => toggleDay(i)}
              className={`rounded px-2 py-0.5 text-xs ${weekdays.includes(i) ? 'bg-accent/20 text-accent' : 'bg-panelup text-muted'}`}
            >
              {label}
            </button>
          ))}
        </div>
        <button type="button" disabled={busy || !deviceId} onClick={() => void createSchedule()} className="btn btn-primary text-xs">
          Create pfSense schedule
        </button>
        {schedulesLoading && schedules.length === 0 ? (
          <LoadingSpinner label="Loading schedules…" className="py-2" />
        ) : (
          schedules.length > 0 && (
          <ul className="space-y-1 text-xs text-slate-300">
            {schedules.map((s) => (
              <li key={s.id}>
                {s.name} · {s.startTime}–{s.endTime} · {s.deviceIds.length} device(s)
              </li>
            ))}
          </ul>
          )
        )}
      </div>

      {auditLoading && audit.length === 0 ? (
        <LoadingSpinner label="Loading policy audit…" className="py-4" />
      ) : (
        audit.length > 0 && (
        <div className="card p-4">
          <h3 className="mb-2 text-xs font-semibold uppercase text-muted">Policy audit</h3>
          <ul className="max-h-40 space-y-1 overflow-auto text-xs text-slate-300">
            {audit.map((e) => (
              <li key={e.id}>
                <span className="text-muted">{new Date(e.createdAt).toLocaleString()}</span> · {e.action} ·{' '}
                <span className="font-mono">{e.target}</span>
              </li>
            ))}
          </ul>
        </div>
        )
      )}
    </section>
  );
}
