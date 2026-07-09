'use client';

import { useCallback, useEffect, useState } from 'react';
import type { ControlStatus, Device } from '@netscanner/contracts';
import { api } from '../lib/api';

export function DeviceControl({ device }: { device: Device }) {
  const [status, setStatus] = useState<ControlStatus | null>(null);
  const [bootstrapReady, setBootstrapReady] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dhcpHostname, setDhcpHostname] = useState(device.hostname ?? device.label ?? '');

  const refresh = useCallback(async () => {
    try {
      const [boot, st] = await Promise.all([
        api.controlBootstrap(),
        api.controlStatus(device.id),
      ]);
      setBootstrapReady(boot.ready);
      setStatus(st);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [device.id]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  if (bootstrapReady === false) {
    return (
      <section className="mt-5 space-y-2">
        <h3 className="text-sm font-semibold text-slate-200">Network control</h3>
        <p className="text-xs text-muted">
          pfSense control not ready. Enable PFSENSE_CONTROL_ENABLED and run bootstrap in Admin.
        </p>
        <button
          type="button"
          disabled={busy}
          className="btn btn-ghost text-xs"
          onClick={() => void act(() => api.controlBootstrapApply())}
        >
          Bootstrap pfSense aliases
        </button>
        {error && <p className="text-xs text-bad">{error}</p>}
      </section>
    );
  }

  return (
    <section className="mt-5 space-y-2">
      <h3 className="text-sm font-semibold text-slate-200">Network control</h3>
      {status && (
        <div className="flex flex-wrap gap-2 text-xs">
          {status.blocked && <span className="badge bg-bad/20 text-bad">Blocked</span>}
          {status.paused && (
            <span className="badge bg-warn/20 text-warn">
              Paused{status.pauseExpiresAt ? ` until ${new Date(status.pauseExpiresAt).toLocaleTimeString()}` : ''}
            </span>
          )}
          {status.bandwidthLimited && <span className="badge bg-panelup text-slate-300">Bandwidth limited</span>}
          {!status.blocked && !status.paused && !status.bandwidthLimited && (
            <span className="text-muted">No active policies</span>
          )}
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          disabled={busy || status?.blocked}
          className="btn btn-ghost text-xs text-bad"
          onClick={() => void act(() => api.controlBlock({ deviceId: device.id }))}
        >
          Block
        </button>
        <button
          type="button"
          disabled={busy || !status?.blocked}
          className="btn btn-ghost text-xs"
          onClick={() => void act(() => api.controlUnblock({ deviceId: device.id }))}
        >
          Unblock
        </button>
        <button
          type="button"
          disabled={busy || status?.paused}
          className="btn btn-ghost text-xs text-warn"
          onClick={() =>
            void act(() => api.controlPause({ deviceId: device.id, durationMs: 3_600_000 }))
          }
        >
          Pause 1h
        </button>
      </div>
      {device.mac && (
        <div className="space-y-1 border-t border-edge pt-3">
          <div className="text-xs text-muted">DHCP static mapping</div>
          <input
            value={dhcpHostname}
            onChange={(e) => setDhcpHostname(e.target.value)}
            placeholder="Hostname"
            className="w-full rounded-lg border border-edge bg-panelup px-3 py-1.5 text-xs outline-none focus:border-accent"
          />
          <button
            type="button"
            disabled={busy}
            className="btn btn-ghost text-xs"
            onClick={() =>
              void act(() =>
                api.controlDhcpReserve({
                  mac: device.mac!,
                  ip: device.ip,
                  hostname: dhcpHostname || undefined,
                }),
              )
            }
          >
            Reserve IP
          </button>
        </div>
      )}
      {error && <p className="text-xs text-bad">{error}</p>}
    </section>
  );
}
