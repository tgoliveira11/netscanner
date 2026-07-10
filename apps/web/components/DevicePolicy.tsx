'use client';

import { useCallback, useEffect, useState } from 'react';
import type { ControlStatus, Device, PolicyAuditEntry, RouteOption } from '@netscanner/contracts';
import { api } from '../lib/api';

type PolicyTab = 'internet' | 'domains' | 'destinations' | 'route' | 'audit';

const TABS: { id: PolicyTab; label: string }[] = [
  { id: 'internet', label: 'Internet' },
  { id: 'domains', label: 'Domains' },
  { id: 'destinations', label: 'Destinations' },
  { id: 'route', label: 'Route' },
  { id: 'audit', label: 'Audit' },
];

function kindBadge(kind: RouteOption['kind']): string {
  if (kind === 'wan') return 'WAN';
  if (kind === 'lb') return 'LB';
  if (kind === 'vpn') return 'VPN';
  if (kind === 'group') return 'Group';
  return 'Other';
}

export function DevicePolicy({ device }: { device: Device }) {
  const [tab, setTab] = useState<PolicyTab>('internet');
  const [status, setStatus] = useState<ControlStatus | null>(null);
  const [bootstrapReady, setBootstrapReady] = useState<boolean | null>(null);
  const [audit, setAudit] = useState<PolicyAuditEntry[]>([]);
  const [routeOptions, setRouteOptions] = useState<RouteOption[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [domainInput, setDomainInput] = useState('');
  const [destInput, setDestInput] = useState('');

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

  const loadAudit = useCallback(async () => {
    try {
      const { entries } = await api.controlAudit(50);
      setAudit(entries.filter((e) => e.detail?.deviceId === device.id || e.target === device.ip));
    } catch {
      setAudit([]);
    }
  }, [device.id, device.ip]);

  const loadRouteOptions = useCallback(async () => {
    try {
      const { options } = await api.controlRouteOptions();
      setRouteOptions(options);
    } catch {
      setRouteOptions([]);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (tab === 'audit') void loadAudit();
    if (tab === 'route') void loadRouteOptions();
  }, [tab, loadAudit, loadRouteOptions]);

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await refresh();
      if (tab === 'audit') await loadAudit();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const dnsQueries = (device.signals?.dnsProfile as { queries?: string[] } | undefined)?.queries ?? [];
  const trafficPeers = (device.signals?.traffic as { peers?: string[] } | undefined)?.peers ?? [];

  if (bootstrapReady === false) {
    return (
      <section className="mt-5 space-y-2">
        <h3 className="text-sm font-semibold text-slate-200">Policy</h3>
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
    <section className="mt-5 space-y-3">
      <h3 className="text-sm font-semibold text-slate-200">Policy</h3>

      <div className="flex flex-wrap gap-1 border-b border-edge pb-2">
        {TABS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`rounded px-2 py-1 text-xs ${
              tab === t.id ? 'bg-accent/20 text-accent' : 'text-muted hover:text-slate-200'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {status && tab === 'internet' && (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-2 text-xs">
            {status.blocked && <span className="badge bg-bad/20 text-bad">Blocked</span>}
            {status.paused && (
              <span className="badge bg-warn/20 text-warn">
                Paused{status.pauseExpiresAt ? ` until ${new Date(status.pauseExpiresAt).toLocaleTimeString()}` : ''}
              </span>
            )}
            {status.bandwidthLimited && <span className="badge bg-panelup text-slate-300">Bandwidth limited</span>}
            {!status.blocked && !status.paused && !status.bandwidthLimited && (
              <span className="text-muted">No active internet policies</span>
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              disabled={busy || status.blocked}
              className="btn btn-ghost text-xs text-bad"
              onClick={() => void act(() => api.controlBlock({ deviceId: device.id }))}
            >
              Block internet
            </button>
            <button
              type="button"
              disabled={busy || !status.blocked}
              className="btn btn-ghost text-xs"
              onClick={() => void act(() => api.controlUnblock({ deviceId: device.id }))}
            >
              Unblock
            </button>
            <button
              type="button"
              disabled={busy || status.paused}
              className="btn btn-ghost text-xs text-warn"
              onClick={() => void act(() => api.controlPause({ deviceId: device.id, durationMs: 3_600_000 }))}
            >
              Pause 1h
            </button>
          </div>
        </div>
      )}

      {status && tab === 'domains' && (
        <div className="space-y-2 text-xs">
          <p className="text-muted">
            Blocks resolved IPs for listed FQDNs via pfSense URL alias (NS_DNS_BLOCK). CDN-heavy sites may leak —
            see docs.
          </p>
          {status.dnsBlockedDomains.length > 0 ? (
            <ul className="space-y-1">
              {status.dnsBlockedDomains.map((d) => (
                <li key={d} className="flex items-center justify-between rounded border border-edge bg-panelup px-2 py-1">
                  <span className="text-slate-200">{d}</span>
                  <button
                    type="button"
                    disabled={busy}
                    className="text-bad hover:underline"
                    onClick={() => void act(() => api.controlDnsUnblock({ deviceId: device.id, domain: d }))}
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-muted">No blocked domains for this device.</p>
          )}
          <div className="flex flex-wrap gap-2">
            <input
              value={domainInput}
              onChange={(e) => setDomainInput(e.target.value)}
              placeholder="youtube.com"
              className="min-w-[10rem] flex-1 rounded border border-edge bg-panel px-2 py-1 text-slate-100"
            />
            <button
              type="button"
              disabled={busy || !domainInput.trim()}
              className="btn btn-ghost text-xs"
              onClick={() =>
                void act(async () => {
                  await api.controlDnsBlock({ deviceId: device.id, domain: domainInput.trim() });
                  setDomainInput('');
                })
              }
            >
              Block domain
            </button>
          </div>
          {dnsQueries.length > 0 && (
            <div>
              <div className="mb-1 text-muted">Quick add from DNS profile:</div>
              <div className="flex flex-wrap gap-1">
                {dnsQueries.slice(0, 8).map((q) => (
                  <button
                    key={q}
                    type="button"
                    disabled={busy}
                    className="rounded border border-edge px-2 py-0.5 text-[10px] hover:bg-panelup"
                    onClick={() => void act(() => api.controlDnsBlock({ deviceId: device.id, domain: q }))}
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {status && tab === 'destinations' && (
        <div className="space-y-2 text-xs">
          <p className="text-muted">Block traffic to IP/CIDR (optional :port in entry; rule may need manual port on pfSense).</p>
          {status.destBlockedEntries.length > 0 ? (
            <ul className="space-y-1">
              {status.destBlockedEntries.map((d) => (
                <li key={d} className="flex items-center justify-between rounded border border-edge bg-panelup px-2 py-1">
                  <span className="font-mono text-slate-200">{d}</span>
                  <button
                    type="button"
                    disabled={busy}
                    className="text-bad hover:underline"
                    onClick={() => void act(() => api.controlDestUnblock({ deviceId: device.id, destination: d }))}
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-muted">No blocked destinations.</p>
          )}
          <div className="flex flex-wrap gap-2">
            <input
              value={destInput}
              onChange={(e) => setDestInput(e.target.value)}
              placeholder="1.2.3.4 or 10.0.0.0/8:443"
              className="min-w-[12rem] flex-1 rounded border border-edge bg-panel px-2 py-1 font-mono text-slate-100"
            />
            <button
              type="button"
              disabled={busy || !destInput.trim()}
              className="btn btn-ghost text-xs"
              onClick={() =>
                void act(async () => {
                  await api.controlDestBlock({ deviceId: device.id, destination: destInput.trim() });
                  setDestInput('');
                })
              }
            >
              Block destination
            </button>
          </div>
          {trafficPeers.length > 0 && (
            <div>
              <div className="mb-1 text-muted">From traffic peers:</div>
              <div className="flex flex-wrap gap-1">
                {trafficPeers.slice(0, 6).map((p) => (
                  <button
                    key={p}
                    type="button"
                    disabled={busy}
                    className="rounded border border-edge px-2 py-0.5 font-mono text-[10px] hover:bg-panelup"
                    onClick={() => void act(() => api.controlDestBlock({ deviceId: device.id, destination: p }))}
                  >
                    {p}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {status && tab === 'route' && (
        <div className="space-y-2 text-xs">
          <p className="text-muted">
            Policy routing: NetScanner creates a floating pass rule + alias (NS_RT_*) on pfSense with the Gateway
            column set. Survives agent restarts.
          </p>
          <p className="text-slate-300">
            Current:{' '}
            {status.egressGateway ? (
              <>
                <span className="font-mono">{status.egressGateway}</span>
                {status.egressRoute ? ` (${status.egressRoute})` : ''}
              </>
            ) : (
              'Default (pfSense policy)'
            )}
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <select
              className="min-w-[14rem] flex-1 rounded border border-edge bg-panel px-2 py-1.5 text-slate-100"
              value={status.egressGateway ?? ''}
              disabled={busy}
              onChange={(e) => {
                const v = e.target.value;
                void act(() =>
                  api.controlRoute({
                    deviceId: device.id,
                    gatewayName: v === '' ? null : v,
                  }),
                );
              }}
            >
              <option value="">Default (no override)</option>
              {routeOptions.map((o) => (
                <option key={o.name} value={o.name}>
                  [{kindBadge(o.kind)}] {o.label}
                  {o.online === false ? ' (down)' : o.online ? ' (up)' : ''}
                </option>
              ))}
            </select>
            <button
              type="button"
              disabled={busy || !status.egressGateway}
              className="btn btn-ghost text-xs"
              onClick={() => void act(() => api.controlRoute({ deviceId: device.id, gatewayName: null }))}
            >
              Clear
            </button>
          </div>
          {routeOptions.length === 0 && (
            <p className="text-muted">No gateways from telemetry yet — open Admin → Network or wait for pfSense refresh.</p>
          )}
        </div>
      )}

      {tab === 'audit' && (
        <div className="max-h-48 overflow-auto text-xs">
          {audit.length === 0 ? (
            <p className="text-muted">No policy actions for this device.</p>
          ) : (
            <ul className="space-y-1">
              {audit.map((e) => (
                <li key={e.id} className="rounded border border-edge/50 bg-panelup px-2 py-1">
                  <span className="text-slate-300">{e.action}</span>
                  <span className="text-muted"> · {new Date(e.createdAt).toLocaleString()}</span>
                  {e.detail?.domain ? <span className="text-muted"> · {String(e.detail.domain)}</span> : null}
                  {e.detail?.destination ? <span className="text-muted"> · {String(e.detail.destination)}</span> : null}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {error && <p className="text-xs text-bad">{error}</p>}
    </section>
  );
}
