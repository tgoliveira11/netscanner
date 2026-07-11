'use client';

import { useCallback, useEffect, useState } from 'react';
import type { CpeAccessListResponse, CpeAccessSession } from '@netscanner/contracts';
import { api, apiBase } from '../lib/api';

const emptyForm = {
  ip: '',
  username: '',
  password: '',
  label: '',
  port: '',
  tls: false,
};

export function CpeAccessPanel() {
  const [list, setList] = useState<CpeAccessListResponse | null>(null);
  const [form, setForm] = useState(emptyForm);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hint, setHint] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await api.adminCpeList();
      setList(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 5_000);
    return () => clearInterval(t);
  }, [refresh]);

  const openSession = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setHint(null);
    try {
      const portNum = form.port.trim() ? Number(form.port) : undefined;
      const result = await api.adminCpeOpen({
        ip: form.ip.trim(),
        username: form.username.trim(),
        password: form.password,
        label: form.label.trim() || undefined,
        port: portNum && Number.isFinite(portNum) ? portNum : undefined,
        tls: form.tls || undefined,
      });
      if (!result.ok || !result.session) {
        setError(result.error ?? 'Failed to open tunnel');
        setHint(result.hint ?? null);
        return;
      }
      setHint(result.hint ?? 'Tunnel open — opening UI with auto-login.');
      setForm(emptyForm);
      await refresh();
      window.open(`${apiBase()}${result.session.proxyPath}`, '_blank', 'noopener,noreferrer');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const closeSession = async (id: string) => {
    setBusy(true);
    setError(null);
    try {
      await api.adminCpeClose(id);
      setHint('Tunnel closed.');
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const openCount = list?.sessions.length ?? 0;

  return (
    <section className="mt-6 space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">Router / modem tunnel</h2>
          <p className="text-xs text-muted">
            IP + login + password → open a tunnel (persisted until Close tunnel) and auto-sign-in
            on the router UI. Direct when reachable; otherwise SSH via pfSense.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`badge ${
              openCount > 0 ? 'bg-good/20 text-good' : 'bg-panel text-muted'
            }`}
          >
            {openCount > 0 ? `${openCount} tunnel${openCount === 1 ? '' : 's'} open` : 'no tunnel open'}
          </span>
          <button
            type="button"
            onClick={() => void refresh()}
            className="btn btn-ghost text-xs"
            disabled={busy}
          >
            Refresh
          </button>
        </div>
      </div>

      {list && (
        <p className="text-xs text-muted">
          pfSense SSH tunnel helper:{' '}
          <span className={list.pfsenseTunnelAvailable ? 'text-good' : 'text-warn'}>
            {list.pfsenseTunnelAvailable ? 'ready' : 'not configured'}
          </span>
          {!list.pfsenseTunnelAvailable && ' — set PFSENSE_URL + PFSENSE_SSH_PASSWORD for WAN CPE'}
        </p>
      )}

      <form onSubmit={(e) => void openSession(e)} className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        <label className="space-y-1 text-xs">
          <span className="text-muted">IP</span>
          <input
            required
            className="w-full rounded-lg border border-edge bg-panelup px-3 py-2 text-xs"
            placeholder="192.168.0.1"
            value={form.ip}
            onChange={(ev) => setForm((f) => ({ ...f, ip: ev.target.value }))}
            autoComplete="off"
          />
        </label>
        <label className="space-y-1 text-xs">
          <span className="text-muted">Login</span>
          <input
            required
            className="w-full rounded-lg border border-edge bg-panelup px-3 py-2 text-xs"
            value={form.username}
            onChange={(ev) => setForm((f) => ({ ...f, username: ev.target.value }))}
            autoComplete="username"
          />
        </label>
        <label className="space-y-1 text-xs">
          <span className="text-muted">Password</span>
          <input
            required
            type="password"
            className="w-full rounded-lg border border-edge bg-panelup px-3 py-2 text-xs"
            value={form.password}
            onChange={(ev) => setForm((f) => ({ ...f, password: ev.target.value }))}
            autoComplete="current-password"
          />
        </label>
        <label className="space-y-1 text-xs">
          <span className="text-muted">Label (optional)</span>
          <input
            className="w-full rounded-lg border border-edge bg-panelup px-3 py-2 text-xs"
            placeholder="Claro modem"
            value={form.label}
            onChange={(ev) => setForm((f) => ({ ...f, label: ev.target.value }))}
          />
        </label>
        <label className="space-y-1 text-xs">
          <span className="text-muted">Port (optional)</span>
          <input
            className="w-full rounded-lg border border-edge bg-panelup px-3 py-2 text-xs"
            placeholder={form.tls ? '443' : '80'}
            value={form.port}
            onChange={(ev) => setForm((f) => ({ ...f, port: ev.target.value }))}
          />
        </label>
        <label className="flex items-end gap-2 pb-2 text-xs text-slate-300">
          <input
            type="checkbox"
            checked={form.tls}
            onChange={(ev) => setForm((f) => ({ ...f, tls: ev.target.checked }))}
          />
          HTTPS / TLS
        </label>
        <div className="sm:col-span-2 lg:col-span-3">
          <button type="submit" className="btn btn-primary text-xs" disabled={busy}>
            {busy ? 'Opening tunnel…' : 'Open tunnel'}
          </button>
        </div>
      </form>

      {error && <p className="text-xs text-bad">{error}</p>}
      {hint && <p className="text-xs text-muted">{hint}</p>}

      <div className="space-y-2">
        <h3 className="text-xs font-medium text-slate-300">Active tunnels</h3>
        {openCount === 0 ? (
          <p className="rounded-lg border border-dashed border-edge px-3 py-3 text-xs text-muted">
            No tunnel open. Fill IP / login / password above and click <span className="text-slate-300">Open tunnel</span>.
          </p>
        ) : (
          <ul className="space-y-2">
            {list!.sessions.map((s) => (
              <SessionRow
                key={s.id}
                session={s}
                busy={busy}
                onClose={() => void closeSession(s.id)}
              />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

function SessionRow({
  session,
  busy,
  onClose,
}: {
  session: CpeAccessSession;
  busy: boolean;
  onClose: () => void;
}) {
  const openHref = `${apiBase()}${session.proxyPath}`;
  const viaLabel = session.via === 'pfsense-tunnel' ? 'via pfSense SSH' : 'direct';

  async function openUi() {
    try {
      await api.adminCpeRearmLogin(session.id);
    } catch {
      /* still open UI even if rearm fails */
    }
    window.open(openHref, '_blank', 'noopener,noreferrer');
  }

  return (
    <li className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-edge bg-panelup px-3 py-2 text-xs">
      <div>
        <div className="flex flex-wrap items-center gap-2 font-medium text-slate-200">
          <span className="badge bg-good/20 text-good">open</span>
          <span>{session.label ?? session.ip}</span>
          <span className="font-normal text-muted">
            {session.ip}:{session.port} · {viaLabel} · login {session.username}
          </span>
        </div>
        <div className="mt-0.5 text-muted">
          persisted · closes only when you click Close tunnel
          {session.createdAt ? ` · opened ${new Date(session.createdAt).toLocaleString()}` : ''}
        </div>
      </div>
      <div className="flex gap-2">
        <button type="button" className="btn btn-ghost text-xs" disabled={busy} onClick={() => void openUi()}>
          Open UI
        </button>
        <button type="button" className="btn btn-ghost text-xs text-bad" disabled={busy} onClick={onClose}>
          Close tunnel
        </button>
      </div>
    </li>
  );
}
