'use client';

import { useCallback, useEffect, useState } from 'react';
import { api, type ActiveSiteResponse, type NetworkSite } from '../lib/api';

export function SiteSwitcher() {
  const [sites, setSites] = useState<NetworkSite[]>([]);
  const [active, setActive] = useState<ActiveSiteResponse | null>(null);
  const [editing, setEditing] = useState(false);
  const [nameDraft, setNameDraft] = useState('');
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const [siteList, activeState] = await Promise.all([api.listSites(), api.activeSite()]);
    setSites(siteList);
    setActive(activeState);
    if (activeState.site) setNameDraft(activeState.site.name);
  }, []);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 30_000);
    return () => clearInterval(t);
  }, [load]);

  const lock = async (siteId: string | null) => {
    setBusy(true);
    try {
      setActive(await api.lockSite(siteId));
      await load();
    } finally {
      setBusy(false);
    }
  };

  const confirm = async (siteId: string) => {
    setBusy(true);
    try {
      setActive(await api.confirmSite(siteId));
      await load();
    } finally {
      setBusy(false);
    }
  };

  const saveName = async () => {
    if (!active?.site) return;
    setBusy(true);
    try {
      await api.updateSite(active.site.id, { name: nameDraft.trim() || active.site.name });
      setEditing(false);
      await load();
    } finally {
      setBusy(false);
    }
  };

  const siteLabel = active?.site?.name ?? 'Unknown network';

  return (
    <div className="flex flex-col gap-2 rounded-lg border border-edge bg-panel/80 px-3 py-2 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-muted">Site</span>
        {editing ? (
          <>
            <input
              className="rounded border border-edge bg-panelup px-2 py-0.5 text-slate-100"
              value={nameDraft}
              onChange={(e) => setNameDraft(e.target.value)}
            />
            <button type="button" className="btn btn-ghost text-[10px]" disabled={busy} onClick={() => void saveName()}>
              Save
            </button>
            <button type="button" className="btn btn-ghost text-[10px]" onClick={() => setEditing(false)}>
              Cancel
            </button>
          </>
        ) : (
          <>
            <select
              className="max-w-[12rem] rounded border border-edge bg-panelup px-2 py-0.5 text-slate-100"
              value={active?.locked ? active.site?.id ?? '' : ''}
              disabled={busy}
              onChange={(e) => {
                const v = e.target.value;
                void lock(v || null);
              }}
            >
              <option value="">Auto: {siteLabel}</option>
              {sites.map((s) => (
                <option key={s.id} value={s.id}>
                  Lock: {s.name}
                </option>
              ))}
            </select>
            {active?.site && (
              <button type="button" className="btn btn-ghost text-[10px]" onClick={() => setEditing(true)}>
                Rename
              </button>
            )}
          </>
        )}
        {active?.vpnDetected && (
          <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] text-amber-300" title="Geo ignored for matching">
            VPN
          </span>
        )}
        {active?.locked && (
          <span className="rounded bg-accent/15 px-1.5 py-0.5 text-[10px] text-accent">Locked</span>
        )}
      </div>

      {active?.action === 'confirm' && active.candidates.length > 0 && (
        <div className="space-y-1 rounded border border-amber-500/30 bg-amber-500/5 p-2">
          <p className="text-[10px] text-amber-200">Which network is this? Scans are paused until you choose.</p>
          <div className="flex flex-wrap gap-1">
            {active.candidates.map((c) => (
              <button
                key={c.site.id}
                type="button"
                disabled={busy}
                className="rounded border border-edge px-2 py-0.5 hover:bg-panelup"
                onClick={() => void confirm(c.site.id)}
              >
                {c.site.name} ({Math.round(c.score * 100)}%)
              </button>
            ))}
            {active.site && (
              <button
                type="button"
                disabled={busy}
                className="rounded border border-accent/40 px-2 py-0.5 text-accent"
                onClick={() => void confirm(active.site!.id)}
              >
                Use {active.site.name}
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
