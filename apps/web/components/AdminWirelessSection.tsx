'use client';

import { useBackgroundDataStore } from '../lib/background-data-store';
import { LoadingBlock } from './LoadingSpinner';

export function AdminWirelessSection() {
  const wireless = useBackgroundDataStore((s) => s.wireless);
  const loading = useBackgroundDataStore((s) => s.wirelessLoading);
  const refreshing = useBackgroundDataStore((s) => s.wirelessRefreshing);
  const refresh = useBackgroundDataStore((s) => s.refreshWireless);

  return (
    <section className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-semibold text-slate-200">WiFi / SSIDs (OpenWrt only)</h2>
        <button
          type="button"
          onClick={() => void refresh()}
          disabled={refreshing}
          className="btn btn-ghost text-xs"
        >
          {refreshing ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>
      <LoadingBlock loading={loading && !wireless} label="Loading wireless…">
        {!wireless?.configured && (
          <p className="text-xs text-muted">
            Configure ROUTER_SCRAPE_TARGETS with kind=openwrt. Compal APs are on the Integrations tab.
          </p>
        )}
        {wireless?.configured && (
          <div className="grid gap-3 md:grid-cols-2">
            {wireless.routers.map((r) => (
              <div key={r.url} className="rounded-lg border border-edge bg-panelup p-3">
                <div className="text-sm font-medium text-slate-200">{r.host}</div>
                <div className="text-xs text-muted">{r.url}</div>
                {!r.ok && <div className="mt-1 text-xs text-bad">{r.error ?? 'probe failed'}</div>}
                {r.ok && r.ssids.length === 0 && (
                  <div className="mt-1 text-xs text-muted">No WiFi radios / SSIDs (switch or WiFi disabled)</div>
                )}
                {r.ok && r.ssids.length > 0 && (
                  <ul className="mt-2 space-y-1 text-xs text-slate-300">
                    {r.ssids.map((s) => (
                      <li key={`${s.device}-${s.ifname}`}>
                        <span className={s.up ? 'text-good' : 'text-muted'}>{s.up ? '●' : '○'}</span>{' '}
                        <span className="font-medium">{s.ssid || '(hidden)'}</span>
                        <span className="text-muted">
                          {' '}
                          · {s.device} ch={s.channel ?? '—'} {s.mode ?? ''}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
        )}
      </LoadingBlock>
    </section>
  );
}
