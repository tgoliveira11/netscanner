'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../lib/api';
import { LoadingBlock } from './LoadingSpinner';
import { useStore } from '../lib/store';

type Tab = 'traffic' | 'dns' | 'log';

interface TrafficEdge {
  from: string;
  to: string;
  kind: string;
  label: string;
  bytes?: number;
}

interface DnsRow {
  deviceId: string;
  domain: string;
  vendor?: string;
}

interface LogRow {
  at: string;
  deviceId: string;
  deviceLabel: string;
  message: string;
}

function fmtBytes(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} GB`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} MB`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(0)} KB`;
  return `${n} B`;
}

function scopeBadge(kind: string): { label: string; className: string } {
  if (kind === 'traffic-external') {
    return { label: 'WAN', className: 'bg-warn/15 text-warn' };
  }
  return { label: 'LAN', className: 'bg-accent/15 text-accent' };
}

export function RelationsPanel({ fullPage = false }: { fullPage?: boolean }) {
  const devices = useStore((s) => s.devices);
  const select = useStore((s) => s.select);
  const [tab, setTab] = useState<Tab>('traffic');
  const [search, setSearch] = useState('');
  const [scope, setScope] = useState<'all' | 'wan' | 'lan'>('all');
  const [edges, setEdges] = useState<TrafficEdge[]>([]);
  const [external, setExternal] = useState<DnsRow[]>([]);
  const [dnsLog, setDnsLog] = useState<LogRow[]>([]);
  const [loading, setLoading] = useState(false);

  const deviceIds = useMemo(() => Object.keys(devices).sort().join(','), [devices]);

  const load = useCallback(() => {
    setLoading(true);
    api
      .relations()
      .then((r) => {
        setEdges(r.edges);
        setExternal(r.externalContacts);
        setDnsLog(r.dnsLog ?? []);
      })
      .catch(() => undefined)
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 30_000);
    return () => clearInterval(timer);
  }, [load, deviceIds]);

  const labelFor = useCallback(
    (id: string) => {
      const d = devices[id];
      if (d) return d.label ?? d.hostname ?? d.ip;
      return id;
    },
    [devices],
  );

  const destFor = useCallback(
    (e: TrafficEdge) => {
      if (e.kind === 'traffic-external') return String(e.to);
      return labelFor(String(e.to));
    },
    [labelFor],
  );

  const traffic = useMemo(
    () => edges.filter((e) => e.kind.startsWith('traffic')),
    [edges],
  );

  const dnsRows = useMemo(() => {
    const map = new Map<string, DnsRow>();
    for (const e of edges) {
      if (e.kind !== 'dns') continue;
      const key = `${e.from}:${e.to}`;
      map.set(key, { deviceId: e.from, domain: String(e.to) });
    }
    for (const row of external) {
      const key = `${row.deviceId}:${row.domain}`;
      const existing = map.get(key);
      if (existing) {
        if (row.vendor) existing.vendor = row.vendor;
      } else {
        map.set(key, { ...row });
      }
    }
    return [...map.values()].sort((a, b) => {
      const da = labelFor(a.deviceId).localeCompare(labelFor(b.deviceId));
      if (da !== 0) return da;
      return a.domain.localeCompare(b.domain);
    });
  }, [edges, external, labelFor]);

  const q = search.trim().toLowerCase();
  const matches = (...parts: (string | undefined)[]) =>
    !q || parts.some((p) => p?.toLowerCase().includes(q));

  const filteredTraffic = useMemo(() => {
    return traffic.filter((e) => {
      if (scope === 'wan' && e.kind !== 'traffic-external') return false;
      if (scope === 'lan' && e.kind !== 'traffic') return false;
      return matches(labelFor(e.from), destFor(e));
    });
  }, [traffic, scope, q, labelFor, destFor]);

  const filteredDns = useMemo(
    () =>
      dnsRows.filter((r) =>
        matches(labelFor(r.deviceId), r.domain, r.vendor),
      ),
    [dnsRows, q, labelFor],
  );

  const filteredLog = useMemo(
    () =>
      dnsLog.filter((r) =>
        matches(r.deviceLabel, r.message, labelFor(r.deviceId)),
      ),
    [dnsLog, q, labelFor],
  );

  const stats = useMemo(() => {
    const wan = traffic.filter((e) => e.kind === 'traffic-external').length;
    const lan = traffic.filter((e) => e.kind === 'traffic').length;
    const bytes = traffic.reduce((s, e) => s + (e.bytes ?? 0), 0);
    return { wan, lan, bytes, dns: dnsRows.length, log: dnsLog.length };
  }, [traffic, dnsRows.length, dnsLog.length]);

  const tabs: { id: Tab; label: string; count: number }[] = [
    { id: 'traffic', label: 'Traffic', count: traffic.length },
    { id: 'dns', label: 'DNS', count: dnsRows.length },
    { id: 'log', label: 'Activity', count: dnsLog.length },
  ];

  const emptyMessage =
    tab === 'traffic'
      ? 'No traffic peers yet — waiting for pfSense state sample.'
      : tab === 'dns'
        ? 'No external DNS destinations recorded yet.'
        : 'No DNS activity logged yet.';

  return (
    <section
      className={`flex flex-col rounded-xl border border-edge bg-panel ${fullPage ? 'min-h-[calc(100vh-8rem)]' : ''}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-edge px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">Relations</h2>
          <p className="text-xs text-muted">Who talks to whom — traffic peers and DNS destinations.</p>
        </div>
        <button
          type="button"
          className="btn btn-ghost text-xs"
          onClick={load}
          disabled={loading}
        >
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-2 border-b border-edge px-4 py-2">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
              tab === t.id
                ? 'bg-accent/15 text-accent'
                : 'text-muted hover:bg-panelup hover:text-slate-200'
            }`}
          >
            {t.label}
            {t.count > 0 && (
              <span className="ml-1.5 rounded-full bg-panel px-1.5 py-0.5 text-[10px] text-muted">
                {t.count}
              </span>
            )}
          </button>
        ))}

        <div className="ml-auto flex min-w-[200px] flex-1 items-center gap-2 sm:max-w-xs">
          <input
            type="search"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter…"
            className="w-full rounded-lg border border-edge bg-panelup px-3 py-1.5 text-xs text-slate-200 placeholder:text-muted focus:border-accent focus:outline-none"
          />
        </div>
      </div>

      {tab === 'traffic' && (
        <div className="flex flex-wrap items-center gap-2 px-4 py-2 text-[11px]">
          <span className="text-muted">
            {stats.wan} WAN · {stats.lan} LAN · {fmtBytes(stats.bytes)} total
          </span>
          <span className="text-edge">|</span>
          {(['all', 'wan', 'lan'] as const).map((s) => (
            <button
              key={s}
              type="button"
              onClick={() => setScope(s)}
              className={`rounded px-2 py-0.5 uppercase tracking-wide ${
                scope === s ? 'bg-panelup text-slate-200' : 'text-muted hover:text-slate-300'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      )}

      <div className="min-h-0 flex-1 overflow-auto">
        <LoadingBlock
          loading={loading && edges.length === 0 && dnsLog.length === 0}
          label="Loading relations…"
          minHeight="12rem"
        >
        {tab === 'traffic' && filteredTraffic.length > 0 && (
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 z-10 bg-panel text-[10px] uppercase tracking-wide text-muted">
              <tr className="border-b border-edge">
                <th className="px-4 py-2 font-medium">Source</th>
                <th className="px-4 py-2 font-medium">Destination</th>
                <th className="hidden px-4 py-2 font-medium sm:table-cell">Scope</th>
                <th className="px-4 py-2 text-right font-medium">Volume</th>
              </tr>
            </thead>
            <tbody>
              {filteredTraffic.map((e, i) => {
                const badge = scopeBadge(e.kind);
                return (
                  <tr
                    key={`${e.from}-${e.to}-${i}`}
                    className="border-b border-edge/50 hover:bg-panelup/60"
                  >
                    <td className="max-w-[180px] truncate px-4 py-2">
                      <button
                        type="button"
                        className="text-left text-slate-200 hover:text-accent"
                        onClick={() => select(e.from)}
                      >
                        {labelFor(e.from)}
                      </button>
                    </td>
                    <td className="max-w-[240px] truncate px-4 py-2 font-mono text-slate-300" title={destFor(e)}>
                      {destFor(e)}
                    </td>
                    <td className="hidden px-4 py-2 sm:table-cell">
                      <span className={`badge ${badge.className}`}>{badge.label}</span>
                    </td>
                    <td className="whitespace-nowrap px-4 py-2 text-right tabular-nums text-muted">
                      {e.bytes != null ? fmtBytes(e.bytes) : '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}

        {tab === 'dns' && filteredDns.length > 0 && (
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 z-10 bg-panel text-[10px] uppercase tracking-wide text-muted">
              <tr className="border-b border-edge">
                <th className="px-4 py-2 font-medium">Device</th>
                <th className="px-4 py-2 font-medium">Domain</th>
                <th className="hidden px-4 py-2 font-medium md:table-cell">Vendor</th>
              </tr>
            </thead>
            <tbody>
              {filteredDns.map((row) => (
                <tr
                  key={`${row.deviceId}-${row.domain}`}
                  className="border-b border-edge/50 hover:bg-panelup/60"
                >
                  <td className="max-w-[160px] truncate px-4 py-2">
                    <button
                      type="button"
                      className="text-left text-slate-200 hover:text-accent"
                      onClick={() => select(row.deviceId)}
                    >
                      {labelFor(row.deviceId)}
                    </button>
                  </td>
                  <td className="max-w-[320px] truncate px-4 py-2 font-mono text-slate-300" title={row.domain}>
                    {row.domain}
                  </td>
                  <td className="hidden max-w-[140px] truncate px-4 py-2 text-muted md:table-cell">
                    {row.vendor ?? '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {tab === 'log' && filteredLog.length > 0 && (
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 z-10 bg-panel text-[10px] uppercase tracking-wide text-muted">
              <tr className="border-b border-edge">
                <th className="whitespace-nowrap px-4 py-2 font-medium">Time</th>
                <th className="px-4 py-2 font-medium">Device</th>
                <th className="px-4 py-2 font-medium">Event</th>
              </tr>
            </thead>
            <tbody>
              {[...filteredLog].reverse().map((row, i) => (
                <tr
                  key={`${row.at}-${row.deviceId}-${i}`}
                  className="border-b border-edge/50 hover:bg-panelup/60"
                >
                  <td className="whitespace-nowrap px-4 py-2 tabular-nums text-muted">
                    {new Date(row.at).toLocaleString(undefined, {
                      month: 'short',
                      day: 'numeric',
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                    })}
                  </td>
                  <td className="max-w-[140px] truncate px-4 py-2">
                    <button
                      type="button"
                      className="text-left text-slate-200 hover:text-accent"
                      onClick={() => select(row.deviceId)}
                    >
                      {row.deviceLabel}
                    </button>
                  </td>
                  <td className="px-4 py-2 text-slate-300">{row.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {((tab === 'traffic' && filteredTraffic.length === 0) ||
          (tab === 'dns' && filteredDns.length === 0) ||
          (tab === 'log' && filteredLog.length === 0)) && (
          <p className="px-4 py-12 text-center text-sm text-muted">
            {q ? 'No matches for this filter.' : emptyMessage}
          </p>
        )}
        </LoadingBlock>
      </div>
    </section>
  );
}
