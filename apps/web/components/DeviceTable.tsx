'use client';

import { useMemo, useState } from 'react';
import { useStore } from '../lib/store';
import { confidenceColor, connectionGlyph, deviceMeta } from '../lib/device-ui';

/** Sortable/filterable inventory table; a row click opens the detail drawer. */
export function DeviceTable() {
  const devices = useStore((s) => s.devices);
  const select = useStore((s) => s.select);
  const [query, setQuery] = useState('');
  const [type, setType] = useState('all');

  const rows = useMemo(() => {
    const q = query.toLowerCase();
    return Object.values(devices)
      .filter((d) => (type === 'all' ? true : d.deviceType === type))
      .filter((d) =>
        q
          ? [d.ip, d.mac, d.vendor, d.brand, d.model, d.hostname, d.label].some((v) =>
              v?.toLowerCase().includes(q),
            )
          : true,
      )
      .sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));
  }, [devices, query, type]);

  const types = useMemo(
    () => ['all', ...new Set(Object.values(devices).map((d) => d.deviceType))],
    [devices],
  );

  return (
    <div className="card overflow-hidden">
      <div className="flex flex-wrap items-center gap-2 border-b border-edge p-3">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search ip / mac / vendor / name…"
          className="flex-1 rounded-lg border border-edge bg-panelup px-3 py-2 text-sm outline-none focus:border-accent"
        />
        <select
          value={type}
          onChange={(e) => setType(e.target.value)}
          className="rounded-lg border border-edge bg-panelup px-3 py-2 text-sm outline-none focus:border-accent"
        >
          {types.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
      </div>
      <div className="max-h-[540px] overflow-auto">
        <table className="w-full text-left text-sm">
          <thead className="sticky top-0 bg-panelup text-xs uppercase text-muted">
            <tr>
              <th className="px-4 py-2">Device</th>
              <th className="px-4 py-2">IP</th>
              <th className="px-4 py-2">Brand / Model</th>
              <th className="px-4 py-2">OS</th>
              <th className="px-4 py-2">Type</th>
              <th className="px-4 py-2">Ports</th>
              <th className="px-4 py-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((d) => {
              const meta = deviceMeta(d.deviceType);
              return (
                <tr
                  key={d.id}
                  onClick={() => select(d.id)}
                  className="cursor-pointer border-t border-edge/60 hover:bg-panelup"
                >
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-2">
                      <span className="text-lg">{meta.icon}</span>
                      <div>
                        <div className="font-medium text-slate-100">
                          {d.label ?? d.hostname ?? 'Unknown host'}
                        </div>
                        <div className="text-xs text-muted">
                          {connectionGlyph(d.connectionType)} {d.mac ?? 'no MAC'}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs">{d.ip}</td>
                  <td className="px-4 py-2 text-slate-300">
                    <div>{d.brand ?? d.vendor ?? '—'}</div>
                    {d.model && <div className="text-xs text-muted">{d.model}</div>}
                  </td>
                  <td className="px-4 py-2 text-xs text-slate-300">
                    {d.os
                      ? `${d.os.family ?? d.os.name ?? '?'}${d.os.version ? ` ${d.os.version}` : ''}`
                      : '—'}
                  </td>
                  <td className="px-4 py-2">
                    <span className="badge bg-panelup text-slate-200">{meta.label}</span>
                    <div className={`text-[10px] ${confidenceColor(d.classificationConfidence)}`}>
                      {Math.round(d.classificationConfidence * 100)}% conf.
                    </div>
                  </td>
                  <td className="px-4 py-2 text-slate-300">{d.services.length}</td>
                  <td className="px-4 py-2">
                    {d.isOnline ? (
                      <span className="badge bg-good/15 text-good">● online</span>
                    ) : (
                      <span className="badge bg-edge text-muted">○ offline</span>
                    )}
                    {d.securityFlags.length > 0 && (
                      <span className="badge ml-1 bg-bad/15 text-bad">⚠ {d.securityFlags.length}</span>
                    )}
                  </td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-10 text-center text-muted">
                  No devices yet — start a scan to discover your network.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
