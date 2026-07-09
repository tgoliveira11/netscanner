'use client';

import { useCallback, useEffect, useState } from 'react';
import { AppNav } from '../../components/AppNav';
import { Header } from '../../components/Header';
import { api } from '../../lib/api';
import type { CameraScanResponse, WifiScanResponse } from '@netscanner/contracts';

export default function ToolsPage() {
  const [wifi, setWifi] = useState<WifiScanResponse | null>(null);
  const [cameras, setCameras] = useState<CameraScanResponse | null>(null);
  const [dnsName, setDnsName] = useState('');
  const [dnsResult, setDnsResult] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [travelMode, setTravelMode] = useState(false);

  const loadWifi = useCallback(async () => {
    setBusy('wifi');
    setError(null);
    try {
      setWifi(await api.diagnosticsWifi());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }, []);

  useEffect(() => {
    void loadWifi();
  }, [loadWifi]);

  const scanCameras = async () => {
    setBusy('camera');
    setError(null);
    try {
      setCameras(await api.diagnosticsCameraScan());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const lookupDns = async () => {
    if (!dnsName.trim()) return;
    setBusy('dns');
    setError(null);
    try {
      const res = await api.diagnosticsDns(dnsName.trim());
      setDnsResult(res.records.length ? res.records.join('\n') : res.output ?? 'No records');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <main className="mx-auto w-full max-w-[1920px] space-y-4 p-4 md:p-5">
      <Header />
      <AppNav />
      <h1 className="text-lg font-semibold text-slate-100">Tools</h1>
      {error && <p className="text-sm text-bad">{error}</p>}

      <section className="rounded-xl border border-edge bg-panel p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-slate-200">Wi‑Fi scanner</h2>
          <button type="button" onClick={() => void loadWifi()} disabled={busy === 'wifi'} className="btn btn-ghost text-xs">
            {busy === 'wifi' ? 'Scanning…' : 'Refresh'}
          </button>
        </div>
        {wifi && (
          <>
            <p className="mb-2 text-xs text-muted">
              Connected: {wifi.currentSsid ?? '—'} · {wifi.aps.length} APs visible
            </p>
            <div className="overflow-auto rounded-lg border border-edge">
              <table className="w-full min-w-[28rem] text-left text-xs">
                <thead className="border-b border-edge bg-panelup text-muted">
                  <tr>
                    <th className="px-3 py-2">SSID</th>
                    <th className="px-3 py-2">BSSID</th>
                    <th className="px-3 py-2">Ch</th>
                    <th className="px-3 py-2">RSSI</th>
                    <th className="px-3 py-2">Security</th>
                  </tr>
                </thead>
                <tbody>
                  {wifi.aps.map((ap) => (
                    <tr key={`${ap.ssid}-${ap.bssid ?? ap.channel}`} className="border-b border-edge/50">
                      <td className="px-3 py-1.5">{ap.ssid || '(hidden)'}</td>
                      <td className="px-3 py-1.5 font-mono text-muted">{ap.bssid ?? '—'}</td>
                      <td className="px-3 py-1.5">{ap.channel ?? '—'}</td>
                      <td className="px-3 py-1.5">{ap.rssi != null ? `${ap.rssi} dBm` : '—'}</td>
                      <td className="px-3 py-1.5 text-muted">{ap.security ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {wifi.channelCollisions.length > 0 && (
              <p className="mt-2 text-xs text-warn">
                Channel overlap: {wifi.channelCollisions.map((c) => `ch${c.channel}×${c.count}`).join(', ')}
              </p>
            )}
          </>
        )}
      </section>

      <section className="rounded-xl border border-edge bg-panel p-4">
        <h2 className="mb-3 text-sm font-semibold text-slate-200">DNS lookup</h2>
        <div className="flex gap-2">
          <input
            value={dnsName}
            onChange={(e) => setDnsName(e.target.value)}
            placeholder="example.com"
            className="min-w-0 flex-1 rounded-lg border border-edge bg-panelup px-3 py-2 text-sm outline-none focus:border-accent"
          />
          <button type="button" onClick={() => void lookupDns()} disabled={busy === 'dns'} className="btn btn-primary text-xs">
            Lookup
          </button>
        </div>
        {dnsResult && (
          <pre className="mt-2 max-h-32 overflow-auto rounded-lg border border-edge bg-panelup p-3 text-xs text-slate-300">
            {dnsResult}
          </pre>
        )}
      </section>

      <section className="rounded-xl border border-edge bg-panel p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-slate-200">Camera heuristics + RTSP probe</h2>
            <p className="text-xs text-muted">Travel mode: scan without assuming home inventory context.</p>
          </div>
          <label className="flex items-center gap-2 text-xs text-muted">
            <input type="checkbox" checked={travelMode} onChange={(e) => setTravelMode(e.target.checked)} />
            Travel mode
          </label>
        </div>
        <button type="button" onClick={() => void scanCameras()} disabled={busy === 'camera'} className="btn btn-primary text-xs">
          {busy === 'camera' ? 'Scanning…' : travelMode ? 'Scan local inventory (travel)' : 'Scan network'}
        </button>
        {cameras && (
          <>
            <p className="mt-2 text-xs text-muted">{cameras.disclaimer}</p>
            <div className="mt-3 space-y-2">
              {cameras.candidates.length === 0 && (
                <p className="text-xs text-muted">No camera candidates in current site inventory.</p>
              )}
              {cameras.candidates.map((c) => (
                <div key={c.ip} className="rounded-lg border border-edge bg-panelup px-3 py-2 text-xs">
                  <div className="flex justify-between text-slate-200">
                    <span className="font-mono">{c.ip}</span>
                    <span>{Math.round(c.confidence * 100)}% · RTSP {c.rtspOpen ? 'open' : 'closed'}</span>
                  </div>
                  <ul className="mt-1 list-inside list-disc text-muted">
                    {c.reasons.map((r) => (
                      <li key={r}>{r}</li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
          </>
        )}
      </section>
    </main>
  );
}
