'use client';

import { useCallback, useEffect, useState } from 'react';
import { Header } from '../../components/Header';
import { WifiAnalyzerPanel } from '../../components/WifiAnalyzerPanel';
import { api } from '../../lib/api';
import type { CameraScanResponse, PingResponse, TracerouteResponse, WifiScanResponse } from '@netscanner/contracts';

export default function ToolsPage() {
  const [wifi, setWifi] = useState<WifiScanResponse | null>(null);
  const [cameras, setCameras] = useState<CameraScanResponse | null>(null);
  const [pingTarget, setPingTarget] = useState('');
  const [pingResult, setPingResult] = useState<PingResponse | null>(null);
  const [traceTarget, setTraceTarget] = useState('');
  const [traceResult, setTraceResult] = useState<TracerouteResponse | null>(null);
  const [dnsName, setDnsName] = useState('');
  const [dnsResult, setDnsResult] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>('wifi');
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
      setCameras(await api.diagnosticsCameraScan(travelMode ? { travelMode: true } : {}));
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

  const runPing = async () => {
    if (!pingTarget.trim()) return;
    setBusy('ping');
    setError(null);
    try {
      setPingResult(await api.diagnosticsPing(pingTarget.trim()));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const runTraceroute = async () => {
    if (!traceTarget.trim()) return;
    setBusy('trace');
    setError(null);
    try {
      setTraceResult(await api.diagnosticsTraceroute(traceTarget.trim()));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <main className="mx-auto w-full max-w-[1920px] space-y-4 p-4 md:p-5">
      <Header />
      <h1 className="text-lg font-semibold text-slate-100">Tools</h1>
      {error && <p className="text-sm text-bad">{error}</p>}

      <WifiAnalyzerPanel wifi={wifi} busy={busy === 'wifi'} onRefresh={() => void loadWifi()} />

      <section className="rounded-xl border border-edge bg-panel p-4">
        <h2 className="mb-3 text-sm font-semibold text-slate-200">Ping</h2>
        <div className="flex gap-2">
          <input
            value={pingTarget}
            onChange={(e) => setPingTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void runPing()}
            placeholder="192.168.1.1 or hostname"
            className="min-w-0 flex-1 rounded-lg border border-edge bg-panelup px-3 py-2 text-sm outline-none focus:border-accent"
          />
          <button type="button" onClick={() => void runPing()} disabled={busy === 'ping'} className="btn btn-primary text-xs">
            {busy === 'ping' ? 'Pinging…' : 'Ping'}
          </button>
        </div>
        {pingResult && (
          <>
            <p className="mt-2 text-xs text-muted">
              {pingResult.alive ? (
                <span className="text-good">
                  Reachable · {pingResult.packetsReceived}/{pingResult.packetsSent} replies
                  {pingResult.avgLatencyMs != null ? ` · avg ${pingResult.avgLatencyMs.toFixed(1)} ms` : ''}
                </span>
              ) : (
                <span className="text-bad">No reply · {pingResult.packetsReceived}/{pingResult.packetsSent} replies</span>
              )}
            </p>
            <pre className="mt-2 max-h-40 overflow-auto rounded-lg border border-edge bg-panelup p-3 text-xs text-slate-300">
              {pingResult.output.trim() || 'No output'}
            </pre>
          </>
        )}
      </section>

      <section className="rounded-xl border border-edge bg-panel p-4">
        <h2 className="mb-3 text-sm font-semibold text-slate-200">Traceroute</h2>
        <div className="flex gap-2">
          <input
            value={traceTarget}
            onChange={(e) => setTraceTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void runTraceroute()}
            placeholder="8.8.8.8 or hostname"
            className="min-w-0 flex-1 rounded-lg border border-edge bg-panelup px-3 py-2 text-sm outline-none focus:border-accent"
          />
          <button
            type="button"
            onClick={() => void runTraceroute()}
            disabled={busy === 'trace'}
            className="btn btn-primary text-xs"
          >
            {busy === 'trace' ? 'Tracing…' : 'Trace'}
          </button>
        </div>
        {traceResult && (
          <>
            {traceResult.hops.length > 0 && (
              <div className="mt-2 overflow-auto rounded-lg border border-edge">
                <table className="w-full min-w-[24rem] text-left text-xs">
                  <thead className="border-b border-edge bg-panelup text-muted">
                    <tr>
                      <th className="px-3 py-2">Hop</th>
                      <th className="px-3 py-2">Host</th>
                      <th className="px-3 py-2">IP</th>
                      <th className="px-3 py-2">Latency</th>
                    </tr>
                  </thead>
                  <tbody>
                    {traceResult.hops.map((hop) => (
                      <tr key={hop.hop} className="border-b border-edge/50">
                        <td className="px-3 py-1.5">{hop.hop}</td>
                        <td className="px-3 py-1.5 font-mono text-muted">{hop.host ?? '—'}</td>
                        <td className="px-3 py-1.5 font-mono">{hop.ip ?? '—'}</td>
                        <td className="px-3 py-1.5">{hop.latencyMs != null ? `${hop.latencyMs.toFixed(1)} ms` : '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <pre className="mt-2 max-h-48 overflow-auto rounded-lg border border-edge bg-panelup p-3 text-xs text-slate-300">
              {traceResult.output.trim() || 'No output'}
            </pre>
          </>
        )}
      </section>

      <section className="rounded-xl border border-edge bg-panel p-4">
        <h2 className="mb-3 text-sm font-semibold text-slate-200">DNS lookup</h2>
        <div className="flex gap-2">
          <input
            value={dnsName}
            onChange={(e) => setDnsName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void lookupDns()}
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
            <p className="text-xs text-muted">
              Scans inventory for camera-like devices (RTSP, Alexa/Ring cloud patterns). Travel mode also probes open RTSP ports.
            </p>
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
