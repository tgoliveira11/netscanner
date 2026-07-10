'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import type { SpeedTestReport } from '@netscanner/contracts';
import { api } from '../lib/api';
import { LoadingBlock, LoadingSpinner } from './LoadingSpinner';
import { SpeedTestChart } from './SpeedTestChart';

const REPORT_DAYS = 90;
const REPORT_LIMIT = 2000;

function fmtMbps(v: number | null | undefined): string {
  if (v == null) return '—';
  return `${v.toFixed(1)} Mbps`;
}

function sourceLabel(s: import('@netscanner/contracts').SpeedTestResult): string {
  if (s.testKind === 'wan' && s.wanGateway) {
    return `WAN · ${s.wanGateway}${s.wanInterface ? ` (${s.wanInterface})` : ''}`;
  }
  if (s.egressRoute && s.egressRoute !== 'unknown') {
    const label = s.egressRoute === 'vpn' ? 'VPN' : s.egressRoute === 'lb' ? 'LB' : 'WAN';
    return `Agent · ${label}${s.egressGateway ? ` · ${s.egressGateway}` : ''}`;
  }
  return s.egressGateway ? `Agent · ${s.egressGateway}` : 'Agent';
}

function StatusCard({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-edge bg-panelup px-3 py-2">
      <div className="text-[10px] uppercase tracking-wide text-muted">{label}</div>
      <div className="mt-0.5 text-sm font-medium text-slate-100">{value}</div>
    </div>
  );
}

export function SpeedTestPanel() {
  const [report, setReport] = useState<SpeedTestReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState<'agent' | 'wan' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [wanConfigured, setWanConfigured] = useState<boolean | null>(null);
  const [wanFilter, setWanFilter] = useState<string>('all');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setReport(await api.speedTestReport(REPORT_DAYS, REPORT_LIMIT));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    // Prefer fast observability flag (SSH configured) — do not gate the button on the slow gateways refresh.
    void api
      .adminObservability()
      .then((o) => {
        const flag = o.background?.wanSpeedTestConfigured;
        if (typeof flag === 'boolean') setWanConfigured(flag);
        else setWanConfigured(null);
      })
      .catch(() => {
        /* leave null — keep button enabled; click will surface the real error */
      });
  }, [load]);

  const runAgent = async () => {
    setRunning('agent');
    setError(null);
    try {
      await api.runSpeedTest('agent');
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(null);
    }
  };

  const runWanAll = async () => {
    setRunning('wan');
    setError(null);
    try {
      await api.runSpeedTest('wan-all');
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(null);
    }
  };

  const busy = running !== null;
  const allSamples = report?.samples ?? [];

  const wanOptions = useMemo(() => {
    const wans = new Set<string>();
    for (const s of allSamples) {
      if (s.testKind === 'wan' && s.wanGateway) wans.add(s.wanGateway);
    }
    return [...wans].sort();
  }, [allSamples]);

  const samples = useMemo(() => {
    if (wanFilter === 'all') return allSamples;
    if (wanFilter === 'agent') return allSamples.filter((s) => s.testKind !== 'wan');
    return allSamples.filter((s) => s.wanGateway === wanFilter);
  }, [allSamples, wanFilter]);

  return (
    <div className="w-full space-y-4">
      <p className="text-xs text-muted">
        <strong className="text-slate-300">Per-WAN</strong> tests run on pfSense via SSH, egress bound to each
        physical interface (before VPN or gateway groups). <strong className="text-slate-300">Agent</strong> uses this
        Mac&apos;s default route and records observed egress (VPN / LB / WAN).
      </p>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          onClick={() => void runWanAll()}
          disabled={busy || wanConfigured === false}
          className="rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-medium text-accent hover:bg-accent/20 disabled:opacity-50"
        >
          {running === 'wan' ? 'Testing WANs…' : 'Test each WAN (pfSense)'}
        </button>
        <button
          type="button"
          onClick={() => void runAgent()}
          disabled={busy}
          className="rounded-lg border border-edge px-3 py-1.5 text-xs text-slate-200 hover:bg-panelup disabled:opacity-50"
        >
          {running === 'agent' ? 'Testing…' : 'Test agent route (Mac)'}
        </button>
        <button
          type="button"
          onClick={() => void load()}
          disabled={loading || busy}
          className="rounded-lg border border-edge px-3 py-1.5 text-xs text-muted hover:text-slate-200 disabled:opacity-50"
        >
          Refresh
        </button>
      </div>

      {wanOptions.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-muted">Filter:</span>
          <select
            value={wanFilter}
            onChange={(e) => setWanFilter(e.target.value)}
            className="rounded border border-edge bg-panel px-2 py-1 text-slate-200"
          >
            <option value="all">All sources</option>
            <option value="agent">Agent only</option>
            {wanOptions.map((w) => (
              <option key={w} value={w}>
                WAN · {w}
              </option>
            ))}
          </select>
        </div>
      )}

      {wanConfigured === false && (
        <p className="text-xs text-warn">Set PFSENSE_URL + PFSENSE_SSH_PASSWORD for per-WAN tests.</p>
      )}
      {error && <p className="text-xs text-bad">{error}</p>}

      {running && (
        <LoadingSpinner
          label={running === 'wan' ? 'Running per-WAN tests on pfSense…' : 'Testing agent route…'}
          className="py-4"
        />
      )}

      <LoadingBlock loading={loading && !report} label="Loading history…">
        {report && (
          <>
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              <StatusCard label="Latest download" value={fmtMbps(report.latest?.downloadMbps)} />
              <StatusCard label="Latest upload" value={fmtMbps(report.latest?.uploadMbps)} />
              <StatusCard label={`${REPORT_DAYS}d avg ↓`} value={fmtMbps(report.avgDownloadMbps)} />
              <StatusCard label="Samples" value={String(samples.length)} />
            </div>

            <SpeedTestChart samples={samples} />

            {samples.length > 0 && (
              <div className="overflow-auto rounded-lg border border-edge">
                <table className="w-full min-w-[36rem] text-left text-xs">
                  <thead className="border-b border-edge bg-panelup text-muted">
                    <tr>
                      <th className="px-3 py-2 font-medium">When</th>
                      <th className="px-3 py-2 font-medium">Source</th>
                      <th className="px-3 py-2 font-medium">↓ Mbps</th>
                      <th className="px-3 py-2 font-medium">↑ Mbps</th>
                      <th className="px-3 py-2 font-medium">Latency</th>
                      <th className="px-3 py-2 font-medium">Trigger</th>
                    </tr>
                  </thead>
                  <tbody>
                    {samples.map((s) => (
                      <tr key={s.id} className="border-b border-edge/50">
                        <td className="px-3 py-1.5 text-slate-300">{new Date(s.measuredAt).toLocaleString()}</td>
                        <td className="px-3 py-1.5 text-muted">{sourceLabel(s)}</td>
                        <td className="px-3 py-1.5">{fmtMbps(s.downloadMbps)}</td>
                        <td className="px-3 py-1.5">{fmtMbps(s.uploadMbps)}</td>
                        <td className="px-3 py-1.5">{s.latencyMs != null ? `${Math.round(s.latencyMs)} ms` : '—'}</td>
                        <td className="px-3 py-1.5 text-muted">{s.trigger}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="text-[10px] text-muted">
              Up to {REPORT_DAYS} days of history · newest first · retention via SPEED_TEST_RETENTION_DAYS
            </p>
          </>
        )}
      </LoadingBlock>
    </div>
  );
}
