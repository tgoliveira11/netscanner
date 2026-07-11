'use client';

import type { WifiAnalysis, WifiAp, WifiScanResponse } from '@netscanner/contracts';
import { LoadingBlock } from './LoadingSpinner';

function severityClass(severity: 'info' | 'warn' | 'critical'): string {
  if (severity === 'critical') return 'text-bad border-bad/40 bg-bad/5';
  if (severity === 'warn') return 'text-warn border-warn/40 bg-warn/5';
  return 'text-muted border-edge bg-panelup';
}

function congestionTone(score: number): string {
  if (score >= 70) return 'text-bad';
  if (score >= 40) return 'text-warn';
  return 'text-good';
}

function bandLabel(band: string): string {
  if (band === '2.4') return '2.4 GHz';
  if (band === '5') return '5 GHz';
  if (band === '6') return '6 GHz';
  return band;
}

function connectedHint(wifi: WifiScanResponse): string | undefined {
  if (!wifi.currentSsid) return 'CoreWLAN / networksetup';
  const parts: string[] = [];
  if (wifi.connectedInferred) parts.push('inferred from channel');
  if (wifi.currentBand) parts.push(bandLabel(wifi.currentBand));
  if (wifi.currentChannel != null) parts.push(`ch ${wifi.currentChannel}`);
  const local = wifi.aps.find(
    (a) => a.source === 'local' && a.ssid === wifi.currentSsid && a.rssi != null,
  );
  if (local?.rssi != null) parts.push(`${local.rssi} dBm`);
  return parts.length ? parts.join(' · ') : undefined;
}

function ChannelHeatmap({
  band,
  scores,
  best,
  worst,
  ownChannels,
}: {
  band: string;
  scores: WifiAnalysis['bandSummaries'][0]['channelScores'];
  best: number[];
  worst: number[];
  ownChannels: Set<number>;
}) {
  const max = Math.max(0.01, ...scores.map((s) => s.overlapScore));
  return (
    <div className="space-y-1">
      <div className="text-[10px] uppercase text-muted">{bandLabel(band)} — channel occupancy</div>
      <div className="flex flex-wrap gap-1">
        {scores.map((s) => {
          const pct = Math.round((s.overlapScore / max) * 100);
          const isBest = best.includes(s.channel);
          const isWorst = worst.includes(s.channel);
          const isOwn = ownChannels.has(s.channel);
          return (
            <div
              key={`${band}-${s.channel}`}
              title={`ch ${s.channel}: score ${s.overlapScore}, ${s.coChannelCount} co-channel, ${s.apCount} AP(s)`}
              className={`min-w-[2.4rem] rounded border px-1.5 py-1 text-center text-[10px] ${
                isOwn ? 'border-accent ring-1 ring-accent/30' : 'border-edge'
              } ${isWorst ? 'bg-bad/10' : isBest ? 'bg-good/10' : 'bg-panelup'}`}
            >
              <div className="font-mono font-medium text-slate-200">{s.channel}</div>
              <div className="mx-auto mt-0.5 h-1 w-full overflow-hidden rounded bg-edge">
                <div
                  className={`h-full ${pct >= 70 ? 'bg-bad' : pct >= 40 ? 'bg-warn' : 'bg-good'}`}
                  style={{ width: `${Math.max(8, pct)}%` }}
                />
              </div>
              {s.coChannelCount > 0 && <div className="text-muted">{s.coChannelCount} co</div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

export function WifiAnalyzerPanel({
  wifi,
  busy,
  onRefresh,
}: {
  wifi: WifiScanResponse | null;
  busy: boolean;
  onRefresh: () => void;
}) {
  const analysis = wifi?.analysis;
  const ownChannels = new Set(
    (analysis?.ownNetworks ?? [])
      .map((n) => n.channel)
      .filter((c): c is number => c != null),
  );

  return (
    <section className="rounded-xl border border-edge bg-panel p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">Wi‑Fi analyzer</h2>
          <p className="text-xs text-muted">
            Channel congestion from nearby RF (Mac scan) plus your AP radios — Re-scan to refresh.
          </p>
        </div>
        <button type="button" onClick={onRefresh} disabled={busy} className="btn btn-ghost text-xs">
          {busy ? 'Analyzing…' : 'Re-scan'}
        </button>
      </div>

      <LoadingBlock loading={!wifi && busy} label="Analyzing Wi‑Fi…">
        {wifi && (
        <>
          <div className="mb-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <SummaryCard
              label="Connected"
              value={wifi.currentSsid ? `${wifi.currentSsid}${wifi.connectedInferred ? ' *' : ''}` : '—'}
              hint={connectedHint(wifi)}
            />
            <SummaryCard label="Networks seen" value={String(wifi.aps.length)} />
            <SummaryCard
              label="Congestion"
              value={analysis ? `${analysis.congestionIndex}%` : '—'}
              valueClass={analysis ? congestionTone(analysis.congestionIndex) : undefined}
            />
            <SummaryCard
              label="Recommendations"
              value={String(analysis?.recommendations.length ?? 0)}
              hint={
                analysis?.recommendations.filter((r) => r.severity === 'critical').length
                  ? `${analysis.recommendations.filter((r) => r.severity === 'critical').length} critical`
                  : undefined
              }
            />
          </div>

          {wifi.note && <p className="mb-3 text-xs text-muted">{wifi.note}</p>}

          {analysis && analysis.recommendations.length > 0 && (
            <div className="mb-4 space-y-2">
              <h3 className="text-xs font-semibold uppercase text-muted">Recommendations</h3>
              {analysis.recommendations.map((rec) => (
                <div key={rec.title} className={`rounded-lg border px-3 py-2 text-xs ${severityClass(rec.severity)}`}>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-slate-100">{rec.title}</span>
                    <span className="rounded bg-panel px-1.5 py-0.5 text-[10px] uppercase text-muted">{rec.category}</span>
                  </div>
                  <p className="mt-1 text-slate-300">{rec.detail}</p>
                </div>
              ))}
            </div>
          )}

          {analysis && analysis.ownNetworks.length > 0 && (
            <div className="mb-4 space-y-2">
              <h3 className="text-xs font-semibold uppercase text-muted">Your APs / modem</h3>
              <div className="grid gap-2 md:grid-cols-2">
                {analysis.ownNetworks.map((n) => (
                  <div key={`${n.routerHost}-${n.ssid}`} className="rounded-lg border border-edge bg-panelup p-3 text-xs">
                    <div className="font-medium text-slate-200">{n.ssid}</div>
                    <div className="text-muted">
                      {n.routerHost} · {bandLabel(n.band)}
                      {n.channel != null ? ` · ch ${n.channel}` : ''}
                      {n.mode ? ` · ${n.mode}` : ''}
                    </div>
                    <dl className="mt-2 grid grid-cols-2 gap-1 text-slate-300">
                      <dt className="text-muted">Clients</dt>
                      <dd>{n.clientCount}{n.weakClientCount ? ` (${n.weakClientCount} fraco)` : ''}</dd>
                      <dt className="text-muted">Avg signal</dt>
                      <dd>{n.avgClientRssi != null ? `${n.avgClientRssi} dBm` : '—'}</dd>
                      <dt className="text-muted">Congestionamento</dt>
                      <dd className={n.congestionScore != null ? congestionTone(n.congestionScore) : ''}>
                        {n.congestionScore != null ? `${n.congestionScore}%` : '—'}
                      </dd>
                      <dt className="text-muted">Suggested channel</dt>
                      <dd className="font-medium text-good">
                        {n.suggestedChannel != null && n.suggestedChannel !== n.channel
                          ? `ch ${n.suggestedChannel}`
                          : n.channel != null
                            ? `ch ${n.channel} (ok)`
                            : '—'}
                      </dd>
                    </dl>
                  </div>
                ))}
              </div>
            </div>
          )}

          {analysis?.bandSummaries.map((band) => (
            <div key={band.band} className="mb-4">
              <ChannelHeatmap
                band={band.band}
                scores={band.channelScores}
                best={band.bestChannels}
                worst={band.worstChannels}
                ownChannels={ownChannels}
              />
              <p className="mt-1 text-[11px] text-muted">
                Best: {band.bestChannels.map((c) => `ch${c}`).join(', ') || '—'} · Worst:{' '}
                {band.worstChannels.map((c) => `ch${c}`).join(', ') || '—'}
              </p>
            </div>
          ))}

          {analysis && analysis.issues.length > 0 && (
            <ul className="mb-4 space-y-1 text-xs">
              {analysis.issues.map((issue) => (
                <li key={issue.message} className={issue.severity === 'warn' ? 'text-warn' : 'text-muted'}>
                  {issue.message}
                </li>
              ))}
            </ul>
          )}

          {wifi.channelCollisions.length > 0 && (
            <p className="mb-3 text-xs text-warn">
              Co-channel (same number):{' '}
              {wifi.channelCollisions.map((c) => `ch${c.channel}×${c.count}`).join(', ')}
            </p>
          )}

          <div className="overflow-auto rounded-lg border border-edge">
            <table className="w-full min-w-[36rem] text-left text-xs">
              <thead className="border-b border-edge bg-panelup text-muted">
                <tr>
                  <th className="px-3 py-2">SSID</th>
                  <th className="px-3 py-2">Source</th>
                  <th className="px-3 py-2">Band</th>
                  <th className="px-3 py-2">Ch</th>
                  <th className="px-3 py-2">RSSI</th>
                  <th className="px-3 py-2">Security</th>
                </tr>
              </thead>
              <tbody>
                {wifi.aps.map((ap: WifiAp) => (
                  <tr
                    key={`${ap.ssid}-${ap.bssid ?? ''}-${ap.channel}-${ap.source}`}
                    className={`border-b border-edge/50 ${ap.isOwnNetwork ? 'bg-accent/5' : ''}`}
                  >
                    <td className="px-3 py-1.5 font-medium text-slate-200">{ap.ssid || '(hidden)'}</td>
                    <td className="px-3 py-1.5 text-muted">
                      {ap.source === 'router' ? 'your AP' : ap.source === 'nearby' ? 'scan AP' : 'Mac'}
                      {ap.routerHost ? ` · ${ap.routerHost}` : ''}
                    </td>
                    <td className="px-3 py-1.5 text-muted">{ap.band ? bandLabel(ap.band) : '—'}</td>
                    <td className="px-3 py-1.5">{ap.channel ?? '—'}</td>
                    <td className="px-3 py-1.5">{ap.rssi != null ? `${ap.rssi} dBm` : '—'}</td>
                    <td className="px-3 py-1.5 text-muted">{ap.security ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
        )}
      </LoadingBlock>
    </section>
  );
}

function SummaryCard({
  label,
  value,
  hint,
  valueClass,
}: {
  label: string;
  value: string;
  hint?: string;
  valueClass?: string;
}) {
  return (
    <div className="rounded-lg border border-edge bg-panelup px-3 py-2">
      <div className="text-[10px] uppercase text-muted">{label}</div>
      <div className={`mt-0.5 truncate text-sm font-medium ${valueClass ?? 'text-slate-100'}`}>{value}</div>
      {hint && <div className="mt-0.5 truncate text-[11px] text-muted">{hint}</div>}
    </div>
  );
}
