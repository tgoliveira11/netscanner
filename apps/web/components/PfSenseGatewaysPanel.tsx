'use client';

import { useMemo } from 'react';
import { useBackgroundDataStore } from '../lib/background-data-store';
import { LoadingSpinner } from './LoadingSpinner';

function statusTone(status: string | null | undefined): string {
  const s = (status ?? '').toLowerCase();
  if (s.includes('online') || s.includes('connected') || s.includes('enabled')) return 'text-good';
  if (s.includes('offline') || s.includes('down') || s.includes('disabled')) return 'text-bad';
  if (s.includes('warn')) return 'text-warn';
  return 'text-muted';
}

function formatBytes(n: number): string {
  if (n <= 0) return '—';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatFetchedAt(iso: string | undefined): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function isKeyInterface(descr: string | null, name: string | null, hwif: string | null): boolean {
  const text = `${descr ?? ''} ${name ?? ''} ${hwif ?? ''}`.toLowerCase();
  return (
    /wan|vivo|claro|main|guest|iot|infra|vlan|ovpn|openvpn|wireguard|wg|tun_|surfs?shark|vpn/.test(text) ||
    (hwif?.startsWith('tun_') ?? false) ||
    (hwif?.startsWith('ovpn') ?? false)
  );
}

export function PfSenseGatewaysPanel() {
  const data = useBackgroundDataStore((s) => s.pfsense);
  const loading = useBackgroundDataStore((s) => s.pfsenseLoading);
  const refreshing = useBackgroundDataStore((s) => s.pfsenseRefreshing);
  const error = useBackgroundDataStore((s) => s.pfsenseError);
  const refresh = useBackgroundDataStore((s) => s.refreshPfSense);

  const groupsByGw = useMemo(() => {
    const map = new Map<string, { group: string; tier: number }>();
    for (const g of data?.gatewayGroups ?? []) {
      for (const m of g.members) {
        map.set(m.name, { group: g.name, tier: m.tier });
      }
    }
    return map;
  }, [data?.gatewayGroups]);

  const keyInterfaces = useMemo(
    () =>
      (data?.interfaces ?? []).filter((i) => isKeyInterface(i.descr, i.name, i.hwif)).slice(0, 16),
    [data?.interfaces],
  );

  const topEgress = data?.egress?.[0];

  if (loading && !data) {
    return (
      <section className="space-y-2">
        <h2 className="text-sm font-semibold text-slate-200">pfSense</h2>
        <LoadingSpinner label="Loading pfSense…" />
      </section>
    );
  }

  if (!data?.configured) {
    return (
      <section className="space-y-2">
        <h2 className="text-sm font-semibold text-slate-200">pfSense</h2>
        <p className="text-xs text-muted">Configure PFSENSE_URL + PFSENSE_API_KEY to see live router status.</p>
      </section>
    );
  }

  const defaultV4 = data.defaultGateway?.ipv4;
  const sys = data.system;
  const displayHost = sys?.hostname ?? data.hostname ?? 'pfSense';
  const displayVersion = sys?.version ?? data.version;

  return (
    <section className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">pfSense</h2>
          <p className="text-xs text-muted">
            {displayHost}
            {displayVersion ? ` · ${displayVersion}` : ''}
            {sys?.uptime ? ` · uptime ${sys.uptime}` : ''}
            {sys?.platform ? ` · ${sys.platform}` : ''}
          </p>
          <p className="text-[11px] text-muted">Updated: {formatFetchedAt(data.fetchedAt)}</p>
        </div>
        <button type="button" onClick={() => void refresh()} disabled={refreshing} className="btn btn-ghost text-xs">
          {refreshing ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      {error && <p className="text-xs text-bad">{error}</p>}

      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <SummaryCard
          label="Default gateway"
          value={defaultV4 ?? data.defaultGateway?.ipv6 ?? '—'}
          hint="System → Routing → Default gateway"
        />
        <SummaryCard
          label="Firewall states"
          value={String(data.stateCount ?? 0)}
          hint="Recent sample (up to 500)"
        />
        <SummaryCard
          label="Observed egress"
          value={topEgress ? topEgress.gateway : '—'}
          hint={
            topEgress
              ? `${topEgress.stateCount} states · ${topEgress.interface} · ${formatBytes(topEgress.bytesOut)}`
              : 'Inferred from per-interface states'
          }
        />
        <SummaryCard
          label="VPN clients"
          value={String((data.vpnClients ?? []).filter((v) => v.enabled).length)}
          hint={`${(data.vpnClients ?? []).length} configured`}
        />
      </div>

      {(data.gatewayGroupInsights?.length ?? 0) > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase text-muted">Gateway groups — preferred vs active</h3>
          <div className="grid gap-2 md:grid-cols-2">
            {data.gatewayGroupInsights!.map((g) => {
              const mismatch =
                g.preferredGateway &&
                g.activeGateway &&
                g.preferredGateway !== g.activeGateway &&
                g.activeStateCount > 0;
              return (
                <div
                  key={g.group}
                  className={`rounded-lg border bg-panelup p-3 text-xs ${mismatch ? 'border-warn/40' : 'border-edge'}`}
                >
                  <div className="font-medium text-slate-200">{g.group}</div>
                  {g.description && <div className="text-muted">{g.description}</div>}
                  <dl className="mt-2 space-y-1 text-slate-300">
                    <div className="flex justify-between gap-2">
                      <dt className="text-muted">Failover (tier online)</dt>
                      <dd className="text-right font-medium">
                        {g.preferredGateway ?? '—'}
                        {g.preferredTier != null ? ` · tier ${g.preferredTier}` : ''}
                      </dd>
                    </div>
                    <div className="flex justify-between gap-2">
                      <dt className="text-muted">Egress now (states)</dt>
                      <dd className={`text-right font-medium ${mismatch ? 'text-warn' : ''}`}>
                        {g.activeGateway ?? '—'}
                        {g.activeStateCount > 0 ? ` · ${g.activeStateCount} states` : ''}
                      </dd>
                    </div>
                  </dl>
                  {mismatch && (
                    <p className="mt-2 text-[11px] text-warn">
                      Policy routing may send traffic via a gateway other than the tier-1 online member.
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="overflow-auto rounded-lg border border-edge">
        <table className="w-full min-w-[40rem] text-left text-xs">
          <thead className="border-b border-edge bg-panelup text-muted">
            <tr>
              <th className="px-3 py-2">Gateway</th>
              <th className="px-3 py-2">Monitor</th>
              <th className="px-3 py-2">RTT</th>
              <th className="px-3 py-2">Loss</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Group / tier</th>
              <th className="px-3 py-2">States</th>
            </tr>
          </thead>
          <tbody>
            {(data.gateways ?? []).map((gw) => {
              const grp = gw.name ? groupsByGw.get(gw.name) : undefined;
              const isDefault = gw.isDefault || gw.name === defaultV4;
              const egressRow = (data.egress ?? []).find(
                (e) => e.gateway.toLowerCase() === (gw.name ?? '').toLowerCase(),
              );
              return (
                <tr key={`${gw.name ?? ''}-${gw.interface ?? ''}-${gw.monitor ?? ''}`} className="border-b border-edge/50">
                  <td className="px-3 py-1.5 font-medium text-slate-200">
                    {gw.name ?? '—'}
                    {isDefault && <span className="ml-1 text-muted">(default)</span>}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-muted">{gw.monitor ?? gw.gateway ?? '—'}</td>
                  <td className="px-3 py-1.5">{gw.delay != null ? `${gw.delay} ms` : '—'}</td>
                  <td className="px-3 py-1.5">{gw.loss != null ? `${gw.loss}%` : '—'}</td>
                  <td className={`px-3 py-1.5 ${statusTone(gw.status)}`}>{gw.status ?? '—'}</td>
                  <td className="px-3 py-1.5 text-muted">
                    {grp ? `${grp.group} · tier ${grp.tier}` : '—'}
                  </td>
                  <td className="px-3 py-1.5 text-muted">
                    {egressRow ? `${egressRow.stateCount} · ${formatBytes(egressRow.bytesOut)}` : '—'}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {(data.vpnClients?.length ?? 0) > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase text-muted">VPN</h3>
          <div className="grid gap-2 md:grid-cols-2">
            {data.vpnClients!.map((v) => (
              <div key={`${v.type}-${v.name}`} className="rounded-lg border border-edge bg-panelup p-3 text-xs">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-medium text-slate-200">{v.name}</span>
                  <span className="text-[10px] uppercase text-muted">{v.type}</span>
                </div>
                <div className={`mt-1 ${statusTone(v.status)}`}>{v.status ?? (v.enabled ? 'enabled' : 'disabled')}</div>
                {v.virtualAddress && <div className="mt-1 font-mono text-muted">{v.virtualAddress}</div>}
                {v.remoteHost && <div className="text-muted">→ {v.remoteHost}</div>}
              </div>
            ))}
          </div>
        </div>
      )}

      {keyInterfaces.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase text-muted">Interfaces (WAN / VLAN / VPN)</h3>
          <div className="overflow-auto rounded-lg border border-edge">
            <table className="w-full min-w-[32rem] text-left text-xs">
              <thead className="border-b border-edge bg-panelup text-muted">
                <tr>
                  <th className="px-3 py-2">Label</th>
                  <th className="px-3 py-2">IP</th>
                  <th className="px-3 py-2">HWIF</th>
                  <th className="px-3 py-2">Status</th>
                </tr>
              </thead>
              <tbody>
                {keyInterfaces.map((i) => (
                  <tr key={`${i.name}-${i.hwif}`} className="border-b border-edge/50">
                    <td className="px-3 py-1.5 font-medium text-slate-200">{i.descr ?? i.name ?? '—'}</td>
                    <td className="px-3 py-1.5 font-mono text-muted">{i.ipaddr ?? '—'}</td>
                    <td className="px-3 py-1.5 font-mono text-muted">{i.hwif ?? '—'}</td>
                    <td className={`px-3 py-1.5 ${statusTone(i.status)}`}>{i.status ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {(data.egress?.length ?? 0) > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase text-muted">Egress by interface (states)</h3>
          <ul className="space-y-1 text-xs text-slate-300">
            {data.egress!.slice(0, 8).map((e) => (
              <li key={`${e.gateway}-${e.interface}`} className="flex justify-between gap-2 rounded border border-edge/50 bg-panelup px-3 py-1.5">
                <span>
                  <span className="font-medium text-slate-200">{e.gateway}</span>
                  <span className="text-muted"> · {e.interface}</span>
                </span>
                <span className="text-muted">
                  {e.stateCount} states · {formatBytes(e.bytesOut)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <p className="text-[11px] text-muted">
        <strong className="font-medium text-slate-400">Online</strong> in the monitor only confirms probe IP reachability —
        it does not prove which route the LAN uses. Compare &quot;Failover (tier online)&quot; with &quot;Egress now&quot; and check
        Firewall → Rules → Gateway column on VLANs.
      </p>
    </section>
  );
}

function SummaryCard({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-lg border border-edge bg-panelup px-3 py-2">
      <div className="text-[10px] uppercase text-muted">{label}</div>
      <div className="mt-0.5 truncate text-sm font-medium text-slate-100">{value}</div>
      {hint && <div className="mt-0.5 truncate text-[11px] text-muted">{hint}</div>}
    </div>
  );
}
